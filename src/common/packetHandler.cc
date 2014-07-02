/********************************************************************
    PACP - Polynomial assisted Ad-hoc Charging Protocol

    Author: João Paulo Barraca <jpbarraca@av.it.pt>
    Copyright (c) João Paulo Barraca

    This file is part of PACP.

    PACP is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    PACP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with PACP.  If not, see <http://www.gnu.org/licenses/>.

 ********************************************************************/


#include <linux/netfilter.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <stdint.h>

extern "C"
{
#include "../../lib/libipq/libipq.h"
}

#include "packetHandler.h"
#include "packet.h"
#include <sys/time.h>
#include <pthread.h>
#include "exception.h"

#define PACKET_BUFFER_SIZE 1700
#define PACKET_IPQ_PAYLOAD_SIZE 1500


//! PacketHandler constructor
PacketHandler::PacketHandler(const bool useIPQ, const int timeout) {
    uint32_t status;
    ipqHandle = NULL;

    if ((_socket = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        MYTHROW1("Could not open socket");

    } else {
        in6_addr addr;
        memset(&addr, 0, sizeof(in6_addr));
        sockaddr_in6 sock;
        sock.sin6_addr = addr;
        sock.sin6_family = AF_INET6;
        sock.sin6_port = htons(conf->getSignallingPort());

        if ( bind(_socket, (sockaddr*) &sock, sizeof(sock)) < 0 ) {
            MYTHROW2("Cannot bind to socket", strerror(errno));
        }
    }

    _useIPQ = useIPQ;
    pthread_mutex_init(&_mutPHSocket, NULL);
    pthread_mutex_init(&_mutPHandler, NULL);

    if (useIPQ) {
        ipqHandle = ipq_create_handle(0, PF_INET6);

        if (!ipqHandle) {
            MYTHROW1("Could not Initialize IP6QUEUE Handle!");
        }

        status = ipq_set_mode(ipqHandle, IPQ_COPY_PACKET, PACKET_IPQ_PAYLOAD_SIZE);

        if (status <= 0) {                                    //Something went wrong. ip6_queue not loaded?
            ipq_perror(NULL);
            ipq_destroy_handle(ipqHandle);
            ipqHandle = NULL;
            MYTHROW1("Could not Initialize IP6QUEUE!");
        }

        logger << LOG_L(LOG_DEBUG) << "PacketHandler: PacketHandler Initialized. pmsg=" << sizeof(ipq_packet_msg) << " vmsg=" << sizeof(ipq_verdict_msg) << "\n";
    }

    _lastTimeout = 0;
}

PacketHandler::~PacketHandler() {
    ipq_destroy_handle(ipqHandle);      //Releasing handle.
}

void	PacketHandler::insert(pktCmn_t* pkt) {
    pthread_mutex_lock(&_mutPHandler);
    _processQueue.push(pkt);
    pthread_mutex_unlock(&_mutPHandler);
}

//! Read a packet from IP6 QUEUE
pktCmn_t* PacketHandler::getPacket(const int timeout) {
    uint8_t* buffer = NULL; //buffer for receiving packets.
    uint32_t status = 0;

    if (_useIPQ && !ipqHandle) {
        logger << LOG_L(LOG_ERROR) << "IpqHandle not initialized!\n";
        return NULL;
    }

    //If we have queued packets waiting we must process them first
    if (! _processQueue.empty()) {
        logger << LOG_L(LOG_DEBUG) << "PacketHandler::getPacket: Packet to reinject!\n";
        pthread_mutex_lock(&_mutPHandler);
        pktCmn_t* p = _processQueue.front();
        _processQueue.pop();
        p->verdict = PACKET_VERDICT_UNKNOWN;
        pthread_mutex_unlock(&_mutPHandler);
        return p;
    }

    //Lets check if there is a control packet waiting
    pktCmn_t* control = readSocket(timeout);

    if (control) {
        logger << LOG_L(LOG_DEBUG) << "PacketHandler::getPacket: Control Packet!\n";
        return control;
    }

    if (_useIPQ) {
        buffer = new uint8_t[PACKET_BUFFER_SIZE];
        errno = 0;
        status = ipq_read(ipqHandle, buffer, PACKET_BUFFER_SIZE, timeout);

        if (status < 0) {
            ipq_perror(NULL);
            ipq_destroy_handle(ipqHandle);
            delete [] buffer;
            MYTHROW1("Could not read from ip6queue");

        } else if (status == 0) { //No Data
            delete [] buffer;
            int err = errno;

            if (err != 0  && err != EINTR) {
                logger << LOG_L(LOG_ERROR) << "Reseting IPQ socket Err: " << err << "\n";
                ipq_perror("");
                ipq_destroy_handle(ipqHandle);
                ipqHandle = ipq_create_handle(0, PF_INET6);

                if (!ipqHandle) {
                    MYTHROW1("Could not create IP6QUEUE handle. Module Loaded?");
                }

                status = ipq_set_mode(ipqHandle, IPQ_COPY_PACKET, PACKET_IPQ_PAYLOAD_SIZE);

                if (status <= 0) {                                    //Something went wrong. ip6_queue not loaded?
                    ipq_perror(NULL);
                    ipq_destroy_handle(ipqHandle);
                    ipqHandle = NULL;
                    MYTHROW1("Could not initialize IP6QUEUE. Module Loaded?");
                }
            }

            //_lastTimeout = currTime;
            return NULL;
        }

        switch (ipq_message_type(buffer)) {
            case IPQM_PACKET: { //We have a packet!
                ipq_packet_msg_t* ipqPacket = ipq_get_packet(buffer);

                if (conf->getFilterMarkStatus() &&
                        ipqPacket->mark != NF_MARK_FORWARD &&
                        ipqPacket->mark != NF_MARK_OUTPUT &&
                        ipqPacket->mark != NF_MARK_INPUT) {
                    ipq_set_verdict(ipqHandle, ipqPacket->packet_id, NF_ACCEPT, 0, NULL);
                    delete [] buffer;
//						fprintf(stderr,"Wrong MARK %u\n", ipqPacket->mark);
                    return NULL;
                }

//					logger<<LOG_L(LOG_DEBUG)<<"PacketHandler: Packet Mark="<<ipqPacket->mark<<"\n";
                //Filter out White packets
                pktCmn_t* p = Packet::decode(buffer, ipqPacket);
                p->alloc = PKTCMN_ALLOC_BUFFER;

                if(p && p->ptype & PACKET_TYPE_WHITE) {
                    ipq_set_verdict(ipqHandle, ipqPacket->packet_id, NF_ACCEPT, 0, NULL);
                    delete [] buffer;
                    return NULL;
                }

//						fprintf(stderr,"PACKET\n");
                return p;
            }

            case NLMSG_ERROR: { //We have an error!
                ipq_perror("IPQ_ERROR:");
                ipq_get_msgerr(buffer);
                delete [] buffer;
                MYTHROW1("PacketHandler: Got Error from ip6queue");
            }

            default: {  // We have something...treat it as an error!
                logger << LOG_L(LOG_WARNING) << "Got unknown message from ip6queue\n";
                fprintf(stderr, "MTYPE: %u\n", ipq_message_type(buffer));
                //				ipq_get_msgerr("");
                delete [] buffer;
                return NULL;
            }
        }
    }

    return NULL;
}

void PacketHandler::setVerdict(pktCmn_t* packet, const int verdict ) {
    if (!packet) {
        logger << LOG_L(LOG_ERROR) << "Cannot set verdict on NULL packet\n";
        return ;
    }

    timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t delay = ((uint64_t) (tv.tv_sec) * 1000000) + (tv.tv_usec) - packet->timestamp;

    if (ipqHandle) {
        switch (packet->verdict) {
            case	PACKET_VERDICT_ACCEPT_WHITE:
                ipq_set_verdict(ipqHandle, packet->ipqhdr->packet_id, NF_ACCEPT, 0, NULL);
                break;

            case PACKET_VERDICT_ACCEPT:
                if(packet->status == PACKET_DATA_ORIGINAL) {
                    logger << LOG_L(LOG_DEBUG) << "PacketHandler: Original Packet (" << packet->ipqhdr->packet_id << ") processed in " << delay << "us\n";
                    ipq_set_verdict(ipqHandle, packet->ipqhdr->packet_id, NF_ACCEPT, 0, NULL);

                } else {
                    logger << LOG_L(LOG_DEBUG) << "PacketHandler: Changed Packet (" << packet->ipqhdr->packet_id << ") processed in " << delay << "us\n";
                    ipq_set_verdict(ipqHandle, packet->ipqhdr->packet_id, NF_ACCEPT, packet->ipqhdr->data_len, packet->ipqhdr->payload);
                }

                break;

            case PACKET_VERDICT_DROP:
                ipq_set_verdict(ipqHandle, packet->ipqhdr->packet_id, NF_DROP, 0, NULL);
                break;

            default:
                break;
        }

    } else {
        logger << LOG_L(LOG_ERROR) << "Cannot operate over NULL ipq handle\n";
        return ;
    }
}

uint32_t PacketHandler::sendto(uint8_t* buf, uint16_t len, int flags, sockaddr* to, socklen_t tolen) {
    char addr[200];
    uint16_t	port = ntohs( ((sockaddr_in6*) to)->sin6_port );
    inet_ntop(AF_INET6, &((sockaddr_in6*) to)->sin6_addr, addr, 200);
    logger << LOG_L(LOG_DEBUG) << "PacketHandler::sendto: Sending packet to " << addr << " port: " << port << " with " << len << "bytes\n";
    pthread_mutex_lock(&_mutPHSocket);
    int32_t ret = ::sendto(_socket, buf, len, flags, to, tolen);
    pthread_mutex_unlock(&_mutPHSocket);

    if (ret < 0) {
        char* a = strerror(ret);
        logger << LOG_L(LOG_DEBUG) << "PacketHandler::sendto: Error sending: " << a << "\n";
    }

    return ret;
}




pktCmn_t*	PacketHandler::readSocket(uint32_t timeout) {
    fd_set rfds;
    struct timeval tv;
    int retval;
    pthread_mutex_lock(&_mutPHSocket);
    FD_ZERO(&rfds);
    FD_SET(_socket, &rfds);

    if(!_useIPQ) {
        tv.tv_sec = timeout  / 1000000;
        tv.tv_usec = timeout % 1000000;

    } else {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
    }

    retval = select(_socket + 1, &rfds, NULL, NULL, &tv);

    if (retval <= 0) {
        pthread_mutex_unlock(&_mutPHSocket);
        return NULL;

    } else {
        if (retval > 0) {
            uint8_t*	buffer = new uint8_t[1600];
            sockaddr_in6*	from = new sockaddr_in6;
            socklen_t fromLen = sizeof(sockaddr_in6);
            int32_t	readBytes = recvfrom(_socket, buffer, 1600, 0, (sockaddr*) from, &fromLen);
            pthread_mutex_unlock(&_mutPHSocket);

            if (readBytes <= 0) {
                delete [] buffer;
                return NULL;
            }

            pktCmn_t* p = Packet::decode(buffer, readBytes, from);
            p->ptype |= PACKET_TYPE_SIG;
            return p;
        }
    }

    pthread_mutex_unlock(&_mutPHSocket);
    return NULL;
}
