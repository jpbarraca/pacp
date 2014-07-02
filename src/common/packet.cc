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


#include "packet.h"

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <libipq.h>
#include <openssl/md5.h>
#include <time.h>
#include "log.h"
#include "fec.h"
#include "hash.h"
#include "netinet/tcp.h"
#include <sys/time.h>
#include <exception.h>
#include <keyManager.h>
#include <debug.h>

#define IPPROTO_HOPOPTS_CHARGING 		0x2a
#define IP6_HDR_SIZE								40
#define CHARGING_UDP_PORT			 			9999
#define PACKET_BUFFER_SIZE					2048
#define IP6_MULTICAST_ADDR					0xff
#define IP6_MULTICAST_MASK					3
#define IP6_LINKLOCAL_ADDR					0xfe80

//WHILE LIST PORTS
//RIPNG, RIPv2
#define UDPWhitePortNumber 6
static uint16_t	UDPWhitePortList[UDPWhitePortNumber] = {0, 9999, 521, 520, 910, 654};

pktCmn_t* Packet::decode(uint8_t* buffer, int32_t bufferLength, sockaddr_in6* sock) {
    if (!buffer || !bufferLength || !sock) {
        MYTHROW1("Error with parameters");
    }

    pktCmn_t* p = alloc(0);
    //Time Stats
    timeval tv;
    gettimeofday(&tv, NULL);
    p->timestamp = ((uint64_t) tv.tv_sec * 1000000) + tv.tv_usec;
    p->buffer = buffer;
    p->ipv6sock = sock;
    p->psize = bufferLength;
    setupControl(p, buffer);
    return p;
}



pktCmn_t* Packet::decode(uint8_t* buffer, ipq_packet_msg_t* p) {
    uint8_t* payload = p->payload;
    uint8_t* pProto;
    pktCmn_t* packet = alloc(0);
    packet->buffer = buffer;
    packet->ipqhdr = p;
    packet->ptype = PACKET_TYPE_UNKNOWN;
    //Time Stats
    timeval tv;
    gettimeofday(&tv, NULL);
    packet->timestamp = ((uint64_t) tv.tv_sec * 1000000) + tv.tv_usec;

    if (payload[0] >> 4 != 6 ) {
        //		logger << LOG_L(LOG_WARNING) << "Can only support IPV6 Packets!\n";
        setupWhite(packet);

    } else {
        packet->ipv6hdr = (ip6_hdr*) p->payload;
        uint32_t	ip6_mcast = IP6_MULTICAST_ADDR;
        uint32_t	ip6_ll	= IP6_LINKLOCAL_ADDR;
        int8_t	cHeader	= -1;

        if (!memcmp(IPV6Packet::getDst(packet), &ip6_mcast, 1) || !memcmp(IPV6Packet::getDst(packet), &ip6_ll, 2)) {
            setupWhite(packet);

        } else {
            bool setupd = false;
            payload += IP6_HDR_SIZE;
            pProto = IPV6Packet::getNextHdr(packet);

            if (!pProto) {
                setupWhite(packet);

            } else

                //Scan for a TCP or UDP header
                while (!setupd) {
                    //Cicle through options
                    //Last header was a CHeader must set the next hdr
                    if (cHeader != -1) {
                        if (cHeader == HEADER_TYPE_SMALL) {
                            PACPHeaderSmall::setNxt(packet, pProto[0]);

                        } else {
                            PACPHeaderFull::setNxt(packet, pProto[0]);
                        }

                        cHeader = -1;
                    }

                    //We have a TCP
                    if (pProto[0] == IPPROTO_TCP) {
                        TCPPacket::setup(packet, payload);
                        setupd = true;
                        logger << LOG_L(LOG_DEBUG) << "Packet: Packet is TCP Data\n";
                        break;
                    }

                    //Or it is an UDP packet?
                    if (pProto[0] == IPPROTO_UDP ) {
                        UDPPacket::setup(packet, payload);
                        setupd = true;

                        if (UDPPacket::inWhiteList(packet, UDPWhitePortList, UDPWhitePortNumber)) {
                            setupWhite(packet);
                            break;
                        }

                        logger << LOG_L(LOG_DEBUG) << "Packet: Packet is UDP Data\n";
                        break;
                    }

                    //Maybe it is an Data packet already with a Charging Header
                    if (*pProto == IPPROTO_HOPOPTS && payload[2] == IPPROTO_HOPOPTS_CHARGING) {
                        //DUP PACKET!!
                        logger << LOG_L(LOG_DEBUG) << "Packet: Packet is Data With Header\n";

                        if (p->indev_name[0] == 0 || !strcmp((const char*) p->indev_name, "lo") ) {
                            setupWhite(packet);
                            setupd = true;
                            break;
                        }

                        //Its a Data packet allready with a HOP by HOP Header
                        cHeader = payload[4];

                        if (cHeader & HEADER_TYPE_SMALL) {
                            PACPHeaderSmall::setup(packet, payload);

                        } else if (cHeader & HEADER_TYPE_FULL) {
                            PACPHeaderFull::setup(packet, payload);

                        } else {
                            logger << LOG_L(LOG_WARNING) << "Packet: Invalid type of Header: 0x" << hex << cHeader << dec << "\n";
                            setupWhite(packet);
                            setupd = true;
                            break;
                        }

                        //Must find the upper layer protocol
                    }

                    pProto = payload;
                    payload += (payload[1] + 1) * 8;

                    //Unknown protocol???

                    if (payload > p->payload + p->data_len) {
                        setupWhite(packet);
                        setupd = true; //Loop out
                        break;
                    }
                }
        }
    }

    if (packet->ipqhdr->timestamp_sec == 0) {
        packet->ipqhdr->timestamp_sec = time(NULL);
    }

    if (!(packet->ptype & PACKET_TYPE_WHITE))
        switch (Packet::getDirection(packet)) {
            case PACKET_DIRECTION_OUT:
                logger << LOG_L(LOG_DEBUG) << "PACKET IS GOING OUT\n";
                break;

            case PACKET_DIRECTION_IN:
                logger << LOG_L(LOG_DEBUG) << "PACKET IS COMMING IN\n";
                break;

            case PACKET_DIRECTION_FWR:
                logger << LOG_L(LOG_DEBUG) << "PACKET IS BEING FWR\n";
                break;
        }

    return packet;
}


uint8_t	Packet::getDirection(pktCmn_t* p) {
    if (!p) {
        return PACKET_DIRECTION_UNKNOWN;
    }

    if (p->ipv6sock) {
        return PACKET_DIRECTION_IN;
    }

    if (!p->ipqhdr) {
        return PACKET_DIRECTION_UNKNOWN;
    }

    switch (p->ipqhdr->mark) {
        case NF_MARK_INPUT:
            return PACKET_DIRECTION_IN;

        case NF_MARK_OUTPUT:
            return PACKET_DIRECTION_OUT;

        case NF_MARK_FORWARD:
            return PACKET_DIRECTION_FWR;

        default:
            return PACKET_DIRECTION_UNKNOWN;
    }
}

bool Packet::sameNet(in6_addr* addr, in6_addr* net, uint8_t mask) {
    if(!addr || !net || ! mask) {
        return false;
    }

    uint32_t n = mask / 8;
    uint32_t i;

    for(i = 0; i < n; i++) {
        uint8_t a = *(((uint8_t*) addr) + i);
        uint8_t b = *(((uint8_t*) net) + i);
//fprintf(stderr,"%X:%X ",a,b);

        if(a != b) {
//	fprintf(stderr,"\n");
            return false;
        }
    }

//printf(stderr,"\n");
    return true;
}


/*
    Allocates a packet

*/
pktCmn_t* Packet::alloc(uint32_t	bl) {
    pktCmn_t*	cmn = new pktCmn_t;

    if (!cmn) {
        MYTHROW1("Error allocating memory");
    }

    memset(cmn, 0, sizeof(pktCmn_t));

    if (bl) {
        cmn->buffer = new uint8_t[bl];

        if (!cmn->buffer) {
            delete cmn;
            return NULL;
        }

        cmn->alloc = PKTCMN_ALLOC_BUFFER;
    }

    return cmn;
}

/*
    Free a packet

*/
void Packet::free(pktCmn_t* p) {
    if (!p) {
        MYTHROW1("Error with parameters");
    }

    if(p->ptype & PACKET_TYPE_DATA_SHDR) {
        PACPHeaderSmall::free(p);

    } else if(p->ptype & PACKET_TYPE_DATA_FHDR) {
        PACPHeaderFull::free(p);

    } else if (p->ptype & PACKET_TYPE_SIG_SINIT) {
        PACPSessionInit::free(p);

    } else if (p->ptype & PACKET_TYPE_SIG_SINIT_RESP) {
        PACPSessionInitResponse::free(p);

    } else if (p->ptype & PACKET_TYPE_SIG_FAUTH) {
        PACPFlowAuth::free(p);

    } else if (p->ptype & PACKET_TYPE_SIG_FAUTH_RESP) {
        PACPFlowAuthResponse::free(p);

    } else if (p->ptype & PACKET_TYPE_SIG_REP) {
        PACPReport::free(p);

    } else if (p->ptype & PACKET_TYPE_SIG_REP_RESP) {
        PACPReportResponse::free(p);
    }

    if (p->buffer && p->alloc & PKTCMN_ALLOC_BUFFER) {
        delete [] p->buffer;
    }

    delete p;
}


void Packet::shiftData(pktCmn_t* p, uint8_t* offset, int32_t len) {
    int32_t	plen = IPV6Packet::getPLength(p);
    IPV6Packet::setPLength(p, plen + len);
    int i;

    for(i = plen; i >= 0 ; i -= sizeof(uint32_t)) {
        memcpy(&offset[i + len], &offset[i], sizeof(uint32_t));
    }

    if(i > 0) {
        memcpy(&offset[len], &offset[0], i);
    }

    /*
    	if(len % sizeof(uint32_t))
    	{
    	int i;

    		for(i = plen;i >= 0 ;i-=sizeof(uint32_t)){
        //			offset[i+len] = offset[i];
    			memcpy(&offset[i+len], &offset[i], sizeof(uint32_t));
    		}
    	}else{
    	int i;

    	for(i = plen;i >= 0 ;i--){
    		offset[i+len] = offset[i];
    		}
    	}
    */
    /*
        int i;
        int rest = len % sizeof(uint64_t);

        for(i = rest;i >= 0 ;i--){
        offset[i+len] = offset[i];
        }

        int intoffset = len - rest;
        int intcount = intoffset / sizeof(uint64_t);
    	int intlen = len / sizeof(uint64_t);

    	fprintf(stderr,"PLEN: %u, IntCount: %u, Rest: %u, IntLen: %u, intOffset: %u\n", plen, intcount, rest,intlen, intoffset);

    	if(intcount){
    	  for(i = intcount;i >= 0 ;i--){
    	    ((uint64_t*) offset)[i+intlen] = ((uint64_t*) offset)[i];
    	  }
    	}
    */
    memset(offset, 0, len);

    //Adjust IPQ Packet size
    if (p->ipqhdr) {
        p->ipqhdr->data_len += len;
    }
}


/*
 	Decodes a control packet

*/
void Packet::setupControl(pktCmn_t* p, uint8_t* data) {
    if (!p || !data) {
        MYTHROW1("Error with parameters");
    }

    p->ptype |= PACKET_TYPE_SIG;
    p->status = PACKET_DATA_ORIGINAL;

    if (getDirection(p) == PACKET_DIRECTION_IN) {
        p->verdict = PACKET_VERDICT_DROP;
    }

    switch (data[0] & 0x0F) {
        case PACKET_SIG_REPORT:
            PACPReport::setup(p, data);
            break;

        case PACKET_SIG_REPORT_RESP:
            PACPReportResponse::setup(p, data);
            break;

        case PACKET_SIG_SESSION_INIT:
            PACPSessionInit::setup(p, data);
            break;

        case PACKET_SIG_SESSION_INIT_RESP:
            PACPSessionInitResponse::setup(p, data);
            break;

        case PACKET_SIG_FLOW_AUTH:
            PACPFlowAuth::setup(p, data);
            break;

        case PACKET_SIG_FLOW_AUTH_RESP:
            PACPFlowAuthResponse::setup(p, data);
            break;

        default:
            logger << LOG_L(LOG_DEBUG) << "Packet::SetupControl: UNKNOWN type of control packet  \n";
    }
}


/*
	Decodes a White packet
	Actually it just sets some flags. No handling required.
*/
void Packet::setupWhite(pktCmn_t* p) {
    p->ptype = PACKET_TYPE_WHITE;
    p->verdict = PACKET_VERDICT_ACCEPT;
    p->status = PACKET_DATA_ORIGINAL;
}



/*
	UDP Packet Class
*/
uint8_t	UDPPacket::inWhiteList(pktCmn_t* p, uint16_t* pl, uint16_t np) {
    if (!p || !pl || !np || !p->udphdr || !p->ptype & PACKET_TYPE_DATA) {
        MYTHROW1("Error with parameters");
    }

    int i;

    for (i = 0; i < np; i++)
        if ( ntohs(p->udphdr->dest) == pl[i] ) {
            return true;
        }

    return false;
}


void UDPPacket::setup(pktCmn_t* packet, uint8_t* data) {
    if (!packet || !data) {
        MYTHROW1("Error with parameters");
    }

    packet->ptype |= PACKET_TYPE_DATA;
    packet->ptype |= PACKET_TYPE_DATA_UDP;
    packet->status = PACKET_DATA_ORIGINAL;
    packet->udphdr = (udphdr*) data;
}



/*

    IPV6Packet

*/
in6_addr*	IPV6Packet::getDst(pktCmn_t* p) {
    if (p && p->ipv6hdr) {
        return &((ip6_hdr*) p->ipv6hdr)->ip6_dst;
    }

    return NULL;
}

in6_addr*	IPV6Packet::getSrc(pktCmn_t* p) {
    if (!p) {
        MYTHROW1("Error with parameters");
    }

    if (p->ipv6hdr) {
        return &((ip6_hdr*) p->ipv6hdr)->ip6_src;
    }

    //Packet received through a socket
    if (p->ipv6sock) {
        return &p->ipv6sock->sin6_addr;
    }

    return NULL;
}

uint16_t	IPV6Packet::getPayloadLength(pktCmn_t* p) {
    if (p && p->ipv6hdr) {
        return ntohs(((ip6_hdr*) p->ipv6hdr)->ip6_plen);
    }

    return 0;
}


uint8_t*	IPV6Packet::getNextHdr(pktCmn_t* p) {
    if (p && p->ipv6hdr) {
        return &((ip6_hdr*) p->ipv6hdr)->ip6_nxt;
    }

    return NULL;
}

void	IPV6Packet::setNextHdr(pktCmn_t* p, uint8_t n) {
    if (!p || !p->ipv6hdr) {
        MYTHROW1("Error in Parameters");
    }

    p->ipv6hdr->ip6_nxt = n;
}

uint16_t	IPV6Packet::getPLength(pktCmn_t* p) {
    if (p && p->ipv6hdr) {
        return ntohs(((ip6_hdr*) p->ipv6hdr)->ip6_plen);
    }

    return 0;
}

void	IPV6Packet::setPLength(pktCmn_t* p, uint16_t pl) {
    if (p && p->ipv6hdr) {
        ((ip6_hdr*) p->ipv6hdr)->ip6_plen = htons(pl);
    }
}


/*
 	PACPHeaderFull


*/

void PACPHeaderFull::setup(pktCmn_t* packet, uint8_t* data) {
    if (!packet || !data) {
        MYTHROW1("Error with parameters");
    }

    packet->ptype |= PACKET_TYPE_DATA_FHDR;
    packet->alloc |= PKTCMN_ALLOC_SIG;
    chargingHeader_t*	c = new chargingHeader_t;
    memset(c, 0, sizeof(chargingHeader_t));
    packet->sighdr = (uint8_t*) c;
    c->buffer = data;
    unpack(packet);
}

void PACPHeaderFull::free(pktCmn_t* p) {
    if (p) {
        if (p->sighdr && p->alloc & PKTCMN_ALLOC_FHDR) {
            delete ((chargingHeader_t*) p->sighdr);
            p->alloc &= ~PKTCMN_ALLOC_FHDR;
        }
    }
}

void PACPHeaderFull::pack(pktCmn_t* p) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_DATA_FHDR) || !p->ipv6hdr ) {
        MYTHROW1("Error with parameters");
    }

    p->status = PACKET_DATA_PACKED;
    uint8_t* chData = ((uint8_t*) p->ipv6hdr) + IP6_HDR_SIZE;
    chargingHeader_t* ch = (chargingHeader_t*) p->sighdr;
    uint16_t extLength = getFullLength(p);
    Packet::shiftData(p, chData, extLength);
//	fprintf(stderr,"FullHeaderL: %u, HeaderL: %u, Padding: %u\n",getFullLength(p), getLength(p), getPadding(p));
    chData[0] = *ch->nextHeader;
    chData[1] = *ch->headerLength = (getFullLength(p) - 4) / 8 ;
    chData[2] = *ch->type;
    chData[3] = *ch->dataLength  = getFullLength(p) - 4;
    chData[HEADER_FULL_CODE_OFFSET] = *ch->code;
    memcpy(&chData[HEADER_FULL_SEQUENCE_OFFSET], ch->sequence, HEADER_SEQUENCE_SIZE);
    memcpy(&chData[HEADER_FULL_ROUTEHASH_OFFSET], ch->routeHash, HEADER_ROUTEHASH_SIZE);
    memcpy(&chData[HEADER_FULL_ROUTEID_OFFSET], ch->routeID, HEADER_ROUTEID_SIZE);
    memcpy(&chData[HEADER_FULL_HASHCHAIN_OFFSET], ch->hashChain, HEADER_HASHCHAIN_SIZE);
    chData[HEADER_FULL_MAC_OFFSET] = *ch->macLength;

    if (chData[HEADER_FULL_MAC_OFFSET]) {
        memcpy(&chData[HEADER_FULL_MAC_OFFSET + 1], ch->mac, chData[HEADER_FULL_MAC_OFFSET]);
    }

    if (ch->buffer) {
        delete [] ch->buffer;
    }

    IPV6Packet::setNextHdr(p, IPPROTO_HOPOPTS);
    ch->buffer = chData;
    unpack(p);

    if(p->ptype & PACKET_TYPE_DATA_TCP) {
        ((uint8_t*) p->tcphdr) += extLength;
        TCPPacket::updateMSS(p);

    } else if(p->ptype & PACKET_TYPE_DATA_UDP) {
        ((uint8_t*) p->udphdr) += extLength;
    }
}

void PACPHeaderFull::unpack(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !((chargingHeader_t*) packet->sighdr)->buffer) {
        MYTHROW1("Error with parameters");
    }

    chargingHeader_t* ch = (chargingHeader_t*) packet->sighdr;
    //Option Header
    ch->nextHeader = &ch->buffer[0];
    ch->headerLength = &ch->buffer[1];
    ch->type = &ch->buffer[2];
    ch->dataLength = &ch->buffer[3];
    //Option Data
    ch->code = &ch->buffer[HEADER_FULL_CODE_OFFSET];
    ch->index = &ch->buffer[HEADER_FULL_INDEX_OFFSET];
    ch->sequence = (uint16_t*) & ch->buffer[HEADER_FULL_SEQUENCE_OFFSET];
    ch->routeHash = &ch->buffer[HEADER_FULL_ROUTEHASH_OFFSET];
    ch->routeID = &ch->buffer[HEADER_FULL_ROUTEID_OFFSET];
    ch->hashChain = &ch->buffer[HEADER_FULL_HASHCHAIN_OFFSET];
    ch->macLength = &ch->buffer[HEADER_FULL_MAC_OFFSET];
    ch->mac = &ch->buffer[HEADER_FULL_MAC_OFFSET + 1];
}



void PACPHeaderFull::addHeader(pktCmn_t* packet, uint8_t index, uint16_t sequence) {
    chargingHeader_t* ch;

    if (!packet) {
        MYTHROW1("Error with parameters");
    }

    if (!packet->sighdr) {
        ch = new chargingHeader_t;
        memset(ch, 0, sizeof(chargingHeader_t));
        ch->buffer = new uint8_t[512];
        memset(ch->buffer, 0, 512);
        packet->sighdr = (uint8_t*) ch;
        packet->alloc |= PKTCMN_ALLOC_FHDR;
        packet->ptype |= PACKET_TYPE_DATA_FHDR;
        unpack(packet);

    } else {
        ch = (chargingHeader_t*) packet->sighdr;
    }

    logger << LOG_L(LOG_DEBUG) << "Packet: Adding Full header to packet:\n";
    *ch->nextHeader = *IPV6Packet::getNextHdr(packet);
    *ch->headerLength = (getFullLength(packet) - 4 ) / 8;
    *ch->type = IPPROTO_HOPOPTS_CHARGING;
    *ch->dataLength = getLength(packet);
    *ch->code = HEADER_TYPE_FULL;
    *ch->index = index;
    logger << LOG_L(LOG_DEBUG) << "Packet: Index is " << (uint32_t) *ch->index << "\n";
    uint32_t	hash = fnv_32a_buf(IPV6Packet::getSrc(packet), sizeof(in6_addr), 0);
    memcpy(ch->routeHash, &hash , HEADER_ROUTEHASH_SIZE);
    ch->routeHash[0] = 0;	//Used for Hop Count
    memset(ch->routeID, 0x00, HEADER_ROUTEID_SIZE);
    *ch->sequence = htons(sequence);
    logger << LOG_L(LOG_DEBUG) << "Packet: Sequence is " << (uint16_t) sequence << "\n";
    *ch->macLength = 0;
}


void PACPHeaderFull::setNxt(pktCmn_t* packet, uint8_t nxt) {
    if (!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_FHDR) {
        MYTHROW1("Error with parameters");
    }

//	fprintf(stderr,"SET NEXT!\n");
    *(((chargingHeader_t*) packet->sighdr)->nextHeader) = nxt;
}

uint8_t PACPHeaderFull::getCode(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_FHDR) {
        fprintf(stderr, "Packet: %x, hdr: %x, ptype: %u\n", packet, packet->sighdr, packet->ptype);
        MYTHROW1("Error with parameters");
    }

    return *(((chargingHeader_t*) packet->sighdr)->code);
}



void PACPHeaderFull::initHashChain(pktCmn_t* packet, uint8_t* secret, uint16_t sl) {
    if (!packet || !packet->sighdr || !(packet->ptype & PACKET_TYPE_DATA_FHDR)) {
        MYTHROW1("Error with parameters");
    }

    uint8_t*	buf1 = new uint8_t[sizeof(uint8_t) + sl + HEADER_SEQUENCE_SIZE + 2 * sizeof(in6_addr) + sizeof(uint16_t)];

    if (!buf1) {
        MYTHROW1("Could not allocate memory");
    }

    uint8_t	buf2[HEADER_HASHCHAIN_SIZE];
    uint16_t	size = 0;
    uint16_t	sequence = 0;
    uint8_t	index = 0;
    chargingHeader_t* ch = (chargingHeader_t*) packet->sighdr;
    uint16_t	dataLen = IPV6Packet::getPLength(packet);
    memcpy(buf1, &dataLen, sizeof(uint16_t));
    size += sizeof(uint16_t);
    index = *ch->index;
    memcpy(&buf1[size], &index, sizeof(uint8_t));
    size += sizeof(uint8_t);
    sequence = getSequence(packet);
    memcpy(&buf1[size], &sequence, HEADER_SEQUENCE_SIZE);
    size += HEADER_SEQUENCE_SIZE;
    memcpy(&buf1[size], secret, sl);
    size += sl;
    memcpy(&buf1[size], IPV6Packet::getSrc(packet), sizeof(in6_addr));
    size += sizeof(in6_addr);
    memcpy(&buf1[size], IPV6Packet::getDst(packet), sizeof(in6_addr));
    size += sizeof(in6_addr);
    MD5(buf1, size, buf2);
    delete [] buf1;
    memcpy(ch->hashChain, buf2, HEADER_HASHCHAIN_SIZE);
}


void PACPHeaderFull::updateHashChain(pktCmn_t* packet, uint8_t* secret, uint16_t sl) {
    if (!packet || !secret || !sl || !packet->sighdr || ! (packet->ptype & PACKET_TYPE_DATA_FHDR)) {
        MYTHROW1("Error with parameters");
    }

    uint8_t* buf1 = new uint8_t[sl + 1024];
    uint8_t	buf2[128];
    int size = 0;
    uint16_t	sequence = 0;
    uint16_t dataSize = IPV6Packet::getPLength(packet) - getFullLength(packet);
    chargingHeader_t* ch = (chargingHeader_t*) packet->sighdr;
    memcpy(buf1, &dataSize, sizeof(uint16_t));
    size += sizeof(uint16_t);
    sequence = getSequence(packet);
    memcpy(buf1, &sequence, HEADER_SEQUENCE_SIZE);
    size += HEADER_SEQUENCE_SIZE;
    memcpy(&buf1[size], secret, sl);
    size += sl;
    memcpy(&buf1[size], IPV6Packet::getSrc(packet), sizeof(in6_addr));
    size += sizeof(in6_addr);
    memcpy(&buf1[size], IPV6Packet::getDst(packet), sizeof(in6_addr));
    size += sizeof(in6_addr);
    MD5(buf1, size, buf2);
    memcpy(ch->hashChain + HEADER_CHARGING_HASH_SIZE, buf2 + HEADER_CHARGING_HASH_SIZE, HEADER_REWARDING_HASH_SIZE);
    delete [] buf1;
}




void PACPHeaderFull::updateRID(pktCmn_t* packet, uint8_t* uid, uint16_t	ul, fec_parms* fecCode) {
    if (!packet || !uid || ! fecCode || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_FHDR) {
        MYTHROW1("Error with parameters");
    }

    chargingHeader_t*	ch = (chargingHeader_t*) packet->sighdr;
    //    logger<<LOG_L(LOG_DEBUG)<<"Packet: Updating RID with ID:\""<<id<<"\"\n";
    uint16_t index = *ch->index;
    uint8_t* routeID = ch->routeID;
    uint8_t* nhops = ch->routeHash;
    nhops[0]++;
    fec_encode_iter(fecCode, (gf*) uid, routeID, index, nhops[0], HEADER_ROUTEID_SIZE);
}




void PACPHeaderFull::updateRHash(pktCmn_t* packet, uint8_t* uid, uint16_t	uidl) {
    if (!packet || !uid || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_FHDR) {
        MYTHROW1("Error with parameters");
    }

    uint8_t	oldRHash[HEADER_ROUTEHASH_SIZE + HEADER_ROUTEID_SIZE];
    chargingHeader_t* ch = (chargingHeader_t*) packet->sighdr;
    memcpy(oldRHash, ch->routeHash, HEADER_ROUTEHASH_SIZE);
    memcpy(oldRHash + HEADER_ROUTEHASH_SIZE, uid, HEADER_ROUTEID_SIZE);
    Fnv32_t hash = fnv_32a_buf(oldRHash, HEADER_ROUTEHASH_SIZE * 2, FNV1_32A_INIT);
    memcpy(ch->routeHash + 1, &hash, HEADER_ROUTEHASH_SIZE - 1);
}




uint8_t* PACPHeaderFull::getRHash(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_FHDR) {
        MYTHROW1("Error with parameters");
    }

    chargingHeader_t* ch = (chargingHeader_t*) packet->sighdr;
    return ch->routeHash;
}




uint8_t* PACPHeaderFull::getHashChain(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_FHDR) {
        MYTHROW1("Error with parameters");
    }

    chargingHeader_t* ch = (chargingHeader_t*) packet->sighdr;
    return (uint8_t*) ch->hashChain;
}

uint8_t PACPHeaderFull::getIndex(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_FHDR) {
        MYTHROW1("Error with parameters");
    }

    chargingHeader_t* ch = (chargingHeader_t*) packet->sighdr;
    return *ch->index;
}

uint8_t* PACPHeaderFull::getRID(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_FHDR) {
        MYTHROW1("Error with parameters");
    }

    chargingHeader_t* ch = (chargingHeader_t*) packet->sighdr;
    return ch->routeID;
}

uint16_t	PACPHeaderFull::getFullLength(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_FHDR) {
        MYTHROW1("Error with parameters");
    }

    return getLength(packet) + getPadding(packet);
}

uint16_t	PACPHeaderFull::getLength(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_FHDR) {
        MYTHROW1("Error with parameters");
    }

    uint16_t	size;
    chargingHeader_t* ch = (chargingHeader_t*) packet->sighdr;
    size = 4 + 1 + 1 + 2 + HEADER_ROUTEHASH_SIZE + sizeof(in6_addr) + CRYPTO_HASH_SIZE + sizeof(uint8_t);

    if(ch->macLength && *ch->macLength) {
        size += *ch->macLength;
    }

    return size;
}

void PACPHeaderFull::sign(pktCmn_t* packet, kmKey_t* key) {
    if(!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_FHDR || !key || !key->ec) {
        MYTHROW1("Error with parameters");
    }

    chargingHeader_t* ch = (chargingHeader_t*) packet->sighdr;
    unsigned char*	buf = new unsigned char[200];
    unsigned char* buffi = buf;
    memcpy(buffi, IPV6Packet::getSrc(packet), sizeof(in6_addr));
    buffi += sizeof(in6_addr);
    memcpy(buffi, IPV6Packet::getDst(packet), sizeof(in6_addr));
    buffi += sizeof(in6_addr);
    memcpy(buffi, ch->sequence, sizeof(uint16_t));
    buffi += sizeof(uint16_t);
    uint16_t	len = 2 * sizeof(in6_addr) + sizeof(uint16_t);
    ch->mac = new uint8_t[200];
    uint16_t	maclen = 200;
    KeyManager::signECDSA(key, ch->mac, &maclen, buf, len);
    *ch->macLength = maclen;
    *ch->headerLength = (getFullLength(packet) - 4) / 8;
    *ch->dataLength = getFullLength(packet) - 4;
    delete [] buf;
}

bool PACPHeaderFull::verifySig(pktCmn_t* packet, kmKey_t* key) {
    if(!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_FHDR || !key || !key->ec) {
//		fprintf(stderr,"Packet: %x, sig: %x, ptype: %x, key: %x, ec: %x\n", packet, packet->sighdr, packet->ptype, key);
        MYTHROW1("Error with parameters");
    }

    chargingHeader_t* ch = (chargingHeader_t*) packet->sighdr;
    unsigned char*	buf = new unsigned char[200];
    unsigned char* buffi = buf;
    memcpy(buffi, IPV6Packet::getSrc(packet), sizeof(in6_addr));
    buffi += sizeof(in6_addr);
    memcpy(buffi, IPV6Packet::getDst(packet), sizeof(in6_addr));
    buffi += sizeof(in6_addr);
    memcpy(buffi, ch->sequence, sizeof(uint16_t));
    buffi += sizeof(uint16_t);
    uint16_t	len = 2 * sizeof(in6_addr) + sizeof(uint16_t);
    int ret = KeyManager::verifyECDSA(key, ch->mac, *ch->macLength, buf, len);
    delete [] buf;
    return ret;
}

/*
	PACPHeaderSmall


*/

void PACPHeaderSmall::setup(pktCmn_t* packet, uint8_t* data) {
    if (!packet || !data) {
        MYTHROW1("Error with parameters");
    }

    packet->ptype |= PACKET_TYPE_DATA_SHDR;
    packet->alloc |= PKTCMN_ALLOC_SIG;
    chargingHeaderSmall_t* c = new chargingHeaderSmall_t;
    memset(c, 0, sizeof(chargingHeaderSmall_t));
    packet->sighdr = (uint8_t*) c;
    c->buffer = data;
    unpack(packet);
}

void PACPHeaderSmall::free(pktCmn_t* p) {
    if (p && p->ptype & PACKET_TYPE_DATA_SHDR) {
        if(((chargingHeader_t*) p->sighdr)->alloc & PKTSHDR_ALLOC_BUFFER) {
            delete ((chargingHeader_t*) p->sighdr)->buffer;
        }

        if (p->sighdr && p->alloc & PKTCMN_ALLOC_SHDR) {
            delete ((chargingHeader_t*) p->sighdr);
            p->alloc &= ~PKTCMN_ALLOC_SHDR;
        }
    }
}


void PACPHeaderSmall::pack(pktCmn_t* p) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_DATA_SHDR) || !p->ipv6hdr ) {
        MYTHROW1("Error in Parameters") ;
    }

    p->status = PACKET_DATA_PACKED;
    uint8_t* chData = ((uint8_t*) p->ipv6hdr) + IP6_HDR_SIZE;
    chargingHeaderSmall_t* ch = (chargingHeaderSmall_t*) p->sighdr;
    uint16_t extLength = getFullLength(p);
    Packet::shiftData(p, chData, extLength);
    chData[0] = *ch->nextHeader;
    chData[1] = *ch->headerLength = (getFullLength(p) - 4 ) / 8;
    chData[2] = *ch->type;
    chData[3] = *ch->dataLength  = getFullLength(p) - 4;
    chData[HEADER_SMALL_CODE_OFFSET] = *ch->code;
    chData[HEADER_SMALL_CODE_OFFSET] |= HEADER_TYPE_SMALL;
    memcpy(&chData[HEADER_SMALL_SEQUENCE_OFFSET], ch->sequence, HEADER_SEQUENCE_SIZE);
    memcpy(&chData[HEADER_SMALL_HASHCHAIN_OFFSET], ch->hashChain, HEADER_HASHCHAIN_SIZE);
    chData[HEADER_SMALL_MAC_OFFSET] = *ch->macLength;

    if (chData[HEADER_SMALL_MAC_OFFSET]) {
        memcpy(&chData[HEADER_SMALL_MAC_OFFSET + sizeof(uint8_t)], ch->mac, chData[HEADER_SMALL_MAC_OFFSET]);
    }

    if (ch->buffer) {
        delete [] ch->buffer;
    }

    IPV6Packet::setNextHdr(p, IPPROTO_HOPOPTS);
    ch->buffer = chData;
    unpack(p);

    if(p->ptype & PACKET_TYPE_DATA_TCP) {
        ((uint8_t*) p->tcphdr) += extLength;
        TCPPacket::updateMSS(p);

    } else if(p->ptype & PACKET_TYPE_DATA_UDP) {
        ((uint8_t*) p->udphdr) += extLength;
    }
}

void PACPHeaderSmall::unpack(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !((chargingHeader_t*) packet->sighdr)->buffer) {
        MYTHROW1("Error with parameters");
    }

    chargingHeaderSmall_t* ch = (chargingHeaderSmall_t*) packet->sighdr;
    //Option Header
    ch->nextHeader = &ch->buffer[0];
    ch->headerLength = &ch->buffer[1];
    ch->type = &ch->buffer[2];
    ch->dataLength = &ch->buffer[3];
    //Option Data
    ch->code = &ch->buffer[HEADER_SMALL_CODE_OFFSET];
    ch->sequence = (uint16_t*) & ch->buffer[HEADER_SMALL_SEQUENCE_OFFSET];
    ch->hashChain = &ch->buffer[HEADER_SMALL_HASHCHAIN_OFFSET];
    ch->macLength = &ch->buffer[HEADER_SMALL_MAC_OFFSET];
    ch->mac = &ch->buffer[HEADER_SMALL_MAC_OFFSET + sizeof(uint8_t)];
}


void PACPHeaderSmall::setNxt(pktCmn_t* packet, uint8_t nxt) {
    if (!packet || !packet->sighdr || !((chargingHeader_t*) packet->sighdr)->buffer) {
        MYTHROW1("Error with parameters");
    }

    chargingHeader_t* ch = (chargingHeader_t*) packet->sighdr;
    *ch->nextHeader = nxt;
}

uint8_t PACPHeaderSmall::getCode(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_SHDR) {
        MYTHROW1("Error with parameters");
    }

    return *(((chargingHeaderSmall_t*) packet->sighdr)->code);
}



void PACPHeaderSmall::addHeader(pktCmn_t* packet, uint8_t index, uint16_t sequence) {
    chargingHeaderSmall_t* ch;

    if (!packet) {
        MYTHROW1("Error with parameters");
    }

    if (!packet->sighdr) {
        ch = new chargingHeaderSmall_t;
        memset(ch, 0, sizeof(chargingHeaderSmall_t));
        ch->buffer = new uint8_t[HEADER_PROOF_SMALL_SIZE];
        memset(ch->buffer, 0, HEADER_PROOF_SMALL_SIZE);
        packet->sighdr = (uint8_t*) ch;
        packet->alloc |= PKTCMN_ALLOC_SHDR;
        packet->ptype |= PACKET_TYPE_DATA_SHDR;
        unpack(packet);

    } else {
        ch = (chargingHeaderSmall_t*) packet->sighdr;
    }

    *ch->nextHeader = *IPV6Packet::getNextHdr(packet);
    *ch->type = IPPROTO_HOPOPTS_CHARGING;
    *ch->code = HEADER_TYPE_SMALL;
    *ch->sequence = htons(sequence);
    *ch->macLength = 0;
    *ch->headerLength = (getFullLength(packet) - 4 ) / 8;
    *ch->dataLength = getLength(packet);
    logger << LOG_L(LOG_DEBUG) << "Packet: Adding small header to packet: " << getFullLength(packet) << "\n";
}




void PACPHeaderSmall::initHashChain(pktCmn_t* packet, uint8_t* secret, uint16_t sl) {
    if (!packet || !packet->sighdr || !(packet->ptype & PACKET_TYPE_DATA_SHDR)) {
        MYTHROW1("Error with parameters");
    }

    int size = sl + HEADER_SEQUENCE_SIZE + 2 * sizeof(in6_addr) + sizeof(uint16_t);
    uint8_t*	buf1 = new uint8_t[size];

    if (!buf1) {
        MYTHROW1("PACPHeaderSmall::initHashChain: Could not allocate memory");
    }

    uint32_t	index = 0;
    uint8_t	buf2[CRYPTO_HASH_SIZE];
    uint16_t sequence = 0;
    uint16_t dataLen = IPV6Packet::getPLength(packet);
    chargingHeaderSmall_t* ch = (chargingHeaderSmall_t*) packet->sighdr;
    memcpy(buf1, &dataLen, sizeof(uint16_t));
    index += sizeof(uint16_t);
    sequence = getSequence(packet);
    memcpy(buf1 + index, &sequence, HEADER_SEQUENCE_SIZE);
    index += HEADER_SEQUENCE_SIZE;
    memcpy(buf1 + index, secret, sl);
    index += sl;
    memcpy(buf1 + index, IPV6Packet::getSrc(packet), sizeof(in6_addr));
    index += sizeof(in6_addr);
    memcpy(buf1 + index, IPV6Packet::getDst(packet), sizeof(in6_addr));
    index += sizeof(in6_addr);
    MD5(buf1, size, buf2);
    delete [] buf1;
    memcpy(ch->hashChain, buf2, HEADER_HASHCHAIN_SIZE);
}

uint8_t* PACPHeaderSmall::getHashChain(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !(packet->ptype & PACKET_TYPE_DATA_SHDR)) {
        MYTHROW1("Error with parameters");
    }

    chargingHeaderSmall_t* ch = (chargingHeaderSmall_t*) packet->sighdr;
    return ch->hashChain;
}



uint16_t	PACPHeaderSmall::getSequence(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !(packet->ptype & PACKET_TYPE_DATA_SHDR)) {
        MYTHROW1("Error with parameters");
    }

    chargingHeaderSmall_t* ch = (chargingHeaderSmall_t*) packet->sighdr;
    uint16_t sequence = 0;
    memcpy(&sequence, ch->sequence, sizeof(uint16_t));
    return ntohs(sequence);
}



uint16_t	PACPHeaderSmall::getFullLength(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !(packet->ptype & PACKET_TYPE_DATA_SHDR)) {
        MYTHROW1("Error with parameters");
    }

    return getLength(packet) + getPadding(packet);
}

uint16_t	PACPHeaderSmall::getLength(pktCmn_t* packet) {
    if (!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_SHDR) {
        MYTHROW1("Error with parameters");
    }

    chargingHeaderSmall_t* ch = (chargingHeaderSmall_t*) packet->sighdr;
    uint16_t size = 4 + 1 + 2 + CRYPTO_HASH_SIZE + sizeof(uint8_t);

    if(ch->macLength) {
        size += *ch->macLength;
    }

    return size;
}



void PACPHeaderSmall::sign(pktCmn_t* packet, kmKey_t* key) {
    if(!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_SHDR || !key || !key->ec) {
        MYTHROW1("Error with parameters");
    }

    chargingHeaderSmall_t* ch = (chargingHeaderSmall_t*) packet->sighdr;
    unsigned char*	buf = new unsigned char[200];
    unsigned char* buffi = buf;
    memcpy(buffi, IPV6Packet::getSrc(packet), sizeof(in6_addr));
    buffi += sizeof(in6_addr);
    memcpy(buffi, IPV6Packet::getDst(packet), sizeof(in6_addr));
    buffi += sizeof(in6_addr);
    memcpy(buffi, ch->sequence, sizeof(uint16_t));
    buffi += sizeof(uint16_t);
    uint16_t	len = 2 * sizeof(in6_addr) + sizeof(uint16_t);
    ch->mac = new uint8_t[200];
    uint16_t	maclen = 200;
    KeyManager::signECDSA(key, ch->mac, &maclen, buf, len);
    *ch->macLength = maclen;
    *ch->headerLength = (getFullLength(packet) - 4) / 8 ;
    *ch->dataLength = getFullLength(packet) - 4;
    delete [] buf;
}

bool PACPHeaderSmall::verifySig(pktCmn_t* packet, kmKey_t* key) {
    if(!packet || !packet->sighdr || !packet->ptype & PACKET_TYPE_DATA_SHDR || !key || !key->ec) {
        MYTHROW1("Error with parameters");
    }

    chargingHeaderSmall_t* ch = (chargingHeaderSmall_t*) packet->sighdr;
    unsigned char*	buf = new unsigned char[200];
    unsigned char* buffi = buf;
    memcpy(buffi, IPV6Packet::getSrc(packet), sizeof(in6_addr));
    buffi += sizeof(in6_addr);
    memcpy(buffi, IPV6Packet::getDst(packet), sizeof(in6_addr));
    buffi += sizeof(in6_addr);
    memcpy(buffi, ch->sequence, sizeof(uint16_t));
    buffi += sizeof(uint16_t);
    uint16_t	len = 2 * sizeof(in6_addr) + sizeof(uint16_t);
    int ret = KeyManager::verifyECDSA(key, ch->mac, *ch->macLength, buf, len);
    delete [] buf;
    return ret;
}



/*

	TCPPacket


*/
void TCPPacket::setup(pktCmn_t* packet, uint8_t* data) {
    if (!packet || !data) {
        MYTHROW1("Error with parameters");
    }

    packet->ptype |= PACKET_TYPE_DATA;
    packet->ptype |= PACKET_TYPE_DATA_TCP;
    packet->status = PACKET_DATA_ORIGINAL;
    packet->tcphdr = (tcphdr*) data;
}

void TCPPacket::updateMSS(pktCmn_t* packet) {
    if (!packet || !packet->tcphdr || !packet->sighdr ) {
        MYTHROW1("Error with parameters");
    }

    //Found a TCP Header
    tcphdr*	tcp = packet->tcphdr;
    uint16_t	extLen = 0;

    if (packet->ptype & PACKET_TYPE_DATA_FHDR) {
        extLen = PACPHeaderFull::getFullLength(packet);

    } else if (packet->ptype & PACKET_TYPE_DATA_SHDR) {
        extLen = PACPHeaderSmall::getFullLength(packet);

    } else {
        return ;
    }

    uint8_t* payload = (uint8_t*) tcp;

    if (tcp->syn) {
        //SYN Packet. Adjust MSS
        payload += 22;
        uint16_t	mss = ntohs(*((uint16_t*) payload));
        uint16_t nmss = mss - extLen;
        logger << LOG_L(LOG_DEBUG) << "Packet: Adjusting MSS Old=" << mss << " New=" << nmss << " ExtLen=" << extLen << "(" << hex << (extLen - 1 ) / 8 << dec << ")\n";
        nmss = htons(nmss);
        memcpy(payload, &nmss, sizeof(uint16_t));
        uint16_t	check = ntohs(tcp->check);
        logger << LOG_L(LOG_DEBUG) << "Packet: Adjusting TCPCheck Old=" << hex << check << " New=" << check + extLen << dec << "\n";
        check += extLen;
        tcp->check = htons(check);
    }
}



/*
	PACPReport

*/



void PACPReport::setup(pktCmn_t* p, uint8_t* data) {
    if (!p || !data) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* s = new pktReport_t;
    memset(s, 0, sizeof(pktReport_t));
    s->buffer = data;
    p->sighdr = (uint8_t*) s;
    p->ptype |= PACKET_TYPE_SIG_REP;
    p->alloc |= PKTCMN_ALLOC_SIG;
    unpack(p);
}

pktCmn_t* PACPReport::alloc() {
    pktCmn_t* p = Packet::alloc();
    pktReport_t* rep = new pktReport_t;
    p->ptype |= PACKET_TYPE_SIG_REP;
    p->alloc |= PKTCMN_ALLOC_SIG;
    memset(rep, 0, sizeof(pktReport_t));
    rep->buffer = new uint8_t[1500];
    memset(rep->buffer, 0, 1500);
    rep->alloc = PKTREPORT_ALLOC_BUFFER;
    rep->dataLength = PKTREPORT_SIZE;
    p->sighdr = (uint8_t*) rep;
    rep->buffer[0] = PACKET_SIG_REPORT;
    unpack(p);
    return p;
}


void PACPReport::free(pktCmn_t* p) {
    if(!p || !p->ptype & PACKET_TYPE_SIG_REP || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* r = (pktReport_t*) p->sighdr;

    if(r->alloc & PKTREPORT_ALLOC_BUFFER) {
        delete [] r->buffer;
    }

    if(p->alloc & PKTCMN_ALLOC_SIG) {
        delete r;
    }

    p->sighdr = NULL;
}



uint8_t* PACPReport::getBuffer(pktCmn_t* p, uint16_t* bl) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_REP) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* s = (pktReport_t*) p->sighdr;
    *bl = s->dataLength;
    return s->buffer;
}


void PACPReport::unpack(pktCmn_t* p) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_REP)) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* rep = (pktReport_t*) p->sighdr;
    uint8_t* buffi = rep->buffer;
    rep->type = buffi;
    buffi++;
    rep->reportID = (uint64_t*) buffi;
    buffi += sizeof(uint64_t);
    rep->sessionSrc = (in6_addr*) buffi;
    buffi += sizeof(in6_addr);
    rep->sessionDst = (in6_addr*) buffi;
    buffi += sizeof(in6_addr);
    rep->nroutes = buffi;
    buffi += sizeof(uint8_t);
    rep->lastRoute = rep->pointer = buffi;
    int i;

    for(i = 0; i < *rep->nroutes; i++) {
        rep->lastRoute = buffi;
        uint32_t	nproofs = buffi[sizeof(uint32_t)];
        uint32_t proofSize = 0;

        if(buffi[0]  == 0) {
            proofSize  = REPORT_PROOF_SIZE_SMALL;
            int32_t sum = sizeof(uint32_t) + sizeof(uint8_t) + (nproofs * proofSize);	 //Small proofs
            buffi += sum;

        } else {
            buffi += sizeof(uint32_t) + sizeof(uint8_t) + (nproofs * REPORT_PROOF_SIZE);	 //FULL proofs
        }
    }

    rep->endPointer = rep->pointer = rep->macLength = buffi;
    rep->mac = rep->macLength + sizeof(uint8_t);
    rep->dataLength = rep->macLength - rep->buffer + *((uint8_t*) rep->macLength) + sizeof(uint8_t);
}

int16_t	PACPReport::addRoute(pktCmn_t* packet, uint32_t rhash) {
    if (!packet || !packet->sighdr || !(packet->ptype & PACKET_TYPE_SIG_REP)) {
        MYTHROW1("Error with parameters");
    }

    /*
        Must have space for one route and one full proof... at least..
    */
    pktReport_t*	rep = (pktReport_t*) packet->sighdr;

    if (rep->dataLength + REPORT_ROUTE_SIZE + REPORT_PROOF_SIZE > REPORT_MAX_SIZE) {
        return 0;
    }

    rep->lastRoute = rep->pointer;
    memcpy(rep->lastRoute, &rhash, sizeof(uint32_t));
    rep->lastRoute[sizeof(uint32_t)] = 0;	//nproofs
    rep->pointer += sizeof(uint32_t) + sizeof(uint8_t);
    rep->dataLength += sizeof(uint32_t) + sizeof(uint8_t);
    rep->buffer[sizeof(uint8_t) + sizeof(uint64_t) + sizeof(in6_addr) + sizeof(in6_addr)]++;
    rep->macLength = rep->pointer;
    *rep->macLength = 0;
    rep->mac = rep->pointer + sizeof(uint8_t);
    return REPORT_MAX_SIZE - rep->dataLength;
}


int16_t	PACPReport::addProof(pktCmn_t* packet, uint8_t type, uint8_t index, uint16_t packetLength, uint16_t sequence, uint8_t* routeID, uint8_t* hashChain) {
    if (!packet || !routeID || !hashChain || !(packet->ptype & PACKET_TYPE_SIG_REP) || ! packet->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* rep = (pktReport_t*) packet->sighdr;

    if (type == HEADER_TYPE_SMALL) {
        if (rep->dataLength + REPORT_PROOF_SIZE_SMALL > REPORT_MAX_SIZE) {
            return 0;
        }

        uint16_t aux = htons(packetLength);
        memcpy(rep->pointer, &aux, sizeof(uint16_t));
        rep->pointer += sizeof(uint16_t);
        aux = htons(sequence);
        memcpy(rep->pointer, &aux, sizeof(uint16_t));
        rep->pointer += sizeof(uint16_t);
        memcpy(rep->pointer, hashChain, sizeof(in6_addr));
        rep->pointer += sizeof(in6_addr);
        rep->dataLength += REPORT_PROOF_SIZE_SMALL;

    } else {
        if (rep->dataLength + REPORT_PROOF_SIZE > REPORT_MAX_SIZE) {
            return 0;
        }

        rep->pointer[0] = index;
        rep->pointer += sizeof(uint8_t);
        uint16_t aux = htons(packetLength);
        memcpy(rep->pointer, &aux, sizeof(uint16_t));
        rep->pointer += sizeof(uint16_t);
        aux = htons(sequence);
        memcpy(rep->pointer, &aux, sizeof(uint16_t));
        rep->pointer += sizeof(uint16_t);
        memcpy(rep->pointer, routeID, sizeof(in6_addr));
        rep->pointer += sizeof(in6_addr);
        memcpy(rep->pointer, hashChain, sizeof(in6_addr));
        rep->pointer += sizeof(in6_addr);
        rep->dataLength += REPORT_PROOF_SIZE;
    }

    rep->lastRoute[sizeof(uint32_t)]++;
    rep->macLength = rep->pointer;
    *rep->macLength = 0;
    rep->mac = rep->pointer + sizeof(uint8_t);
    return REPORT_MAX_SIZE - rep->dataLength;
}



void PACPReport::setReportID(pktCmn_t* p, uint64_t id) {
    if (!p || !(p->ptype & PACKET_TYPE_SIG_REP) || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* rep = (pktReport_t*) p->sighdr;
    memcpy(rep->reportID, &id, sizeof(uint64_t));
}



uint64_t	PACPReport::getReportID(pktCmn_t* p) {
    if (!p || !(p->ptype & PACKET_TYPE_SIG_REP) || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* rep = (pktReport_t*) p->sighdr;
//	fprintf(stderr,"\n\nGet REPORTID: %llu\n", *rep->reportID);
    return *rep->reportID;
}



void PACPReport::setSessionSrc(pktCmn_t* p, in6_addr* address) {
    if (!p || !(p->ptype & PACKET_TYPE_SIG_REP) || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* rep = (pktReport_t*) p->sighdr;
    memcpy(rep->sessionSrc, address, sizeof(in6_addr));
}

in6_addr* PACPReport::getSessionSrc(pktCmn_t* p) {
    if (!p || !(p->ptype & PACKET_TYPE_SIG_REP) || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* rep = (pktReport_t*) p->sighdr;
    return rep->sessionSrc;
}


void PACPReport::setSessionDst(pktCmn_t* p, in6_addr* address) {
    if (!p || !(p->ptype & PACKET_TYPE_SIG_REP) || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* rep = (pktReport_t*) p->sighdr;
    memcpy(rep->sessionDst, address, sizeof(in6_addr));
}

in6_addr* PACPReport::getSessionDst(pktCmn_t* p) {
    if (!p || !(p->ptype & PACKET_TYPE_SIG_REP) || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* rep = (pktReport_t*) p->sighdr;
    return rep->sessionDst;
}

uint8_t PACPReport::getNumberRoutes(pktCmn_t* p) {
    if (!p || !(p->ptype & PACKET_TYPE_SIG_REP) || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* rep = (pktReport_t*) p->sighdr;
    return *rep->nroutes;
}

uint8_t* PACPReport::getDataStart(pktCmn_t* p) {
    if (!p || !(p->ptype & PACKET_TYPE_SIG_REP) || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t* rep = (pktReport_t*) p->sighdr;
    return rep->nroutes + sizeof(uint8_t);
}


void PACPReport::sign(pktCmn_t* p, kmKey_t* key) {
    if(!p || !key || !key->ec || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_REP) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t*	rep = (pktReport_t*) p->sighdr;
    uint16_t	blen = rep->macLength - rep->buffer;
    uint16_t	siglen = 200;
    KeyManager::signECDSA(key, rep->mac, &siglen, rep->buffer, blen);
    *rep->macLength = siglen;
    rep->dataLength += siglen;
}


bool PACPReport::verifySig(pktCmn_t* p, kmKey_t* key) {
    if(!p || !key || !key->ec || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_REP)) {
        MYTHROW1("Error with parameters");
    }

    pktReport_t*	rep = (pktReport_t*) p->sighdr;
    uint32_t	blen = rep->macLength - rep->buffer;
    uint16_t	siglen = *rep->macLength;
    fprintf(stderr, "BLEN: %u, DataLength: %u, SIGLEN: %u\n", blen, rep->dataLength, siglen);

    if(siglen) {
        return KeyManager::verifyECDSA(key, rep->mac, siglen, rep->buffer, blen);

    } else {
        return false;
    }
}

/*

	PACPSessionInit class

*/

void PACPSessionInit::setup(pktCmn_t* p, uint8_t* data) {
    if (!p || !data) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t* s = new pktSessionInit_t;
    memset(s, 0, sizeof(pktSessionInit_t));
    s->buffer = data;
    p->alloc = PKTCMN_ALLOC_SIG;
    p->sighdr = (uint8_t*) s;
    p->ptype |= PACKET_TYPE_SIG_SINIT;

    if(data[0] == PACKET_SIG_SESSION_INIT_CRYPTO) {
        p->ptype |= PACKET_TYPE_CRYPTO;
    }

    unpack(p);
}


pktCmn_t* PACPSessionInit::alloc() {
    pktCmn_t* p = Packet::alloc();
    pktSessionInit_t* s = new pktSessionInit_t;
    p->ptype |= PACKET_TYPE_SIG;
    p->ptype |= PACKET_TYPE_SIG_SINIT;
    p->alloc |= PKTCMN_ALLOC_SIG;
    p->sighdr = (uint8_t*) s;
    memset(s, 0, sizeof(pktSessionInit_t));
    s->alloc = 0;
    s->buffer = new (uint8_t)[PACKET_DEFAULT_PAYLOAD_SIZE];
    memset(s->buffer, 0, PACKET_DEFAULT_PAYLOAD_SIZE);
    s->alloc = PKTSINIT_ALLOC_BUFFER;
    s->buffer[0] = PACKET_SIG_SESSION_INIT;
    unpack(p);
    return p;
}


void PACPSessionInit::free(pktCmn_t* p) {
    if (!p || !(p->ptype & PACKET_TYPE_SIG_SINIT)) {
        MYTHROW1("Error with parameters");
    }

    p->ptype &= ~PACKET_TYPE_SIG_SINIT;
    p->ptype &= ~PACKET_TYPE_SIG;

    if (p->alloc & PKTCMN_ALLOC_SIG && p->sighdr) {
        pktSessionInit_t* s = (pktSessionInit_t*) p->sighdr;

        if (s->address && s->alloc & PKTSINIT_ALLOC_ADDRESS) {
            delete [] s->address;
        }

        if (s->secretLength && s->alloc & PKTSINIT_ALLOC_SECRET) {
            delete [] s->secretLength;
        }

        if (s->uidLength && s->alloc & PKTSINIT_ALLOC_UID) {
            delete [] s->uidLength;
        }

        if (s->pukLength && s->alloc & PKTSINIT_ALLOC_PUK) {
            delete [] s->pukLength;
        }

        if (s->macLength && s->alloc & PKTSINIT_ALLOC_MAC) {
            delete [] s->macLength;
        }

        if (s->buffer && s->alloc & PKTSINIT_ALLOC_BUFFER) {
            delete [] s->buffer;
        }

        delete s;
        p->sighdr = NULL;
    }

    p->alloc &= ~PKTCMN_ALLOC_SIG;
}


uint8_t*	PACPSessionInit::getBuffer(pktCmn_t* p, uint16_t* bl) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_SINIT) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t* s = (pktSessionInit_t*) p->sighdr;
    *bl = s->dataLength;
    return s->buffer;
}




void PACPSessionInit::pack(pktCmn_t* p) {
    if (!p || !(p->ptype & PACKET_TYPE_SIG_SINIT) || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t* s = (pktSessionInit_t*) p->sighdr;
    s->buffer = new uint8_t[PACKET_DEFAULT_PAYLOAD_SIZE];
    uint8_t* buffi = s->buffer;
    buffi[0] = PACKET_SIG_SESSION_INIT;
    buffi++;
    memcpy(buffi, s->address, sizeof(in6_addr));
    buffi += sizeof(in6_addr);
    memcpy(buffi, s->uidLength, sizeof(uint8_t));
    buffi += sizeof(uint8_t);
    memcpy(buffi, s->uid, *s->uidLength);
    buffi += *s->uidLength;
    memcpy(buffi, s->secretLength, sizeof(uint8_t));
    buffi += sizeof(uint8_t);
    memcpy(buffi, s->secret, *s->secretLength);
    buffi += *s->secretLength;
    memcpy(buffi, s->pukLength, sizeof(uint16_t));
    buffi += sizeof(uint16_t);
    memcpy(buffi, s->puk, *s->pukLength);
    buffi += *s->pukLength;
    memcpy(buffi, s->macLength, sizeof(uint8_t));
    buffi += sizeof(uint8_t);
    memcpy(buffi, s->mac, *s->macLength);
    buffi += *s->macLength;
    s->dataLength = sizeof(uint8_t) * (1 + 3) + sizeof(in6_addr) + sizeof(uint16_t) + *s->secretLength + *s->uidLength + *s->pukLength + *s->macLength;
    p->psize = s->dataLength;
}

void PACPSessionInit::unpack(pktCmn_t* p) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t* s = (pktSessionInit_t*) p->sighdr;

    if(s->buffer[0] == PACKET_SIG_SESSION_INIT_CRYPTO) {
        logger << LOG_L(LOG_DEBUG) << "PACPSessionInit::unpack: Packet is ciphered!\n";
        s->code = s->buffer;
        uint8_t* buffi = s->buffer;
        buffi += sizeof(uint8_t);
        s->cipherLength = ((uint16_t*) buffi);
        buffi += sizeof(uint16_t);
        s->cipher =  buffi;
        buffi += *s->cipherLength;
        s->rsaLength = (uint16_t*) buffi;
        buffi += sizeof(uint16_t);
        s->rsa = buffi;

    } else {
        logger << LOG_L(LOG_DEBUG) << "PACPSessionInit::unpack: Packet is NOT ciphered!\n";
        uint8_t* buffi = s->buffer;
        s->code = buffi;
        buffi += sizeof(uint8_t);
        s->address = (in6_addr*) buffi;
        buffi += sizeof(in6_addr);
        s->uidLength = buffi;
        buffi += sizeof(uint8_t);
        s->uid = buffi;
        buffi += *s->uidLength;
//		fprintf(stderr,"unpack: UID Length :%u\n",*s->uidLength);
        s->secretLength = buffi;
        buffi += sizeof(uint8_t);
        s->secret = buffi;
        buffi += *s->secretLength;
//		fprintf(stderr,"unpack: Secret Length :%u\n",*s->secretLength);
        s->pukLength = (uint16_t*) buffi;
//		fprintf(stderr,"unpack: Puk Length :%u\n",*s->pukLength);
        buffi += sizeof(uint16_t);
        s->puk = buffi;
        buffi += *s->pukLength;
        s->macLength = buffi;
        //	fprintf(stderr,"unpack: MAC Length :%u\n",*s->macLength);
        buffi++;
        s->mac = buffi;
        s->dataLength = buffi - s->buffer;
//		fprintf(stderr,"unpack: Data Length :%u\n",s->dataLength);
    }
};


void PACPSessionInit::sign(pktCmn_t* p, kmKey_t* key) {
    if(!p || !key || !key->ec || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_SINIT) {
        MYTHROW1("Error with parameters");
    }

    unpack(p);
    pktSessionInit_t*	sinit = (pktSessionInit_t*) p->sighdr;
    uint16_t	blen = sinit->macLength - sinit->buffer - sizeof(uint8_t);
    uint16_t	siglen = 256;
    KeyManager::signECDSA(key, sinit->mac, &siglen, sinit->buffer, blen);
    *sinit->macLength = siglen;
}

kmKey_t* PACPSessionInit::getKey(pktCmn_t* p) {
    if(!p ||  !p->sighdr || !p->ptype & PACKET_TYPE_SIG_SINIT) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t*	sinit = (pktSessionInit_t*) p->sighdr;

    if(!sinit->pukLength) {
        logger << LOG_L(LOG_ERROR) << "PACPSessionInit::getKey: No PUK provided!\n";
    }

    kmKey_t* key;

    if(sinit->key) {
        key = sinit->key;

    } else {
        key = new kmKey_t;
        memset(key, 0, sizeof(kmKey_t));
    }

//	fprintf(stderr,"PACPSessionInit::Puk Length: %u\n",*sinit->pukLength);

    if(!key->ec) {
        KeyManager::loadECbuf(sinit->puk, key);
    }

    return key;
}

in6_addr* PACPSessionInit::getAddress(pktCmn_t* p) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT)) {
        MYTHROW1("Error with parameters");
    }

    return ((pktSessionInit_t*) p->sighdr)->address;
}

void PACPSessionInit::setAddress(pktCmn_t* p, in6_addr* address) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t* s = (pktSessionInit_t*) p->sighdr;
    s->address = new in6_addr;
    memcpy(s->address, address, sizeof(in6_addr));
    s->alloc |= PKTSINIT_ALLOC_ADDRESS;
}


uint8_t* PACPSessionInit::getSecret(pktCmn_t* p, uint8_t* sl) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT)) {
        MYTHROW1("Error with parameters");
    }

    *sl = *((pktSessionInit_t*) p->sighdr)->secretLength;
    return ((pktSessionInit_t*) p->sighdr)->secret;
}


void PACPSessionInit::setSecret(pktCmn_t* p, uint8_t* secret, uint8_t secretl) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t* s = (pktSessionInit_t*) p->sighdr;
    s->secretLength = new uint8_t[secretl + sizeof(uint8_t)];
    s->secret =  s->secretLength + sizeof(uint8_t);
    *s->secretLength = secretl;
    memcpy(s->secret, secret, secretl);
    s->alloc |= PKTSINIT_ALLOC_SECRET;
}


uint8_t* PACPSessionInit::getUID(pktCmn_t* p, uint8_t* uidl) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t* s = (pktSessionInit_t*) p->sighdr;
    *uidl = *s->uidLength;
    return s->uid;
}


void PACPSessionInit::setUID(pktCmn_t* p, uint8_t* uid, uint8_t uidl) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t* s = (pktSessionInit_t*) p->sighdr;
    s->uidLength  = new uint8_t[uidl + sizeof(uint8_t)];
    *s->uidLength = uidl;
    s->uid = s->uidLength + sizeof(uint8_t);
    memcpy(s->uid, uid, uidl);
    s->alloc |= PKTSINIT_ALLOC_UID;
}


kmKey_t* PACPSessionInit::getPUK(pktCmn_t* p, kmKey_t* t) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t* s = (pktSessionInit_t*) p->sighdr;

    if(s->pukLength == 0) {
        return NULL;
    }

    kmKey_t* key;

    if(t) {
        key = t;

        if(key->ec) {
            EC_KEY_free(key->ec);
            key->ec = NULL;
        }

        if(key->ec_kinv) {
            BN_free(key->ec_kinv);
            key->ec_kinv = NULL;
        }

        if(key->ec_rp) {
            BN_free(key->ec_rp);
            key->ec_rp = NULL;
        }

    } else {
        key = NULL;
    }

    return KeyManager::loadECbuf(s->puk, key);
}


void	PACPSessionInit::setPUK(pktCmn_t* p, kmKey_t* puk) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t* s = (pktSessionInit_t*) p->sighdr;
    s->pukLength = new uint16_t[512];
    *s->pukLength = 1000;
    s->puk = ((uint8_t*) s->pukLength) + sizeof(uint16_t);
    int32_t pl = KeyManager::dumpECbuf(puk, s->puk);
    *s->pukLength = pl;
//	fprintf(stderr,"PukLength: %u\n",pl);
}



bool PACPSessionInit::verifySig(pktCmn_t* p, kmKey_t* key) {
    if(!p || !key || !key->ec || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_SINIT) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t*	sinit = (pktSessionInit_t*) p->sighdr;
    uint32_t	blen = sinit->macLength - sinit->buffer - sizeof(uint8_t);
    uint16_t	siglen = *sinit->macLength;
    return KeyManager::verifyECDSA(key, sinit->mac, siglen, sinit->buffer, blen);
}


void PACPSessionInit::decipherSimRSA(pktCmn_t* p, kmKey_t* rsa) {
    if(!p || !rsa || !rsa->rsa || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_SINIT || !p->ptype & PACKET_TYPE_CRYPTO) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t* sinit = (pktSessionInit_t*) p->sighdr;

    if(sinit->buffer[0] != PACKET_SIG_SESSION_INIT_CRYPTO) {
        MYTHROW1("Invalid Packet");
    }

    uint8_t*	buffi = sinit->buffer + sizeof(uint8_t);
    uint16_t	len = *((uint16_t*) buffi);
    //First we must get the Simetric Key
    buffi += sizeof(uint16_t) + len;
    len = *((uint16_t*) buffi);
    buffi += sizeof(uint16_t);
    uint8_t	sim[1000];
    uint16_t	simlen = 1000;
    KeyManager::decipherRSAPrivate(rsa, sim, &simlen, buffi, len);
    kmKey_t* simKey = KeyManager::generateSim(simlen, sim);
    buffi = sinit->buffer + sizeof(uint8_t);
    len = *((uint16_t*) buffi);
    buffi += sizeof(uint16_t);
    uint8_t* aux = new uint8_t[len + sizeof(uint8_t)];
    uint16_t auxlen = len + sizeof(uint8_t);
    memset(aux, 0, len + sizeof(uint8_t));
    KeyManager::decipher(simKey, aux + sizeof(uint8_t), &auxlen, buffi, len);

    if(sinit->alloc & PKTSINIT_ALLOC_BUFFER) {
        delete [] sinit->buffer;
    }

    aux[0] = PACKET_SIG_SESSION_INIT;
    p->ptype &= ~PACKET_TYPE_CRYPTO;
    sinit->buffer = aux;
    sinit->dataLength = auxlen + sizeof(uint8_t);
    sinit->key = simKey;
    unpack(p);
}


void PACPSessionInit::cipherSimRSA(pktCmn_t* p, kmKey_t* sim, kmKey_t* rsa) {
    if(!p || !sim || !sim->sim || !sim->rc4 || !rsa || !rsa->rsa || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_SINIT) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInit_t*	sinit = (pktSessionInit_t*) p->sighdr;
    uint16_t dataLength = sinit->dataLength	+ 1000;
    uint8_t*	buf = new uint8_t[dataLength	+	1000];
    buf[0] = PACKET_SIG_SESSION_INIT_CRYPTO;
    uint8_t*	buffi = buf + sizeof(uint8_t);
    KeyManager::cipher(sim, buffi + sizeof(uint16_t), &dataLength, sinit->buffer + sizeof(uint8_t), sinit->dataLength - sizeof(uint8_t));
    memcpy(buffi, &dataLength, sizeof(uint16_t));
    buffi += dataLength + sizeof(uint16_t);
    sinit->dataLength = sizeof(uint8_t) + sizeof(uint16_t) + dataLength;
    dataLength = 1000;
    KeyManager::cipherRSAPublic(rsa, buffi + sizeof(uint16_t), &dataLength, sim->sim, sim->simlen);
    memcpy(buffi, &dataLength, sizeof(uint16_t));
//	fprintf(stderr,"RSA MessageCipher Length : %u\n", dataLength);
    sinit->dataLength += dataLength + sizeof(uint16_t);

    if (sinit->alloc & PKTSINIT_ALLOC_BUFFER) {
        delete [] sinit->buffer;
    }

    sinit->buffer = buf;
    sinit->alloc |= PKTSINIT_ALLOC_BUFFER;
}


/*

	PACPReportResponse

*/

void PACPReportResponse::setup(pktCmn_t* p, uint8_t* data) {
    if (!p || !data) {
        MYTHROW1("Error with parameters");
    }

    pktReportResponse_t* s = new pktReportResponse_t;
    memset(s, 0, sizeof(pktReportResponse_t));
    s->buffer = data;
    p->sighdr = (uint8_t*) s;
    p->ptype |= PACKET_TYPE_SIG_REP_RESP;
    p->alloc = PKTCMN_ALLOC_SIG;
    unpack(p);
}

pktCmn_t* PACPReportResponse::alloc() {
    pktCmn_t* p = Packet::alloc();
    pktReportResponse_t*	r = new pktReportResponse_t;
    memset(r, 0, sizeof(pktReportResponse_t));
    p->sighdr = (uint8_t*) r;
    r->buffer = new uint8_t[PACKET_DEFAULT_PAYLOAD_SIZE];
    memset(r->buffer, 0, PACKET_DEFAULT_PAYLOAD_SIZE);
    r->alloc = PKTREPORTRESPONSE_ALLOC_BUFFER;
    p->ptype |= PACKET_TYPE_SIG_REP_RESP;
    p->alloc |= PKTCMN_ALLOC_SIG;
    unpack(p);
    *r->type = PACKET_SIG_REPORT_RESP;
    return p;
}


void PACPReportResponse::free(pktCmn_t* p) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_REP_RESP)) {
        MYTHROW1("Error with parameters");
    }

    pktReportResponse_t* r = (pktReportResponse_t*) p->sighdr;

    if (r->alloc & PKTREPORTRESPONSE_ALLOC_BUFFER) {
        delete [] r->buffer;
    }

    if (p->alloc & PKTCMN_ALLOC_SIG) {
        delete r;
    }

    p->alloc &= ~PKTCMN_ALLOC_SIG;
    p->sighdr = NULL;
    p->ptype &= ~PACKET_TYPE_SIG_REP_RESP;
}


void PACPReportResponse::pack(pktCmn_t* p) {
}


void PACPReportResponse::unpack(pktCmn_t* p) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_REP_RESP)) {
        MYTHROW1("Error with parameters");
    }

    pktReportResponse_t* r = (pktReportResponse_t*) p->sighdr;
    uint8_t* buffi = r->buffer;
    r->type = buffi;
    buffi += sizeof(uint8_t);
    r->result = buffi;
    buffi += sizeof(uint8_t);
    r->reportID = (uint64_t*) buffi;
    buffi += sizeof(uint64_t);
    r->macLength = buffi;
    buffi += sizeof(uint8_t);
    r->mac = buffi;
    r->dataLength = r->mac - r->buffer + *r->macLength;
}


void PACPReportResponse::sign(pktCmn_t* p, kmKey_t* key) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_REP_RESP)) {
        MYTHROW1("Error with parameters");
    }

    pktReportResponse_t* r = (pktReportResponse_t*) p->sighdr;
    uint8_t	md[16];
    uint16_t	maclen = 100;
    MD5(r->buffer, r->dataLength - 1, md);
    KeyManager::signECDSA(key, r->mac, &maclen, md, 16);
    *r->macLength = 	maclen;
    r->dataLength += maclen;
}

bool PACPReportResponse::verifySig(pktCmn_t* p, kmKey_t* key) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_REP_RESP)) {
        MYTHROW1("Error with parameters");
    }

    pktReportResponse_t* r = (pktReportResponse_t*) p->sighdr;
    return KeyManager::verifyECDSA(key, r->mac, *r->macLength, r->buffer, r->dataLength - 1 - *r->macLength);
}

uint64_t	PACPReportResponse::getReportID(pktCmn_t* p) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_REP_RESP)) {
        MYTHROW1("Error with parameters");
    }

    uint64_t	ret = 0;
    pktReportResponse_t* r = (pktReportResponse_t*) p->sighdr;
    memcpy(&ret, r->reportID, sizeof(uint64_t));
    return ret;
}


void PACPReportResponse::setReportID(pktCmn_t* p, uint64_t	rid) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_REP_RESP)) {
        MYTHROW1("Error with parameters");
    }

    pktReportResponse_t* r = (pktReportResponse_t*) p->sighdr;
    memcpy(r->reportID, &rid, sizeof(uint64_t));
}


uint8_t* PACPReportResponse::getBuffer(pktCmn_t* p, uint16_t* len) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_REP_RESP)) {
        MYTHROW1("Error with parameters");
    }

    pktReportResponse_t* r = (pktReportResponse_t*) p->sighdr;
    *len = r->dataLength;
    return r->buffer;
}


/*

	PACPSessionInitResponse

*/

void PACPSessionInitResponse::setup(pktCmn_t* p, uint8_t* data) {
    if (!p || !data) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t* s = new pktSessionInitResponse_t;
    memset(s, 0, sizeof(pktSessionInitResponse_t));
    s->buffer = data;
    p->sighdr = (uint8_t*) s;
    p->ptype |= PACKET_TYPE_SIG_SINIT_RESP;
    p->alloc = PKTCMN_ALLOC_SIG;

    if(data[0] == PACKET_SIG_SESSION_INIT_RESP_CRYPTO) {
        p->ptype |= PACKET_TYPE_CRYPTO;
    }

    unpack(p);
}


pktCmn_t* PACPSessionInitResponse::alloc() {
    pktCmn_t* p = Packet::alloc();
    pktSessionInitResponse_t* s = new pktSessionInitResponse_t;
    p->ptype |= PACKET_TYPE_SIG;
    p->ptype |= PACKET_TYPE_SIG_SINIT_RESP;
    p->alloc |= PKTCMN_ALLOC_SIG;
    p->sighdr = (uint8_t*) s;
    memset(s, 0, sizeof(pktSessionInitResponse_t));
    s->buffer = new uint8_t[PACKET_DEFAULT_PAYLOAD_SIZE];
    memset(s->buffer, 0, PACKET_DEFAULT_PAYLOAD_SIZE);
    s->alloc |= PKTSINITRESP_ALLOC_BUFFER;
    s->dataLength = sizeof(uint8_t) * 4;
    s->buffer[0] = PACKET_SIG_SESSION_INIT_RESP;
    unpack(p);
    return p;
}
/*
 	Free a pktSessionInitResponse_t* and member structures
 	Calls the base free function.
*/
void PACPSessionInitResponse::free(pktCmn_t* p) {
    if (!p || !(p->ptype & PACKET_TYPE_SIG_SINIT_RESP)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t* s = (pktSessionInitResponse_t*) p->sighdr;

    if (s->buffer && s->alloc & PKTSINITRESP_ALLOC_BUFFER) {
        delete [] s->buffer;
    }

    if (p->alloc & PKTCMN_ALLOC_SINIT_RESP) {
        delete [] ((pktSessionInitResponse_t*) p->sighdr);
    }

    p->sighdr = 0;
    p->alloc &= ~PKTCMN_ALLOC_SINIT_RESP;
}

/*
    Packs the current structure to the buffer.

*/
void PACPSessionInitResponse::pack(pktCmn_t* p) {
    if (!p || !(p->ptype & PACKET_TYPE_SIG_SINIT_RESP) || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t* s = (pktSessionInitResponse_t*) p->sighdr;
    p->psize  = s->dataLength;
    return;
    /*  NOT NECESSARY AS OPERATIONS ARE NOW INLINE


        s->buffer = new uint8_t[PACKET_DEFAULT_PAYLOAD_SIZE];

        uint8_t*	buffi = s->buffer;

        buffi[0] = PACKET_SIG_SESSION_INIT_RESP;

        buffi++;

        buffi[0] = *s->code;

        buffi++;

        memcpy(buffi, s->sharedSecretLength, sizeof(uint8_t));

        buffi += sizeof(uint8_t);

        memcpy(buffi, s->sharedSecret, *s->sharedSecretLength);

        buffi += *s->sharedSecretLength;

        //Copy MAC
        memcpy(buffi,s->macLength,sizeof(uint8_t));
        buffi+=sizeof(uint8_t);

        memcpy(buffi,s->mac,sizeof(uint8_t));
        buffi+=*s->macLength;

        p->psize = 4 * sizeof(uint8_t) + *s->sharedSecretLength + *s->macLength;

        s->dataLength = p->psize;
    */
}

/*
    Reads packet content from buffer into internal structures

*/
void PACPSessionInitResponse::unpack(pktCmn_t* p) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT_RESP)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t* s = (pktSessionInitResponse_t*) p->sighdr;
    uint8_t*  buffi = s->buffer;
    buffi++;

    if(p->ptype & PACKET_TYPE_CRYPTO) {
        s->cryptoLength = buffi;
        buffi += sizeof(uint16_t);
        s->crypto = buffi;
        buffi += *((uint16_t*) s->cryptoLength);
        s->macLength = buffi;
        buffi += sizeof(uint8_t);
        s->mac = buffi;
        s->dataLength = sizeof(uint8_t) * 2 + sizeof(uint16_t) + *((uint16_t*) s->cryptoLength) + *s->macLength;
        logger << LOG_L(LOG_DEBUG) << "SessionInitResponse is Ciphered!\n";

    } else {
        s->code = buffi;
        buffi += sizeof(uint8_t);
        s->sharedSecretLength = buffi;
        buffi += sizeof(uint8_t);
        s->sharedSecret = buffi;
        buffi += *s->sharedSecretLength;
        s->macLength = buffi;
        buffi += sizeof(uint8_t);
        s->mac = buffi;
        s->dataLength = sizeof(uint8_t) * 4 + *s->sharedSecret + *s->macLength;
    }
}

uint8_t*	PACPSessionInitResponse::getBuffer(pktCmn_t* p, uint16_t* bl) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_SINIT_RESP) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t* s = (pktSessionInitResponse_t*) p->sighdr;
    *bl = s->dataLength;
    return s->buffer;
}

/*
    Sets the code to be delivered
*/
void PACPSessionInitResponse::setCode(pktCmn_t* p, uint8_t c) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT_RESP)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t*	s = (pktSessionInitResponse_t*) p->sighdr;
    *s->code = c;
}

/*
    Gets the code in the packet
*/
uint8_t PACPSessionInitResponse::getCode(pktCmn_t* p) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT_RESP)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t*	s = (pktSessionInitResponse_t*) p->sighdr;
    return *s->code;
}


/*
    Sets the shared secret to be delivered
*/
void	PACPSessionInitResponse::setSharedSecret(pktCmn_t* p, uint8_t* ss, uint16_t ssl) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT_RESP)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t*	s = (pktSessionInitResponse_t*) p->sighdr;
    *s->sharedSecretLength = ssl;
    memcpy(s->sharedSecret, ss, ssl);
    s->macLength = s->sharedSecret + *s->sharedSecretLength;
    *s->macLength = 0;
    s->dataLength = 4 * sizeof(uint8_t) + *s->sharedSecretLength;
    s->mac = s->macLength + sizeof(uint8_t);
};


/*
 	Returns the shared secret
*/
uint8_t* PACPSessionInitResponse::getSharedSecret(pktCmn_t* p, uint16_t* ssl) {
    if (!p || !p->sighdr || !(p->ptype & PACKET_TYPE_SIG_SINIT_RESP)) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t*	s = (pktSessionInitResponse_t*) p->sighdr;
    *ssl = *s->sharedSecretLength;
    return s->sharedSecret;
};




void PACPSessionInitResponse::decipher(pktCmn_t* p, kmKey_t* key) {
    if(!p || !key || !key->rc4 || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_SINIT_RESP) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t* sinit = (pktSessionInitResponse_t*) p->sighdr;
    uint8_t* buf = new uint8_t[sinit->dataLength + 256];
    uint16_t bl = sinit->dataLength + 256;
    uint16_t dlen = 0;
    uint8_t* buffi = sinit->buffer + sizeof(uint8_t);
    memcpy(&dlen, buffi, sizeof(uint16_t));
    buffi += sizeof(uint16_t);
    KeyManager::decipher(key, buf, &bl, buffi, dlen);
    buffi += bl;
    //Copy deciphered data to correct position
    memcpy(sinit->buffer + sizeof(uint8_t), buf, bl);
    //MAC LENGTH
    sinit->buffer[sizeof(uint8_t) + bl] = 0; //Mac is invalidated after decipher!
    sinit->buffer[0] = PACKET_SIG_SESSION_INIT_RESP;
    p->ptype &= ~PACKET_TYPE_CRYPTO;
    //Rebuild pointers
    unpack(p);
    delete [] buf;
}


void PACPSessionInitResponse::cipher(pktCmn_t* p, kmKey_t* key) {
    if(!p || !key || !key->rc4 || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_SINIT_RESP || !p->ptype & PACKET_TYPE_CRYPTO) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t* sinit = (pktSessionInitResponse_t*) p->sighdr;
    uint8_t* buf = new uint8_t[sinit->dataLength + 256];
    uint16_t bl = sinit->dataLength + 256;
    KeyManager::cipher(key, buf, &bl, sinit->buffer + sizeof(uint8_t), sinit->dataLength - 2 * sizeof(uint8_t));
    memcpy(sinit->buffer + sizeof(uint8_t), &bl, sizeof(uint16_t));
    memcpy(sinit->buffer + sizeof(uint8_t) + sizeof(uint16_t), buf, bl);
    sinit->macLength = sinit->buffer + sizeof(uint8_t) + sizeof(uint16_t) + bl;
    *sinit->macLength = 0;
    sinit->mac = sinit->macLength + sizeof(uint8_t);
    sinit->dataLength = sizeof(uint8_t) * 2 + sizeof(uint16_t) +  bl;
    sinit->buffer[0] = PACKET_SIG_SESSION_INIT_RESP_CRYPTO;
    delete [] buf;
}


void PACPSessionInitResponse::sign(pktCmn_t* p, kmKey_t* key) {
    if(!p || !key || !key->ec || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_SINIT_RESP) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t*	sinit = (pktSessionInitResponse_t*) p->sighdr;
    uint16_t	blen = sinit->dataLength - sizeof(uint8_t);
    uint16_t	siglen = 256;
    KeyManager::signECDSA(key, sinit->mac, &siglen, sinit->buffer, blen);
    //	fprintf(stderr,"DataL %u, MACL: %u\n", blen, siglen);
    *sinit->macLength = siglen;
    sinit->dataLength += siglen;
}


bool PACPSessionInitResponse::verifySig(pktCmn_t* p, kmKey_t* key) {
    if(!p || !key || !key->ec || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_SINIT_RESP) {
        MYTHROW1("Error with parameters");
    }

    pktSessionInitResponse_t*	sinit = (pktSessionInitResponse_t*) p->sighdr;
    uint32_t	blen = *((uint16_t*) (sinit->buffer + sizeof(uint8_t))) + sizeof(uint16_t) + sizeof(uint8_t);
    uint16_t	siglen = *sinit->macLength;
    //	fprintf(stderr,"DataL: %u, MACL: %u\n", blen,siglen);
    return KeyManager::verifyECDSA(key, sinit->mac, siglen, sinit->buffer, blen);
}






/*

	PACPFlowAuth

*/
void	PACPFlowAuth::setup(pktCmn_t* p, uint8_t* data) {
    if (!p || !data) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = new pktFlowAuth_t;
    memset(s, 0, sizeof(pktFlowAuth_t));
    s->buffer = data;
    p->sighdr = (uint8_t*) s;
    p->ptype |= PACKET_TYPE_SIG_FAUTH;
    p->alloc |= PKTCMN_ALLOC_SIG;
    unpack(p);
}


pktCmn_t*	PACPFlowAuth::alloc() {
    pktCmn_t* p = Packet::alloc();
    pktFlowAuth_t* s = new pktFlowAuth_t;
    p->ptype |= PACKET_TYPE_SIG;
    p->ptype |= PACKET_TYPE_SIG_FAUTH;
    p->alloc |= PKTCMN_ALLOC_SIG;
    p->sighdr = (uint8_t*) s;
    memset(s, 0, sizeof(pktFlowAuth_t));
    s->buffer = new uint8_t[PACKET_DEFAULT_PAYLOAD_SIZE];
    memset(s->buffer, 0, PACKET_DEFAULT_PAYLOAD_SIZE);
    s->buffer[0] = PACKET_SIG_FLOW_AUTH;
    s->dataLength = PKTFLOWAUTH_SIZE;
    s->alloc = PKTFLOWAUTH_ALLOC_BUFFER;
    unpack(p);
    return p;
}

void	PACPFlowAuth::free(pktCmn_t* p) {
    if(!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;

    if(s->alloc && PKTFLOWAUTH_ALLOC_BUFFER) {
        delete [] s->buffer;
    }

    if(p->alloc & PKTCMN_ALLOC_SIG) {
        p->alloc &= ~PKTCMN_ALLOC_SIG;
        delete s;
        p->sighdr = NULL;
    }
}



void	PACPFlowAuth::pack(pktCmn_t* p) {
    //	MYTHROW1("PACPFlowAuth::pack Not Implemented!");
    if(!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    s->dataLength = PKTFLOWAUTH_SIZE + *s->macLength;
}



void PACPFlowAuth::unpack(pktCmn_t* p) {
    if(!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    uint8_t*	buffi = s->buffer;
    buffi++;
    s->request =  ( uint8_t*) buffi;
    buffi++;
    s->sid = (uint64_t*) buffi;
    buffi += sizeof(uint64_t);
    s->src = (in6_addr*) buffi;
    buffi += sizeof(in6_addr);
    s->dst = (in6_addr*) buffi;
    buffi += sizeof(in6_addr);
    s->tc = buffi;
    buffi += sizeof(uint8_t);
    s->proto = buffi;
    buffi += sizeof(uint8_t);
    s->sport = (uint16_t*) buffi;
    buffi += sizeof(uint16_t);
    s->dport = (uint16_t*) buffi;
    buffi += sizeof(uint16_t);
    s->macLength = buffi;
    buffi += sizeof(uint8_t);
    s->mac = buffi;
}



uint8_t* PACPFlowAuth::getBuffer(pktCmn_t* p, uint16_t* bl) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    *bl = s->dataLength;
    return s->buffer;
}

void PACPFlowAuth::setRequestKey(pktCmn_t* p, uint8_t value) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    *s->request = value;
}

uint8_t PACPFlowAuth::getRequestKey(pktCmn_t* p) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    return *s->request;
}


void PACPFlowAuth::setProto(pktCmn_t* p, uint8_t proto) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    *s->proto = proto;
}


uint8_t PACPFlowAuth::getProto(pktCmn_t* p) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    return *s->proto;
}



void PACPFlowAuth::setDPort(pktCmn_t* p, uint16_t dp) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    *s->dport = htons(dp);
}



uint16_t	PACPFlowAuth::getDPort(pktCmn_t* p) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    return ntohs(*s->dport);
}

void PACPFlowAuth::setSPort(pktCmn_t* p, uint16_t sp) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    *s->sport = htons(sp);
}

uint16_t	PACPFlowAuth::getSPort(pktCmn_t* p) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    return ntohs(*s->sport);
}

void PACPFlowAuth::setSessionID(pktCmn_t* p, uint64_t	sid) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    memcpy(s->sid, &sid, sizeof(uint64_t));
}


uint64_t PACPFlowAuth::getSessionID(pktCmn_t* p) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    uint64_t	sid = 0;
    memcpy(&sid, s->sid, sizeof(uint64_t));
    return sid;
}

void PACPFlowAuth::setSessionSrc(pktCmn_t* p, in6_addr* addr) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    memcpy(s->src, addr, sizeof(in6_addr));
}

in6_addr* PACPFlowAuth::getSessionSrc(pktCmn_t* p) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    return s->src;
}


void PACPFlowAuth::setSessionDst(pktCmn_t* p, in6_addr* addr) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    memcpy(s->dst, addr, sizeof(in6_addr));
}

in6_addr* PACPFlowAuth::getSessionDst(pktCmn_t* p) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t* s = (pktFlowAuth_t*) p->sighdr;
    return s->dst;
}

void PACPFlowAuth::sign(pktCmn_t* p, kmKey_t* key) {
    if(!p || !key || !key->ec || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t*	f = (pktFlowAuth_t*) p->sighdr;
    uint16_t	blen = f->macLength - f->buffer - sizeof(uint8_t);
    uint16_t	siglen = 256;
    KeyManager::signECDSA(key, f->mac, &siglen, f->buffer, blen);
    *f->macLength = siglen;
    f->dataLength += siglen;
}


bool PACPFlowAuth::verifySig(pktCmn_t* p, kmKey_t* key) {
    if(!p || !key || !key->ec || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuth_t*	f = (pktFlowAuth_t*) p->sighdr;
    uint32_t	blen = f->macLength - f->buffer - sizeof(uint8_t);
    uint16_t	siglen = *f->macLength;
    return KeyManager::verifyECDSA(key, f->mac, siglen, f->buffer, blen);
}

/*

	PACPFlowAuthResponse

*/
void	PACPFlowAuthResponse::setup(pktCmn_t* p, uint8_t* data) {
    if (!p || !data) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = new pktFlowAuthResponse_t;
    memset(s, 0, sizeof(pktFlowAuthResponse_t));
    s->buffer = data;
    p->sighdr = (uint8_t*) s;
    p->ptype |= PACKET_TYPE_SIG_FAUTH_RESP;
    p->alloc |= PKTCMN_ALLOC_SIG;
    p->alloc |= PKTCMN_ALLOC_FAUTH_RESP;
    unpack(p);
}

pktCmn_t*	PACPFlowAuthResponse::alloc() {
    pktCmn_t* p = Packet::alloc();
    pktFlowAuthResponse_t* s = new pktFlowAuthResponse_t;
    p->ptype |= PACKET_TYPE_SIG;
    p->ptype |= PACKET_TYPE_SIG_FAUTH_RESP;
    p->alloc |= PKTCMN_ALLOC_SIG;
    p->sighdr = (uint8_t*) s;
    memset(s, 0, sizeof(pktFlowAuthResponse_t));
    s->buffer = new uint8_t[PACKET_DEFAULT_PAYLOAD_SIZE];
    memset(s->buffer, 0, PACKET_DEFAULT_PAYLOAD_SIZE);
    s->buffer[0] = PACKET_SIG_FLOW_AUTH_RESP;
    s->dataLength = PKTFLOWAUTHRESP_SIZE;
    s->alloc = PKTFLOWAUTHRESP_ALLOC_BUFFER;
    unpack(p);
    return p;
}



void	PACPFlowAuthResponse::free(pktCmn_t* p) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;

    if (s->buffer && s->alloc & PKTFLOWAUTHRESP_ALLOC_BUFFER) {
        delete [] s->buffer;
    }

    if (p->alloc & PKTCMN_ALLOC_SIG) {
        delete s;
        p->sighdr = NULL;
        p->alloc &= ~PKTCMN_ALLOC_SIG;
    }
}


void	PACPFlowAuthResponse::pack(pktCmn_t* p) {
    //Nothing to do now.
}


void PACPFlowAuthResponse::unpack(pktCmn_t* p) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    s->code = s->buffer;
    uint8_t* buffi = s->buffer + 1;
    s->result = (uint32_t*) buffi;
    buffi += sizeof(uint32_t);
    s->sessionID = (uint64_t*) buffi;
    buffi += sizeof(uint64_t);
    s->issueTime = (uint32_t*) buffi;
    buffi += sizeof(uint32_t);
    s->startTime = (uint32_t*) buffi;
    buffi += sizeof(uint32_t);
    s->expireTime = (uint32_t*) buffi;
    buffi += sizeof(uint32_t);
    s->keyLength =  buffi;
    buffi += sizeof(uint8_t);
    s->key =  buffi;
    buffi += *s->keyLength;
    s->macLength = buffi;
    buffi += sizeof(uint8_t);
    s->mac = buffi;
    s->dataLength = s->mac - s->buffer + *s->macLength;
}



void PACPFlowAuthResponse::setCode(pktCmn_t* p, uint32_t code) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    uint32_t	aux = htonl(code);
    memcpy(s->result, &aux, sizeof(uint32_t));
}




uint32_t PACPFlowAuthResponse::getCode(pktCmn_t* p) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    uint32_t	aux = 0;
    memcpy(&aux, s->result, sizeof(uint32_t));
    return ntohl(aux);
}



void PACPFlowAuthResponse::setSessionID(pktCmn_t* p, uint64_t sid) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    memcpy(s->sessionID, &sid, sizeof(uint64_t));
}



uint64_t PACPFlowAuthResponse::getSessionID(pktCmn_t* p) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    uint64_t	aux = 0;
    memcpy(&aux, s->sessionID, sizeof(uint64_t));
    return aux;
}



void PACPFlowAuthResponse::setExpireTime(pktCmn_t* p, uint32_t t) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    uint32_t	aux = htonl(t);
    memcpy(s->expireTime, &aux, sizeof(uint32_t));
}



uint32_t PACPFlowAuthResponse::getExpireTime(pktCmn_t* p) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    uint32_t	aux = 0;
    memcpy(&aux, s->expireTime, sizeof(uint32_t));
    return ntohl(aux);
}

void PACPFlowAuthResponse::setIssueTime(pktCmn_t* p, uint32_t t) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    uint32_t	aux = htonl(t);
    memcpy(s->issueTime, &aux, sizeof(uint32_t));
}

uint32_t PACPFlowAuthResponse::getIssueTime(pktCmn_t* p) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    uint32_t	aux = 0;
    memcpy(&aux, s->issueTime, sizeof(uint32_t));
    return ntohl(aux);
}



void PACPFlowAuthResponse::setStartTime(pktCmn_t* p, uint32_t t) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    uint32_t	aux = htonl(t);
    memcpy(s->startTime, &aux, sizeof(uint32_t));
}



uint32_t PACPFlowAuthResponse::getStartTime(pktCmn_t* p) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP || !p->sighdr) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    uint32_t	aux = 0;
    memcpy(&aux, s->startTime, sizeof(uint32_t));
    return ntohl(aux);
}


void PACPFlowAuthResponse::setKey(pktCmn_t* p, kmKey_t* k) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP || !k) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    *s->keyLength = KeyManager::dumpECbuf(k, s->key);
    s->macLength += *s->keyLength;
    s->mac += *s->keyLength;
    s->dataLength += *s->keyLength;
//	fprintf(stderr,"Added key with %u bytes\n", *s->keyLength);
}

kmKey_t* PACPFlowAuthResponse::getKey(pktCmn_t* p) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;

    if(s->key && *s->keyLength) {
        return KeyManager::loadECbuf(s->key);
    }

    return NULL;
}


uint8_t* PACPFlowAuthResponse::getBuffer(pktCmn_t* p, uint16_t* bl) {
    if (!p || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t* s = (pktFlowAuthResponse_t*) p->sighdr;
    *bl = s->dataLength;
    return s->buffer;
}

void PACPFlowAuthResponse::sign(pktCmn_t* p, kmKey_t* key) {
    if(!p || !key || !key->ec || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t*	f = (pktFlowAuthResponse_t*) p->sighdr;
    uint16_t	blen = f->macLength - f->buffer;
    uint16_t	siglen = 256;
    KeyManager::signECDSA(key, f->mac, &siglen, f->buffer, blen);
    *f->macLength = siglen;
    f->dataLength += siglen;
    /*
    	int i=0;
    	for(i =0; i<siglen;i++)
    				fprintf(stderr,"%X:",f->mac[i]);
    	fprintf(stderr,"\n");

        <<<<<<< packet.cc
    	fprintf(stderr,"kl: %u, blen: %u, siglen: %u\n", *f->keyLength,blen, siglen);	*/
}


bool PACPFlowAuthResponse::verifySig(pktCmn_t* p, kmKey_t* key) {
    if(!p || !key || !key->ec || !p->sighdr || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP) {
        MYTHROW1("Error with parameters");
    }

    pktFlowAuthResponse_t*	f = (pktFlowAuthResponse_t*) p->sighdr;
    uint32_t	blen = f->macLength - f->buffer;
    uint16_t	siglen = *f->macLength;

    if(!siglen) {
        return false;
    }

    /*

    	fprintf(stderr,"DL: %u, kl: %u, blen: %u, siglen: %u\n", f->dataLength, *f->keyLength,blen, siglen);
    	int i=0;
    	for(i =0; i<siglen;i++)
    				fprintf(stderr,"%X:",f->mac[i]);
    	fprintf(stderr,"\n");
    */
    return KeyManager::verifyECDSA(key, f->mac, siglen, f->buffer, blen);
}
