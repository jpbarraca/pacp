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

#include <stdlib.h>
#include "internetworkAdapter.h"
#include "packetHandler.h"
#include "packet.h"
#include "proofAttendant.h"
#include "log.h"
#include "sessionManager.h"
#include "routingClient.h"
#include "fec.h"
#include "timer.h"
#include "a4cClient.h"
#include "keyManager.h"
#include "exception.h"

//! Default Constructor
InternetworkAdapter::InternetworkAdapter() {
    _pHandler = NULL;
    _proofAttendant = NULL;
    _sessionManager = NULL;
    _routingClient = NULL;
    _a4cClient = NULL;
    _keyManager = NULL;
    _run = false;
    _running = false;
    init_fec();
    _fecCode = fec_new(16, 256);

    if (!_fecCode) {
        logger << LOG_L(LOG_FATAL) << "InternetworkAdapter: Error initializing FEC\n";
        throw (void*) NULL;
    }
}

//! Default Destructor
InternetworkAdapter::~InternetworkAdapter() {
    _run = false;
    logger << LOG_L(LOG_DEBUG) << "Stopping main loop:";
    sleep(1);
    logger << "X\n";
}

//! Charging Agent main loop
int InternetworkAdapter::run() {
    try {
        if (!_keyManager) {
            _keyManager = new KeyManager();
        }

        _keyManager->_hostKey = KeyManager::generateSim(32);
//		KeyManager::generateEC(_keyManager->_hostKey);
        _keyManager->_opKey = KeyManager::loadRSAname((char*) conf->getOperatorRSAKeyFile().c_str());
        KeyManager::loadECname( (char*) conf->getOperatorECKeyFile().c_str(), _keyManager->_opKey);
        KeyManager::loadECname( (char*) conf->getOperatorECKeyFile().c_str(), _keyManager->_hostKey);

        if (!_pHandler) {
            _pHandler = new PacketHandler();
        }

        if (!_timer) {
            _timer = new Timer(_pHandler);
        }

        if (!_sessionManager) {
            _sessionManager = new SessionManager(_timer, _pHandler, _keyManager);
        }

        if (!_a4cClient) {
            _a4cClient = new A4CClient(_timer, _pHandler, _keyManager);
        }

        if (!_routingClient) {
            _routingClient = new RoutingClient(ROUTING_PROTO_STATIC);
        }

        if (!_proofAttendant) {
            _proofAttendant = new ProofAttendant(_timer, _keyManager);
        }

    } catch (Exception e) {
        e.print();
        _running = false;
        return 1;
    }

    //Some init
    _run = true;
    _running = true;
    //Get packets and process them
    logger << LOG_L(LOG_DEBUG) << "Starting InternetworkAdapter loop\n";
    _a4cClient->connect(conf->getDefaultChargingManager());

    while ( _run ) {
        pktCmn_t* packet = NULL;

        try {
            packet = _pHandler->getPacket();

            if (!packet) {
                continue;
            }

        } catch (Exception e) {
            e.print();
            continue;
        }

        //White Packet are ignored
        if (packet->ptype & PACKET_TYPE_WHITE) {
            packet->verdict = PACKET_VERDICT_ACCEPT_WHITE;

        } else {
            if (packet->ptype & PACKET_TYPE_DATA && _a4cClient->getConnectStatus() != A4CCLIENT_CONNECT_OK ) {
                packet->verdict = PACKET_VERDICT_DROP;

            } else
                switch (Packet::getDirection(packet)) {
                    case PACKET_DIRECTION_OUT : {
                        if (packet->ptype & PACKET_TYPE_SIG) {
                            processPacketSigOut(packet);

                        } else {
                            processPacketDataOut(packet);
                        }

                        break;
                    }

                    case PACKET_DIRECTION_IN : {
                        if (packet->ptype & PACKET_TYPE_SIG) {
                            processPacketSigIn(packet);

                        } else {
                            processPacketDataIn(packet);
                        }

                        break;
                    }

                    case PACKET_DIRECTION_FWR : {
                        if (packet->ptype & PACKET_TYPE_SIG) {
                            processPacketSigFwr(packet);

                        } else {
                            processPacketDataFwr(packet);
                        }

                        break;
                    }

                    default: {
                        logger << LOG_L(LOG_WARNING) << "Unknown Packet Direction!! Dropping\n";
                        packet->verdict = PACKET_VERDICT_DROP;
                    }
                }
        }

        switch (packet->verdict) {
            case PACKET_VERDICT_ACCEPT_WHITE:
            case PACKET_VERDICT_ACCEPT:
            case PACKET_VERDICT_DROP: {
                if(packet->ipqhdr) {
                    _pHandler->setVerdict(packet, packet->verdict);
                }

                Packet::free(packet);
                break;
            }

            case PACKET_VERDICT_QUEUE: {
                logger << "InternetworkAdapter: Queueing Packet\n";
                break;
            }
        }
    }

    _running = false;
    return 0;
}


int InternetworkAdapter::processPacketDataIn(pktCmn_t* packet) {
    if(!(packet->ptype & PACKET_TYPE_DATA_SHDR) && !(packet->ptype & PACKET_TYPE_DATA_FHDR)) {
        packet->verdict = PACKET_VERDICT_ACCEPT;
        logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter::processPacketDataIn: Receiving Data packet without proof\n";
        return packet->verdict;
    }

    packet->session = _sessionManager->getSession(packet);

    if (packet->session->status == SESSION_STATUS_UNKNOWN) {
        packet->session->status = SESSION_STATUS_ACTIVE;
    }

    uint32_t auth = _sessionManager->authorizeSession(packet->session, packet);

    switch (auth) {
        case SESSION_AUTH_ONGOING :
            packet->verdict = PACKET_VERDICT_QUEUE;
            return PACKET_VERDICT_QUEUE;

        case SESSION_AUTH_ALLOWED :
            packet->verdict = PACKET_VERDICT_ACCEPT;
            break;

        case SESSION_AUTH_UNKNOWN :
        case SESSION_AUTH_BLOCK :
        default :
            packet->verdict = PACKET_VERDICT_DROP;
            return PACKET_VERDICT_DROP;
    }

    packet->session->lastPacketTime = packet->ipqhdr->timestamp_sec;

    if (conf->getUseCryptoData()) {
        kmKey_t* key = NULL;

        if (packet->ptype & PACKET_TYPE_DATA_SHDR) {
            if (PACPHeaderSmall::getCode(packet) & HEADER_CODE_EXT) {
                key = _keyManager->_opKey;

            } else {
                key = _keyManager->findKey(IPV6Packet::getSrc(packet));
            }

            if (!PACPHeaderSmall::verifySig(packet, key)) {
                logger << LOG_L(LOG_DEBUG) << "ChargingAgent: Header Signature verification failed\n";
                packet->verdict = PACKET_VERDICT_ACCEPT;
                packet->session->lastSigFail = packet->timestamp;

            } else {
                packet->verdict = PACKET_VERDICT_ACCEPT;
                packet->session->recvPackets++;
                packet->session->recvBytes += packet->ipqhdr->data_len;
            }

        } else {
            if (PACPHeaderFull::getCode(packet) & HEADER_CODE_EXT) {
                key = _keyManager->_opKey;

            } else {
                key = _keyManager->findKey(IPV6Packet::getSrc(packet));
            }

            if (!PACPHeaderFull::verifySig(packet, key)) {
                logger << LOG_L(LOG_DEBUG) << "ChargingAgent: Header Signature verification failed\n";
                packet->verdict = PACKET_VERDICT_DROP;
                packet->session->lastSigFail = packet->timestamp;

            } else {
                packet->verdict = PACKET_VERDICT_ACCEPT;
                packet->session->recvPackets++;
                packet->session->recvBytes += packet->ipqhdr->data_len;
            }
        }

    } else {
        packet->verdict = PACKET_VERDICT_ACCEPT;
        packet->session->recvPackets++;
        packet->session->recvBytes += packet->ipqhdr->data_len;
    }

    return packet->verdict;
}

int InternetworkAdapter::processPacketDataOut(pktCmn_t* packet) {
    //		if(Packet::sameNet(&packet->hIP->ip6_dst,conf->getNetworkAdhocAddress(),conf->getNetworkAdhocAddressMask())){
    // Going to the ad-hoc from the outside. Act as first node.
    logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Packet is to the Ad-hoc (from me)\n";
    packet->session->index++;
    packet->session->sequence++;

    //Are we the last hop??
    if (_routingClient->isNextHop(IPV6Packet::getDst(packet))) {
        packet->session->code = HEADER_CODE_SMALL;
        PACPHeaderSmall::addHeader(packet, packet->session->index, packet->session->sequence);
        PACPHeaderSmall::initHashChain(packet, (uint8_t*) conf->getNetworkSecret().c_str(), conf->getNetworkSecret().length());

        if (!packet->session->timer) {
            packet->session->timer = _timer;
        }

        if (conf->getUseCryptoData()) {
            PACPHeaderSmall::sign(packet, _keyManager->_hostKey);
        }

        logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Forwarding and Last HOP!\n";
        packet->session->status |= SESSION_POSITION_LAST | SESSION_POSITION_FIRST;
        _proofAttendant->collectProof(conf->getDefaultChargingManager(), packet);
        PACPHeaderSmall::pack(packet);

    } else {
        packet->session->code = HEADER_CODE_FULL;
        PACPHeaderFull::addHeader(packet, packet->session->index, packet->session->sequence);
        PACPHeaderFull::initHashChain(packet, (uint8_t*) conf->getNetworkSecret().c_str(), conf->getNetworkSecret().length());

        if (conf->getUseCryptoData()) {
            PACPHeaderFull::sign(packet, _keyManager->_hostKey);
        }

        PACPHeaderFull::pack(packet);
    }

    return PACKET_VERDICT_ACCEPT;
}

int InternetworkAdapter::processPacketDataFwr(pktCmn_t* packet) {
    packet->verdict = PACKET_VERDICT_ACCEPT;
    packet->session = _sessionManager->getSession(packet);

    if (packet->session->status == SESSION_STATUS_UNKNOWN) {
        packet->session->status = SESSION_STATUS_ACTIVE;
    }

    uint32_t auth = _sessionManager->authorizeSession(packet->session, packet);

    switch (auth) {
        case SESSION_AUTH_ONGOING :
            packet->verdict = PACKET_VERDICT_QUEUE;
            return PACKET_VERDICT_QUEUE;

        case SESSION_AUTH_ALLOWED :
            packet->verdict = PACKET_VERDICT_ACCEPT;
            break;

        case SESSION_AUTH_UNKNOWN :
        case SESSION_AUTH_BLOCK :
        default :
            packet->verdict = PACKET_VERDICT_DROP;
            return PACKET_VERDICT_DROP;
    }

    packet->session->lastPacketTime = packet->ipqhdr->timestamp_sec;

    //Now... Detect if the packet is going in or out.

    if (!strcmp(packet->ipqhdr->indev_name, conf->getAdhocDev().c_str())) {
        // Comming from the ad-hoc
        if (!strcmp(packet->ipqhdr->outdev_name, conf->getAdhocDev().c_str())) {
            logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Packet is internal!\n";
            //Going to the ad-hoc (Internal traffic using the GW as router)
            //Act as a normal forwarding node.

            if (packet->ptype & PACKET_TYPE_DATA_FHDR ) {
                if (conf->getUseCryptoData()) {
                    kmKey_t* key = _keyManager->findKey(IPV6Packet::getSrc(packet));

                    if (!key) {
                        logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: No key found! Dropping\n";
                        packet->verdict = PACKET_VERDICT_DROP;
                        return packet->verdict;
                    }

                    if (!PACPHeaderFull::verifySig(packet, key)) {
                        logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Data verification failed! Dropping\n";
                        packet->verdict = PACKET_VERDICT_DROP;
                        return packet->verdict;
                    }
                }

                PACPHeaderFull::updateRID(packet, (uint8_t*) conf->getUserID().c_str(), conf->getUserID().length(), _fecCode);
                PACPHeaderFull::updateRHash(packet, (uint8_t*) conf->getUserID().c_str(), conf->getUserID().length());
                PACPHeaderFull::updateHashChain(packet, (uint8_t*) conf->getUserSecret().c_str(), conf->getUserID().length());

                if (_routingClient->isNextHop(&packet->ipv6hdr->ip6_dst)) {
                    logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Forwarding and Last HOP!\n";
                    packet->session->status |= SESSION_POSITION_LAST | SESSION_POSITION_MIDDLE;
                    _proofAttendant->collectProof(conf->getDefaultChargingManager(), packet);
                }

            } else {
                logger << LOG_L(LOG_WARNING) << "InternetworkAdapter: Forwarding packet without proof!\n";
            }

            packet->session->fwrdPackets++;
            packet->session->fwrdBytes += packet->ipqhdr->data_len;
            return PACKET_VERDICT_ACCEPT;

        } else {
            //Going out of the ad-hoc
            //Remove header and collect proof!
            logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Packet is going out of the Ad-hoc!\n";

            if (packet->ptype & PACKET_TYPE_DATA_FHDR) {
                if (conf->getUseCryptoData()) {
                    kmKey_t* key = _keyManager->findKey(IPV6Packet::getSrc(packet));

                    if (!key) {
                        logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: No key found! Dropping\n";
                        packet->verdict = PACKET_VERDICT_DROP;
                        return packet->verdict;
                    }

                    if (!PACPHeaderFull::verifySig(packet, key)) {
                        logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Data verification failed! Dropping\n";
                        packet->verdict = PACKET_VERDICT_DROP;
                        return packet->verdict;
                    }
                }

                _proofAttendant->collectProof(conf->getDefaultChargingManager(), packet);
                //				PACPHeaderFull::remove(packet);

            } else if (packet->ptype & PACKET_TYPE_DATA_SHDR ) {
                kmKey_t* key = _keyManager->findKey(IPV6Packet::getSrc(packet));

                if (!key) {
                    logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: No key found! Dropping\n";
                    packet->verdict = PACKET_VERDICT_DROP;
                    return packet->verdict;
                }

                if (!PACPHeaderSmall::verifySig(packet, key)) {
                    logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Data verification failed! Dropping\n";
                    packet->verdict = PACKET_VERDICT_DROP;
                    return packet->verdict;
                }

                _proofAttendant->collectProof(conf->getDefaultChargingManager(), packet);
                //					PACPHeaderSmall::remove(packet);
            }

            packet->session->status |= SESSION_POSITION_LAST;
            packet->session->fwrdPackets++;
            packet->session->fwrdBytes += packet->ipqhdr->data_len;
            return PACKET_VERDICT_ACCEPT;
        }
    }

    //Going INTO the ADHOC
    if (!strcmp(packet->ipqhdr->indev_name, conf->getCoreDev().c_str())) {
        if (!strcmp(packet->ipqhdr->outdev_name, conf->getAdhocDev().c_str())) {
            //		if(Packet::sameNet(&packet->hIP->ip6_dst,conf->getNetworkAdhocAddress(),conf->getNetworkAdhocAddressMask())){
            // Going to the ad-hoc from the outside. Act as first node.
            logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Packet is going into the Ad-hoc!\n";
            packet->session->index++;
            packet->session->sequence++;

            //Are we the last hop??

            if (_routingClient->isNextHop(IPV6Packet::getDst(packet))) {
                packet->session->code = HEADER_CODE_SMALL;
                PACPHeaderSmall::addHeader(packet, packet->session->index, packet->session->sequence);
                PACPHeaderSmall::initHashChain(packet, (uint8_t*) conf->getNetworkSecret().c_str(), conf->getNetworkSecret().length());

                if (!packet->session->timer) {
                    packet->session->timer = _timer;
                }

                if (conf->getUseCryptoData()) {
                    PACPHeaderSmall::sign(packet, _keyManager->_hostKey);
                }

                logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Forwarding and Last HOP!\n";
                packet->session->status |= SESSION_POSITION_LAST | SESSION_POSITION_FIRST;
                _proofAttendant->collectProof(conf->getDefaultChargingManager(), packet);
                PACPHeaderSmall::pack(packet);

            } else {
                packet->session->code = HEADER_CODE_FULL;
                PACPHeaderFull::addHeader(packet, packet->session->index, packet->session->sequence);
                PACPHeaderFull::initHashChain(packet, (uint8_t*) conf->getNetworkSecret().c_str(), conf->getNetworkSecret().length());

                if (conf->getUseCryptoData()) {
                    PACPHeaderFull::sign(packet, _keyManager->_hostKey);
                }

                PACPHeaderFull::pack(packet);
            }

        } else {
            logger << LOG_L(LOG_ERROR) << "InternetworkAdapter: Forwarding packet not related with the Adhoc cloud!!\n";
            return PACKET_VERDICT_ACCEPT;
        }

    } else {
        logger << LOG_L(LOG_ERROR) << "InternetworkAdapter: Forwarding packet not related with the Adhoc cloud!!\n";
        return PACKET_VERDICT_ACCEPT;
    }

    return PACKET_VERDICT_ACCEPT;
}

int InternetworkAdapter::processPacketSigIn(pktCmn_t* packet) {
    packet->verdict = PACKET_VERDICT_DROP;
    logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Got a Control Packet\n";

    if (packet->ptype & PACKET_TYPE_SIG_REP_RESP) {
        logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Got a Report Response Packet\n";
        _proofAttendant->reportReceived(PACPReportResponse::getReportID(packet));

    } else if (packet->ptype & PACKET_TYPE_SIG_SINIT_RESP) {
        logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Got a Session Init Response\n";
        _a4cClient->responseReceived(packet);

    } else if (packet->ptype & PACKET_TYPE_SIG_FAUTH_RESP) {
        logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: Got a Flow Auth Response\n";
        _sessionManager->processFlowAuthResponse(packet);

    } else {
        logger << LOG_L(LOG_DEBUG) << "InternetworkAdapter: UNKOWN Control Type\n";
    }

    return PACKET_VERDICT_DROP;
}

int InternetworkAdapter::processPacketSigOut(pktCmn_t* packet) {
    packet->verdict = PACKET_VERDICT_ACCEPT;
    return PACKET_VERDICT_ACCEPT;
}

int InternetworkAdapter::processPacketSigFwr(pktCmn_t* packet) {
    packet->verdict = PACKET_VERDICT_ACCEPT;
    return PACKET_VERDICT_ACCEPT;
}
