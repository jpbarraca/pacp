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
#include "chargingAgent.h"
#include "packetHandler.h"
#include "packet.h"
#include "proofAttendant.h"
#include "log.h"
#include "sessionManager.h"
#include "routingClient.h"
#include "exception.h"
#include "fec.h"
#include "gwInfoClient.h"
#include "timer.h"
#include "a4cClient.h"
#include "keyManager.h"

bool ChargingAgent::_run;
bool ChargingAgent::_running;


//! Default Constructor
ChargingAgent::ChargingAgent() {
    _pHandler = NULL;
    _proofAttendant = NULL;
    _sessionManager = NULL;
    _routingClient = NULL;
    _gwInfoClient = NULL;
    _a4cClient = NULL;
    _run = false;
    _running = false;
    _timer = NULL;
    _fecCode = fec_new(16, GF_SIZE + 1);
}

//! Default Destructor
ChargingAgent::~ChargingAgent() {
    _run = false;
    logger << LOG_L(LOG_DEBUG) << "Stopping main loop:";
    sleep(2);

    if (_a4cClient) {
        delete _a4cClient;
        _a4cClient = NULL;
    }

    if (_proofAttendant) {
        delete _proofAttendant;
        _proofAttendant = NULL;
    }

    if (_sessionManager) {
        delete _sessionManager;
        _sessionManager = NULL;
    }

    if (_routingClient) {
        delete _routingClient;
        _routingClient = NULL;
    }

    if (_pHandler) {
        delete _pHandler;
        _pHandler = NULL;
    }

    if (_gwInfoClient) {
        delete _gwInfoClient;
        _gwInfoClient = NULL;
    }

    if(_keyManager) {
        delete _keyManager;
        _keyManager = NULL;
    }

    fec_free(_fecCode);
}

//! Charging Agent main loop
int ChargingAgent::run() {
    try {
        if (!_keyManager) {
            _keyManager = new KeyManager();
        }

        _keyManager->_hostKey = KeyManager::generateSim(32);
        KeyManager::generateEC(_keyManager->_hostKey);
        _keyManager->_opKey =	KeyManager::loadRSAname((char*) conf->getOperatorRSAKeyFile().c_str());
        KeyManager::loadECname( (char*) conf->getOperatorECKeyFile().c_str(), _keyManager->_opKey);

        if (!_pHandler) {
            _pHandler = new PacketHandler();
        }

        if (!_timer) {
            _timer = new Timer(_pHandler);
        }

        if (!_a4cClient) {
            _a4cClient = new A4CClient( _timer, _pHandler, _keyManager);
        }

        if (!_routingClient) {
            _routingClient = new RoutingClient(ROUTING_PROTO_STATIC);
        }

        if (!_proofAttendant) {
            _proofAttendant = new ProofAttendant(_timer, _keyManager);
        }

        /*
        		if (!_gwInfoClient) {
        			_gwInfoClient = new GWInfoClient();
        		}
        */
        if (!_sessionManager) {
            _sessionManager = new SessionManager(_timer, _pHandler, _keyManager);
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
    logger << LOG_L(LOG_DEBUG) << "Starting ChargingAgent loop\n";
    _a4cClient->connect(conf->getDefaultChargingManager());

    while ( _run ) {
        pktCmn_t* packet = NULL;

        try {
//			fprintf(stderr,"Getting Packet: ");
            packet = _pHandler->getPacket();

        } catch (Exception e) {
            e.print();
            continue;
        }

        if (!packet) {
//			fprintf(stderr,"Not packet\n");
            continue;
        }

        //White Packet are ignored
        if (packet->ptype & PACKET_TYPE_WHITE) {
            packet->verdict = PACKET_VERDICT_ACCEPT_WHITE;

        } else {
//			fprintf(stderr,"Got Packet\n");
            if (packet->ptype & PACKET_TYPE_DATA && _a4cClient->getConnectStatus() != A4CCLIENT_CONNECT_OK ) {
                packet->verdict = PACKET_VERDICT_DROP;

            } else
                switch (Packet::getDirection(packet)) {
                    case PACKET_DIRECTION_OUT : {
                        if (packet->ptype & PACKET_TYPE_SIG) {
                            processPacketSigOut(packet);

                        } else if (packet->ptype & PACKET_TYPE_DATA) {
                            processPacketDataOut(packet);
                        }

                        break;
                    }

                    case PACKET_DIRECTION_IN : {
                        if (packet->ptype & PACKET_TYPE_SIG) {
                            processPacketSigIn(packet);

                        } else if (packet->ptype & PACKET_TYPE_DATA) {
                            processPacketDataIn(packet);
                        }

                        break;
                    }

                    case PACKET_DIRECTION_FWR : {
                        if (packet->ptype & PACKET_TYPE_SIG) {
                            processPacketSigFwr(packet);

                        } else if (packet->ptype & PACKET_TYPE_DATA) {
                            processPacketDataFwr(packet);

                        } else {
                            logger << LOG_L(LOG_DEBUG) << "Packet is not SIG neither Data????\n";
                        }

                        break;
                    }

                    default: {
                        //logger<<LOG_L(LOG_WARNING)<<"Unknown Packet Direction!! Accepting\n";
                        packet->verdict = PACKET_VERDICT_ACCEPT_WHITE;
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
                logger << "ChargingAgent: Queueing Packet\n";
                break;
            }
        }
    }

    _running = false;
    return 0;
}


int ChargingAgent::processPacketDataIn(pktCmn_t* packet) {
//	logger << "ChargingAgent: Got a packet IN\n";
    packet->session = _sessionManager->getSession(packet);

    if(conf->getUseCryptoData() && false) {
        kmKey_t* key = NULL;

        if(packet->ptype & PACKET_TYPE_DATA_SHDR) {
            if(PACPHeaderSmall::getCode(packet) & HEADER_CODE_EXT) {
                key = _keyManager->_opKey;

            } else {
                key = _keyManager->findKey(IPV6Packet::getSrc(packet));
            }

            if(!PACPHeaderSmall::verifySig(packet, key)) {
                logger << LOG_L(LOG_DEBUG) << "ChargingAgent: Header Signature verification failed\n";
                packet->verdict = PACKET_VERDICT_DROP;
                packet->session->lastSigFail = packet->timestamp;

            } else	{
                packet->verdict = PACKET_VERDICT_ACCEPT;
                packet->session->recvPackets++;
                packet->session->recvBytes += packet->ipqhdr->data_len;
            }

        } else {
            if(PACPHeaderFull::getCode(packet) & HEADER_CODE_EXT) {
                key = _keyManager->_opKey;

            } else {
                key = _keyManager->findKey(IPV6Packet::getSrc(packet));
            }

            if(!PACPHeaderFull::verifySig(packet, key)) {
                logger << LOG_L(LOG_DEBUG) << "ChargingAgent: Header Signature verification failed\n";
                packet->verdict = PACKET_VERDICT_DROP;
                packet->session->lastSigFail = packet->timestamp;

            } else	{
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


int ChargingAgent::processPacketDataOut(pktCmn_t* packet) {
    packet->session = _sessionManager->getSession(packet);
    uint32_t	auth = _sessionManager->authorizeSession(packet->session, packet);

    switch (auth) {
        case SESSION_AUTH_ONGOING :
            return packet->verdict;

        case SESSION_AUTH_ALLOWED :
            packet->verdict = PACKET_VERDICT_ACCEPT;
            break;

        case SESSION_AUTH_UNKNOWN :
        case SESSION_AUTH_BLOCK :
            packet->verdict = PACKET_VERDICT_DROP;
            return PACKET_VERDICT_DROP;

        default :
            packet->verdict = PACKET_VERDICT_DROP;
            return PACKET_VERDICT_DROP;
    }

    if (packet->session->status == SESSION_STATUS_UNKNOWN) {
        packet->session->status = SESSION_STATUS_ACTIVE;
        packet->session->code = 0;
        logger << LOG_L(LOG_DEBUG) << "ChargingAgent: Session State UNKNOWN\n";
    }

    packet->session->lastPacketTime = packet->ipqhdr->timestamp_sec;
    packet->session->index++;
    packet->session->sequence++;

    if (_routingClient->isNextHop(&packet->ipv6hdr->ip6_dst)) {
        packet->session->code = HEADER_CODE_SMALL;
        PACPHeaderSmall::addHeader(packet, packet->session->index, packet->session->sequence);
        PACPHeaderSmall::initHashChain(packet, (uint8_t*) conf->getUserSecret().c_str(), conf->getUserSecret().length());
        /*
        		if (!packet->session->timer) {
        			packet->session->timer = _timer;
        			packet->session->paTimerKey = _timer->addTimerEvent(_proofAttendant, SESSION_REPORT_INTERVAL, -1, SESSION_REPORT_INTERVAL, (uint8_t*) & packet->session->hash, sizeof(uint64_t));
        		}
        */
        logger << LOG_L(LOG_DEBUG) << "Sending and Last HOP!\n";
        packet->session->status |= SESSION_POSITION_LAST | SESSION_POSITION_FIRST;
        _proofAttendant->collectProof(conf->getDefaultChargingManager(), packet);

        if(conf->getUseCryptoData()) {
            PACPHeaderSmall::sign(packet, _keyManager->_hostKey);
        }

        PACPHeaderSmall::pack(packet);

    } else {
        packet->session->code = HEADER_CODE_FULL;
        logger << LOG_L(LOG_DEBUG) << "Sending and not last HOP!\n";
        PACPHeaderFull::addHeader(packet, packet->session->index, packet->session->sequence);
        PACPHeaderFull::initHashChain(packet, (uint8_t*) conf->getUserSecret().c_str(), conf->getUserSecret().length());

        if(conf->getUseCryptoData()) {
            PACPHeaderFull::sign(packet, _keyManager->_hostKey);
        }

        PACPHeaderFull::pack(packet);
    }

    packet->session->sentPackets++;
    packet->session->sentBytes += ntohs(packet->ipv6hdr->ip6_plen);
    packet->verdict = PACKET_VERDICT_ACCEPT;
    return PACKET_VERDICT_ACCEPT;
}

int ChargingAgent::processPacketDataFwr(pktCmn_t* packet) {
    packet->verdict = PACKET_VERDICT_ACCEPT;
    packet->session = _sessionManager->getSession(packet);

    if (packet->session->status == SESSION_STATUS_UNKNOWN) {
        packet->session->status = SESSION_STATUS_ACTIVE;
    }

    uint32_t	auth = _sessionManager->authorizeSession(packet->session, packet);

    switch (auth) {
        case SESSION_AUTH_ONGOING :
            return packet->verdict;

        case SESSION_AUTH_ALLOWED :
            packet->verdict = PACKET_VERDICT_ACCEPT;
            break;

//				return PACKET_VERDICT_ACCEPT;

        case SESSION_AUTH_UNKNOWN :
        case SESSION_AUTH_BLOCK :
        default :
            packet->verdict = PACKET_VERDICT_DROP;
            return PACKET_VERDICT_DROP;
    }

    packet->session->lastPacketTime = packet->ipqhdr->timestamp_sec;

    if (packet->ptype & PACKET_TYPE_DATA_FHDR ) {
        PACPHeaderFull::updateRID(packet, (uint8_t*) conf->getUserID().c_str(), conf->getUserID().length(), _fecCode);
        PACPHeaderFull::updateRHash(packet, (uint8_t*) conf->getUserID().c_str(), conf->getUserID().length());
        PACPHeaderFull::updateHashChain(packet, (uint8_t*) conf->getUserSecret().c_str(), conf->getUserSecret().length());
        packet->status = PACKET_DATA_CHANGED;

        if(conf->getUseCryptoData()) {
            kmKey_t* key = _keyManager->findKey(IPV6Packet::getSrc(packet));

            if(!key) {
                logger << LOG_L(LOG_WARNING) << "ChargingManager: Host key not found! Discarding packet\n";
                packet->verdict = PACKET_VERDICT_DROP;
                return PACKET_VERDICT_DROP;
            }

            if(!PACPHeaderFull::verifySig(packet, key)) {
                logger << LOG_L(LOG_DEBUG) << "ChargingAgent: Header Signature verification failed\n";
                packet->verdict = PACKET_VERDICT_DROP;
                return packet->verdict;
            };
        }

        if (_routingClient->isNextHop(&packet->ipv6hdr->ip6_dst)) {
            /*			if (!packet->session->timer) {
            				packet->session->timer = _timer;
            				packet->session->paTimerKey = _timer->addTimerEvent(_proofAttendant, SESSION_REPORT_INTERVAL, -1, SESSION_REPORT_INTERVAL, (uint8_t*) & packet->session->hash, sizeof(uint64_t));
            			}
            */
            logger << LOG_L(LOG_DEBUG) << "Forwarding and Last HOP!\n";
            packet->session->status |= SESSION_POSITION_LAST | SESSION_POSITION_MIDDLE;
            _proofAttendant->collectProof(conf->getDefaultChargingManager(), packet);

        } else {
            logger << LOG_L(LOG_DEBUG) << "Forwarding and NOT Last HOP!\n";
        }

    } else if (packet->ptype & PACKET_TYPE_DATA_SHDR) {
        logger << LOG_L(LOG_WARNING) << "Forwarding packet with small proof!!??\n";

    } else {
        logger << LOG_L(LOG_WARNING) << "Forwarding packet without proof!\n";
    }

    packet->session->fwrdPackets++;
    packet->session->fwrdBytes += packet->ipqhdr->data_len;
    return PACKET_VERDICT_ACCEPT;
}

int ChargingAgent::processPacketSigIn(pktCmn_t* packet) {
    packet->verdict = PACKET_VERDICT_DROP;
    logger << LOG_L(LOG_DEBUG) << "ChargingAgent: Got a Control Packet\n";

    if (packet->ptype & PACKET_TYPE_SIG_REP_RESP) {
        logger << LOG_L(LOG_DEBUG) << "ChargingAgent: Got a Report Response Packet\n";
        _proofAttendant->reportReceived(PACPReportResponse::getReportID(packet));

    } else if (packet->ptype & PACKET_TYPE_SIG_SINIT_RESP) {
        logger << LOG_L(LOG_DEBUG) << "ChargingAgent: Got a Session Init Response\n";
        _a4cClient->responseReceived(packet);

    } else if (packet->ptype & PACKET_TYPE_SIG_FAUTH_RESP) {
        logger << LOG_L(LOG_DEBUG) << "ChargingAgent: Got a Flow Auth Response\n";
        _sessionManager->processFlowAuthResponse(packet);

    } else {
        logger << LOG_L(LOG_DEBUG) << "ChargingAgent: UNKOWN Control Type\n";
    }

    return PACKET_VERDICT_DROP;
}

int ChargingAgent::processPacketSigOut(pktCmn_t* packet) {
    packet->verdict = PACKET_VERDICT_ACCEPT;
    return PACKET_VERDICT_ACCEPT;
}

int ChargingAgent::processPacketSigFwr(pktCmn_t* packet) {
    packet->verdict = PACKET_VERDICT_ACCEPT;
    return PACKET_VERDICT_ACCEPT;
}

int ChargingAgent::processPacketWhite(pktCmn_t* packet) {
    packet->verdict = PACKET_VERDICT_ACCEPT;
    return PACKET_VERDICT_ACCEPT;
}
