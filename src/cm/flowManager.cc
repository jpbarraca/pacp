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

#include "flowManager.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <packet.h>
#include "packetHandler.h"
#include "sessionManager.h"
#include "keyManager.h"
#include "exception.h"

FlowManager::FlowManager(PacketHandler* p, KeyManager* km) {
    _pHandler = p;
    _keyManager = km;
}

FlowManager::~FlowManager() {
}

void FlowManager::processPacket(pktCmn_t* fauth) {
    if (!fauth || !fauth->ptype & PACKET_TYPE_SIG_FAUTH) {
        return ;
    }

    uint64_t	sessionID = PACPFlowAuth::getSessionID(fauth);
    logger << LOG_L(LOG_DEBUG) << "\nFlowManager: Received a FlowAuth Request with SID=" << sessionID << "\n";

    if(conf->getUseCryptoControl()) {
        kmKey_t*	key = _keyManager->findKey(IPV6Packet::getSrc(fauth));

        if(!key) {
            logger << LOG_L(LOG_DEBUG) << "FlowManager: FlowAuth from unknown Host. Discarding!\n";
            return;
        }

        try {
            if(!PACPFlowAuth::verifySig(fauth, key)) {
                logger << LOG_L(LOG_WARNING) << "FlowManager: Signature Verification FAILED!\n";
                return;

            } else {
                logger << LOG_L(LOG_WARNING) << "FlowManager: Signature verification OK!\n";
            }

        } catch (Exception e) {
            logger << LOG_L(LOG_WARNING) << "FlowManager: Signature Verification FAILED!\n";
            e.print();
            return;
        }
    }

    pktCmn_t*	response = PACPFlowAuthResponse::alloc();
    PACPFlowAuthResponse::setSessionID(response, sessionID);
    timeval tv;
    gettimeofday(&tv, NULL);

    if(Packet::sameNet(PACPFlowAuth::getSessionSrc(fauth), conf->getNetworkAdhocAddress())) {
        kmKey_t*	key = _keyManager->findKey(PACPFlowAuth::getSessionSrc(fauth));

        if(!key) {
            logger << LOG_L(LOG_DEBUG) << "FlowManager:: Src node is Internal but not Registered! Should be blocked\n";
            PACPFlowAuthResponse::setCode(response, SESSION_AUTH_ALLOWED);
            PACPFlowAuthResponse::setIssueTime(response, tv.tv_sec);
            PACPFlowAuthResponse::setExpireTime(response, tv.tv_sec + 600 * 2);
            PACPFlowAuthResponse::setStartTime(response, tv.tv_sec - 600);

        } else {
            logger << LOG_L(LOG_DEBUG) << "FlowManager:: Src node is Internal and is Registered! Allowing\n";
            PACPFlowAuthResponse::setCode(response, SESSION_AUTH_ALLOWED);
            PACPFlowAuthResponse::setIssueTime(response, tv.tv_sec);
            PACPFlowAuthResponse::setExpireTime(response, tv.tv_sec + 3600 * 2);
            PACPFlowAuthResponse::setStartTime(response, tv.tv_sec - 600);
//			if(PACPFlowAuth::getRequestKey(fauth)){
            PACPFlowAuthResponse::setKey(response, key);
//			}
        }

    } else {
        logger << LOG_L(LOG_DEBUG) << "FlowManager:: Src node is External! Allowing\n";
        PACPFlowAuthResponse::setCode(response, SESSION_AUTH_ALLOWED);
        PACPFlowAuthResponse::setIssueTime(response, tv.tv_sec);
        PACPFlowAuthResponse::setExpireTime(response, tv.tv_sec + 3600 * 2);
        PACPFlowAuthResponse::setStartTime(response, tv.tv_sec - 600);
//			if(PACPFlowAuth::getRequestKey(fauth)){
        PACPFlowAuthResponse::setKey(response, _keyManager->_hostKey);
//			}
    }

    PACPFlowAuthResponse::pack(response);

    if(conf->getUseCryptoControl()) {
        PACPFlowAuthResponse::sign(response, _keyManager->_hostKey);
    }

    //Send response to reporting node
    uint16_t len = 0;
    uint8_t*	buffer = PACPFlowAuthResponse::getBuffer(response, &len);
    sessionID = PACPFlowAuthResponse::getSessionID(response);
    logger << LOG_L(LOG_DEBUG) << "\nFlowManager: Sending FlowAuth Response with Code=" << PACPFlowAuthResponse::getCode(response) << " SID=" << sessionID << "\n";
    _pHandler->sendto(buffer, len, 0, (sockaddr*) fauth->ipv6sock, sizeof(sockaddr_in6));
    //Packet sent. Now lets process what we got
}
