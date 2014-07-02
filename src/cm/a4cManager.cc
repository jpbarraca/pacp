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


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <packet.h>
#include "packetHandler.h"
#include "a4cManager.h"
#include "keyManager.h"
#include "exception.h"
#include "debug.h"

A4CManager::A4CManager(PacketHandler* p, KeyManager* km) {
    _pHandler = p;
    _keyManager = km;
}

A4CManager::~A4CManager() {
}

void A4CManager::processPacket(pktCmn_t* p) {
    if (!p || !p->ptype & PACKET_TYPE_SIG_SINIT) {
        return ;
    }

    logger << LOG_L(LOG_DEBUG) << "A4CManager: Received a Session Init\n";
    PACPSessionInit::decipherSimRSA(p, _keyManager->_opKey);
    uint8_t	sl = 0;
    uint8_t* secret  = PACPSessionInit::getSecret(p, &sl);

//	uint8_t	ul = 0;
    //uint8_t* uid = PACPSessionInit::getUID(p,&ul);

    if(strncmp((const char*) secret, "secret", sl)) {
        int i;

        if(conf->getLogLevel() >= LOG_WARNING) {
            fprintf(stderr, "A4CManager::processPacket: Secret Failed Verification!\n");
        }

        if(conf->getLogLevel() >= LOG_DEBUG) {
            fprintf(stderr, "A4CManager::processPacket: Provided Secret: <");

            for(i = 0; i < sl; i++)
                if(secret[i] >= ' ' && secret[i] <= 'z') {
                    fprintf(stderr, "%c", secret[i]);

                } else {
                    fprintf(stderr, ":%X:", (uint8_t) secret[i]);
                }

            fprintf(stderr, ">\n");
        }

        return;

    } else {
        logger << LOG_L(LOG_DEBUG) << "A4CManager::processPacket: User authenticated!\n";
    }

    try {
        kmKey_t* hostKey = PACPSessionInit::getKey(p);
        _keyManager->setKey(IPV6Packet::getSrc(p), hostKey);
        _keyManager->setKey(PACPSessionInit::getAddress(p), hostKey);
        pktCmn_t* response = PACPSessionInitResponse::alloc();
        PACPSessionInitResponse::setCode(response, PKTSINITRESP_CODE_ALLOWED);
        PACPSessionInitResponse::setSharedSecret(response, (uint8_t*) "secret", strlen("secret"));
        PACPSessionInitResponse::pack(response);

        if(hostKey && conf->getUseCryptoControl() ) {
            PACPSessionInitResponse::cipher(response, hostKey);
            PACPSessionInitResponse::sign(response, _keyManager->_hostKey);

        } else {
            logger << LOG_L(LOG_WARNING) << "\nA4CManager:: Sending SessionInitResponse in clear text!\n";
        }

        //Send response to reporting node
        uint16_t len = 0;
        uint8_t*  buffer = PACPSessionInitResponse::getBuffer(response, &len);
        p->ipv6sock->sin6_port = ntohs(conf->getSignallingPort());
        _pHandler->sendto(buffer, len, 0, (sockaddr*) p->ipv6sock, sizeof(sockaddr_in6));
        Packet::free(response);

    } catch (Exception e) {
        e.print();
        return;
    }
}
