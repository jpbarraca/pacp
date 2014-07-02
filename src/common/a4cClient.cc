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

#include "a4cClient.h"
#include "packet.h"
#include "packetHandler.h"
#include "exception.h"
#include "keyManager.h"

A4CClient::A4CClient(Timer* t, PacketHandler* p, KeyManager* km) {
    _timer = t;
    _pHandler = p;
    _status = A4CCLIENT_CONNECT_NOT;
    _connectKey = 0;
    _km = km;
}

A4CClient::~A4CClient() {
}


void A4CClient::connect(in6_addr* cm, uint32_t	delay) {
    if(!cm) {
        return;
    }

    if(!conf->getAuthEnabled()) {
        _status = A4CCLIENT_CONNECT_OK;
        return;
    }

    pktCmn_t* p = PACPSessionInit::alloc();
    _status = A4CCLIENT_CONNECT_ONGOING;
    PACPSessionInit::setAddress(p, conf->getMyAddress());
    PACPSessionInit::setUID(p, (uint8_t*) conf->getUserID().c_str(), conf->getUserID().length());
    PACPSessionInit::setSecret(p, (uint8_t*) conf->getUserSecret().c_str(), conf->getUserSecret().length());
    PACPSessionInit::setPUK(p, _km->_hostKey);
    PACPSessionInit::pack(p);
//	PACPSessionInit::sign(p,_km->_hostKey);
    PACPSessionInit::cipherSimRSA(p, _km->_hostKey, _km->_opKey);
    uint16_t	len = 0;
    uint8_t* 	buf = PACPSessionInit::getBuffer(p, &len);
    logger << LOG_L(LOG_INFO) << "A4CClient::connect: Connecting to CM in " << delay << "s\n";
    _connectKey = _timer->addRTXEvent(this, *cm, delay * 1000000, PACKET_RTX_COUNT, PACKET_RTX_DELAY, buf, len, (uint8_t*) cm, sizeof(in6_addr));
}


uint8_t	A4CClient::getConnectStatus() {
    return _status;
}


void A4CClient::eventExpired(uint64_t key, uint8_t et, uint8_t* buf, uint32_t bl) {
    logger << LOG_L(LOG_DEBUG) << "A4CClient::eventExpired: Type: " << (uint32_t) et << " Key=" << key << "\n";

    switch(et) {
        case EVENT_TYPE_RTX:
            expireRTX(key, buf, bl);
            break;

        case EVENT_TYPE_TIMER:
            expireTimer(key, buf, bl);
            break;

        default:
            logger << LOG_L(LOG_ERROR) << "A4CClient::eventExpired: UNKNOWN TYPE!!!\n";
    }
}


void A4CClient::expireRTX(uint64_t key, uint8_t* buf, uint16_t bl) {
    logger << LOG_L(LOG_WARNING) << "A4CClient::connect: Connecting Failed. Retrying in " << A4CCLIENT_RECONNECT_DELAY << "s\n";
    connect((in6_addr*) buf, A4CCLIENT_RECONNECT_DELAY);
}

void A4CClient::expireTimer(uint64_t key, uint8_t* buf, uint16_t bl) {
    logger << LOG_L(LOG_DEBUG) << "A4CClient::connect: Renewing Connecting\n";
    connect((in6_addr*) buf);
}

void A4CClient::responseReceived(pktCmn_t* p) {
    logger << LOG_L(LOG_DEBUG) << "A4CClient::connect: Session Init Response Received\n";

    if(p->ptype & PACKET_TYPE_CRYPTO) {
        if(conf->getUseCryptoControl()) {
            if(!PACPSessionInitResponse::verifySig(p, _km->_opKey)) {
                logger << LOG_L(LOG_ERROR) << "A4CClient:: Session Init Response Signature verification FAILED!\n";
                return;

            } else {
                PACPSessionInitResponse::decipher(p, _km->_hostKey);
                logger << LOG_L(LOG_DEBUG) << "A4CClient:: Session Init Response Signature verification PASSED!\n";
            }

        } else {
            logger << LOG_L(LOG_ERROR) << "A4CClient:: Session Init Response is Ciphered but Cryptography is disabled!\n";
            return;
        }
    }

    uint32_t code = PACPSessionInitResponse::getCode(p);

    switch(code) {
        case PKTSINITRESP_CODE_ALLOWED: {
            logger << LOG_L(LOG_INFO) << "A4CClient::responseReceived: Received ALLOW from Manager\n";
            _timer->cancelRTXEvent(_connectKey);
            _status = A4CCLIENT_CONNECT_OK;
            return;
        }

        case PKTSINITRESP_CODE_DENIED: {
            MYTHROW1("Manager Refused Authentication");
            return;
        }

        case PKTSINITRESP_CODE_ERROR:
            logger << LOG_L(LOG_WARNING) << "A4CClient::responseReceived: Received ERROR from Manager\n";
            return;;
    }

    logger << LOG_L(LOG_WARNING) << "A4CClient::responseReceived: UNKNOWN Code\n";
}
