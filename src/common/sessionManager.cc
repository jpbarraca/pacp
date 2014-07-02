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


#include <sessionManager.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <exception.h>
#include "packetHandler.h"
#include "keyManager.h"

SessionManager::SessionManager(Timer* t, PacketHandler* ph, KeyManager* km) {
    srand(time(NULL));
    _timer = t;
    _pHandler = ph;
    _km = km;
}

SessionManager::~SessionManager() {
    //TODO: clean the hash table
}

session_t* SessionManager::findSession(uint64_t hash) {
    hash_map<uint64_t, session_t*, sHash, sEqual>::iterator sit = _sessionTable.find(hash);

    if (sit == _sessionTable.end()) {
        return NULL;
    }

    return (*sit).second;
}

session_t* SessionManager::findSession(pktCmn_t* packet) {
    uint64_t key = sHash::ip6Hash(&packet->ipv6hdr->ip6_src, &packet->ipv6hdr->ip6_dst);
    hash_map<uint64_t, session_t*, sHash, sEqual>::iterator sit = _sessionTable.find(key);

    if (sit == _sessionTable.end()) {
        return NULL;
    }

    return (*sit).second;
}

session_t* SessionManager::createSession(pktCmn_t* packet) {
    session_t* s = new session_t;
    memcpy(&s->srcHost, &packet->ipv6hdr->ip6_src, sizeof(in6_addr));
    memcpy(&s->dstHost, &packet->ipv6hdr->ip6_dst, sizeof(in6_addr));
    s->hash = sHash::ip6Hash(&s->srcHost, &s->dstHost);
    s->asHash = true;
    s->direction = Packet::getDirection(packet);
    s->sequence = rand();
    s->index = 0;
    s->timer = NULL;
    s->status = SESSION_STATUS_UNKNOWN;
    s->token.code = SESSION_AUTH_UNKNOWN;
    s->authRTXKey = 0;
    s->tokenTimerKey = 0;
    s->paTimerKey = 0;
    s->lastFlowAuth = NULL;
    s->lastFlowAuthLength = 0;
    _sessionTable[s->hash] = s;
    return s;
}

uint32_t	SessionManager::authorizeSession(session_t* session, pktCmn_t* packet) {
    if(!session) {
        MYTHROW1("Error with parameters");
    }

    timeval tv;
    gettimeofday(&tv, NULL);

    if(!conf->getAuthEnabled()) {
        return SESSION_AUTH_ALLOWED;
    }

    //Is the token still valid?
    switch(session->token.code) {
        case SESSION_AUTH_ALLOWED:
        case SESSION_AUTH_BLOCK : {
            //					if(session->token.expireTime >= (unsigned long) tv.tv_sec && session->token.startTime <= (unsigned long) tv.tv_sec)
            return session->token.code;
            /*					else{
            						logger<<LOG_L(LOG_DEBUG)<<"SessionManager::AuthorizeSession: Flow Expired!\n";
            						if(queuePacket(session,packet) == SESSION_QUEUE_FULL)	{
            								packet->verdict = PACKET_VERDICT_DROP;
            						}else{
            								packet->verdict = PACKET_VERDICT_QUEUE;
            						}
            						return requestFlowAuth(session,packet);
            					}
            */
        }

        case SESSION_AUTH_ONGOING: {
            if(queuePacket(session, packet) == SESSION_QUEUE_FULL)	{
                packet->verdict = PACKET_VERDICT_DROP;

            } else {
                packet->verdict = PACKET_VERDICT_QUEUE;
            }

            return SESSION_AUTH_ONGOING;
        }

        default: {
            uint32_t ret =  requestFlowAuth(session, packet);

            if(queuePacket(session, packet) == SESSION_QUEUE_FULL)	{
                packet->verdict = PACKET_VERDICT_DROP;

            } else {
                packet->verdict = PACKET_VERDICT_QUEUE;
            }

            return ret;
        }
    }
}

uint32_t SessionManager::queuePacket(session_t* session, pktCmn_t* packet) {
    if(!session) {
        return SESSION_ERROR;
    }

    if(session->queue.size() < SESSION_QUEUE_MAXSIZE) {
        session->queue.push(packet);
        return SESSION_QUEUE_OK;
    }

    return SESSION_QUEUE_FULL;
}

pktCmn_t* SessionManager::dequeuePacket(session_t* session) {
    if(!session) {
        return NULL;
    }

    if(session->queue.empty()) {
        return NULL;
    }

    pktCmn_t* p = session->queue.front();
    session->queue.pop();
    return p;
}

//Used to renew a token
uint32_t	SessionManager::requestFlowAuth(session_t* session) {
    if(!session) {
        return SESSION_AUTH_UNKNOWN;
    }

    if(!session->lastFlowAuth || !session->lastFlowAuthLength) {
        return SESSION_AUTH_UNKNOWN;
    }

    in6_addr*  pm = conf->getDefaultChargingManager();
    _timer->addRTXEvent(this, *pm, 0, PACKET_RTX_COUNT, PACKET_RTX_DELAY, session->lastFlowAuth, session->lastFlowAuthLength, (uint8_t*) &session->hash, sizeof(uint64_t));
    return SESSION_AUTH_ONGOING;
}


uint32_t	SessionManager::requestFlowAuth(session_t* session, pktCmn_t* packet) {
    if(!session || !packet) {
        return SESSION_AUTH_UNKNOWN;
    }

    if(session->token.code == SESSION_AUTH_ONGOING) {
        return SESSION_AUTH_ONGOING;
    }

    pktCmn_t*	p = PACPFlowAuth::alloc();
    kmKey_t* key = _km->findKey(IPV6Packet::getSrc(packet));

    if(!key) {
        PACPFlowAuth::setRequestKey(p, true);

    } else {
        PACPFlowAuth::setRequestKey(p, false);
    }

    PACPFlowAuth::setSessionID(p, session->hash);
    PACPFlowAuth::setSessionSrc(p, IPV6Packet::getSrc(packet));
    PACPFlowAuth::setSessionDst(p, IPV6Packet::getDst(packet));

    if(packet->ptype & PACKET_TYPE_DATA_TCP) {
        PACPFlowAuth::setProto(p, IPPROTO_TCP);
        PACPFlowAuth::setDPort(p, TCPPacket::getDstPort(packet));
        PACPFlowAuth::setSPort(p, TCPPacket::getSrcPort(packet));

    } else {
        PACPFlowAuth::setProto(p, IPPROTO_UDP);
        PACPFlowAuth::setDPort(p, UDPPacket::getDstPort(packet));
        PACPFlowAuth::setSPort(p, UDPPacket::getSrcPort(packet));
    }

    PACPFlowAuth::pack(p);

    if(conf->getUseCryptoControl()) {
        PACPFlowAuth::sign(p, _km->_hostKey);
    }

    //Send packet
    in6_addr*  pm = conf->getDefaultChargingManager();
    uint16_t	len = 0;
    uint8_t*	buffer = PACPFlowAuth::getBuffer(p, &len);

    if(len) {
        uint8_t* buf = new uint8_t[len];
        memcpy(buf, buffer, len);
        session->lastFlowAuth = buf;
        session->lastFlowAuthLength = len;

    } else {
        session->lastFlowAuth = NULL;
        session->lastFlowAuthLength = 0;
    }

    session->token.code = SESSION_AUTH_ONGOING;
    logger << LOG_L(LOG_DEBUG) << "SessionManager: Requesting Flow Auth with len " << len << ". SID=" << session->hash << "\n";
    session->authRTXKey = _timer->addRTXEvent(this, *pm, 0, PACKET_RTX_COUNT, PACKET_RTX_DELAY, buffer, len, (uint8_t*) &session->hash, sizeof(uint64_t));
    return SESSION_AUTH_ONGOING;
    Packet::free(p);
}



uint32_t	SessionManager::processFlowAuthResponse(pktCmn_t* p) {
    if(!p || !p->ptype & PACKET_TYPE_SIG_FAUTH_RESP) {
        return SESSION_AUTH_UNKNOWN;
    }

    session_t* s = NULL;
    uint64_t sid = 0;
    sid = PACPFlowAuthResponse::getSessionID(p);
    s = findSession(sid);

    if(!s) {
        logger << LOG_L(LOG_DEBUG) << "SessionManager: Session Not found: " << sid << "\n";
        return SESSION_AUTH_UNKNOWN;

    } else {
        logger << LOG_L(LOG_DEBUG) << "SessionManager: Session FOUND: " << sid << "\n";
    }

    if(conf->getUseCryptoControl()) {
        if(!PACPFlowAuthResponse::verifySig(p, _km->_opKey)) {
            logger << LOG_L(LOG_ERROR) << "SessionManager: FlowAuthResponse Signature verification failed\n";
            return SESSION_AUTH_UNKNOWN;

        } else {
            logger << LOG_L(LOG_DEBUG) << "SessionManager: FlowAuthResponse Signature verification OK\n";
        }

        //Check if we are the initiator
        if(s->direction != PACKET_DIRECTION_OUT) {
            kmKey_t* key =  PACPFlowAuthResponse::getKey(p);

            if(key) {
                _km->setKey(&s->srcHost, key);
            }
        }
    }

    _timer->cancelRTXEvent(s->authRTXKey);
    s->token.code = PACPFlowAuthResponse::getCode(p);
    s->token.issueTime = PACPFlowAuthResponse::getIssueTime(p);
    s->token.startTime = PACPFlowAuthResponse::getStartTime(p);
    s->token.expireTime = PACPFlowAuthResponse::getExpireTime(p);
    logger << LOG_L(LOG_DEBUG) << "SessionManager: Flow Token: Code:" << s->token.code << " IT:" << s->token.issueTime << " ST:" << s->token.startTime << " ET:" << s->token.expireTime << "\n";
    uint32_t	code = s->token.code;
    pktCmn_t*	qp = NULL;

    while((qp = dequeuePacket(s)) != NULL) {
        _pHandler->insert(qp);
    }

    return code;
}

void SessionManager::eventExpired(uint64_t key, uint8_t type, uint8_t* buffer, uint32_t bufLength) {
    switch(type) {
        case EVENT_TYPE_TIMER:
            timerExpired(key, buffer, bufLength);
            return;

        case EVENT_TYPE_RTX:
            packetExpired(key, buffer, bufLength);
            return;
    }
}


//Timer expired. Time to renew token:)
void	SessionManager::timerExpired(uint64_t key, uint8_t* buffer, uint32_t bufLength) {
    if(!buffer || !bufLength || !_pHandler) {
        return;
    }

    session_t* s = findSession(*(uint64_t*) buffer);

    if(!s) {
        return;
    }

    //this will require a flow auth
    requestFlowAuth(s);
};


//Timeout... No response from A4C
void	SessionManager::packetExpired(uint64_t key, uint8_t* buffer, uint32_t bufLength) {
    if(!buffer || !bufLength || !_pHandler) {
        return;
    }

    session_t* s = findSession(*(uint64_t*) buffer);

    if(!s) {
        return;
    }

    s->token.code = SESSION_AUTH_UNKNOWN;
};



