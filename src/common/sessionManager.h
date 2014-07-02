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


#ifndef _SESSION_MANAGER_H
#define _SESSION_MANAGER_H
#include <iostream>
#include <netinet/ip6.h>
#include <ext/hash_map>
#include "packet.h"
#include <timer.h>
#include <zlib.h>
#include <queue>
#include "hash.h"

//using namespace std;

#define SESSION_REPORT_INTERVAL 60000000	//msecs

#define SESSION_OK 					0
#define SESSION_ERROR 			1
#define SESSION_PARAM_ERROR	2

#define SESSION_QUEUE_OK		0
#define SESSION_QUEUE_ERROR 1
#define SESSION_QUEUE_FULL	2

#define SESSION_QUEUE_MAXSIZE 100

#define SESSION_STATUS_UNKNOWN  0
#define SESSION_STATUS_DROP		  1
#define SESSION_STATUS_ACTIVE   2
#define SESSION_STATUS_EXPIRE   4
#define SESSION_STATUS_BLOCK		8
#define SESSION_STATUS_QUEUE		16

#define SESSION_AUTH_UNKNOWN		0
#define SESSION_AUTH_ALLOWED		1
#define SESSION_AUTH_BLOCK			2
#define SESSION_AUTH_ONGOING		3

#define SESSION_POSITION_FIRST  0
#define SESSION_POSITION_MIDDLE 1
#define SESSION_POSITION_LAST		2

#define SESSION_DIRECTION_INT_IN  0
#define SESSION_DIRECTION_INT_OUT 1
#define SESSION_DIRECTION_INT_FWR 2
#define SESSION_DIRECTION_EXT_IN  3
#define SESSION_DIRECTION_EXT_OUT 4
#define SESSION_DIRECTION_EXT_FWR 5

using namespace __gnu_cxx;

typedef struct authToken_t {
    uint32_t	code;
    uint32_t	expireTime;
    uint32_t	startTime;
    uint32_t	issueTime;
};

typedef struct	session_t {
    //Auth
    authToken_t token;

    //Crypto
    uint64_t	lastSigFail;
    //Timer
    Timer*	timer;
    uint64_t	paTimerKey;			//PA Timer
    uint64_t	authRTXKey;			//Auth process RTX Timer
    uint64_t	tokenTimerKey;	//Auth token timer

    //Hashing

    bool	asHash;
    uint32_t	status;
    //General
    uint32_t	direction;
    uint32_t	lastPacketTime;
    uint32_t	position;
    uint8_t*	lastFlowAuth;
    uint16_t	lastFlowAuthLength;

    //Network
    in6_addr	cm;

    //IP
    in6_addr	srcHost;
    in6_addr	dstHost;

    //Charging
    uint8_t		code;
    uint16_t	sequence;
    uint8_t		index;
    uint64_t		hash;

    //Stats
    uint64_t	sentPackets;
    uint64_t	sentBytes;
    uint64_t	recvPackets;			//Total
    uint64_t	recvBytes;				//Total Packets received
    uint64_t	fwrdPackets;
    uint64_t	fwrdBytes;				//Total Bytes received

    std::queue<pktCmn_t*>	queue;
};

class PacketHandler;
class	KeyManager;

class SessionManager : public TimerClient {

  public:
    SessionManager(Timer*, PacketHandler*, KeyManager*);
    virtual ~SessionManager();

    session_t* findSession(pktCmn_t*);	//Find if a session already exists
    session_t* findSession(uint64_t);

    session_t* createSession(pktCmn_t*); //Creates a new session
    inline session_t* getSession(pktCmn_t* p) {
        session_t* session = findSession(p);

        if (!session) {
            return createSession(p);

        } else {
            return session;
        }
    }

    uint32_t	authorizeSession(session_t*, pktCmn_t*);
    uint32_t	requestSession(session_t*, pktCmn_t*);

    uint32_t	requestFlowAuth(session_t*, pktCmn_t*);
    uint32_t	processFlowAuthResponse(pktCmn_t*);

    uint32_t	queuePacket(session_t*, pktCmn_t*);

    pktCmn_t*	dequeuePacket(session_t*);

    void			eventExpired(uint64_t, uint8_t, uint8_t*, uint32_t);

  protected:
    uint32_t	requestFlowAuth(session_t*);
    void			timerExpired(uint64_t, uint8_t*, uint32_t);		//Timer expired. Time to check for tokens :)
    void			packetExpired(uint64_t, uint8_t*, uint32_t);		//Timeout... No response from A4C

    typedef struct sHash {
        static uint64_t	ip6Hash(in6_addr* a, in6_addr* b) {
            unsigned char	buffer[sizeof(in6_addr) * 2];
            memcpy(buffer, a, sizeof(in6_addr));
            memcpy(buffer + sizeof(in6_addr), a, sizeof(in6_addr));
            return fnv_64a_buf(buffer, sizeof(in6_addr) * 2, 0);
        }

        uint64_t	operator()( session_t* session) {
            if (session->asHash == false) {
                session->hash = ip6Hash(&session->srcHost, &session->dstHost);
                session->asHash = true;
            }

            return session->hash;
        }

        uint64_t operator()(uint64_t a) const {
            return a;
        }

    };

    typedef struct sEqual {
        bool operator()(uint64_t a, uint64_t b) {
            return a == b;
        }

        bool operator()(session_t* sA, session_t* sB) {
            if (!memcmp(&sA->srcHost, &sB->srcHost, sizeof(in6_addr))) {
                return (memcmp(&sA->dstHost, &sB->dstHost, sizeof(in6_addr)) == 0);
            }

            return true;
        }
    };

    //Hash table to store sessions
    hash_map<uint64_t, session_t*, sHash, sEqual>	_sessionTable;
    Timer*	_timer;
    PacketHandler* _pHandler;
    KeyManager* _km;
};

#endif
