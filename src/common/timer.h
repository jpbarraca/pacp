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


#ifndef _RTX_TIMER_H_
#define _RTX_TIMER_H_

#include <stdint.h>
#include <pthread.h>
#include <map>
#include <vector>
#include <netinet/ip6.h>
#include "threadFunc.h"
#include "log.h"

using namespace std;


#define EVENT_OK		 		0
#define EVENT_EXISTS 		1
#define EVENT_ERROR	 		2
#define EVENT_NOTFOUND 	3

#define RTXTIMER_RETRIE_DELAY	5 //In Secs!
#define RTXTIMER_SENDS_MAX		4			 //Number of retries

#define EVENT_TYPE_TIMER 	0
#define EVENT_TYPE_RTX		1

#define TIMER_MAX_RES	10000	//Maximum resolution for timers in usecs


class Configuration;
class PacketHandler;

extern Configuration* conf;
extern Log logger;

class TimerClient {

  public:
    virtual void eventExpired(uint64_t, uint8_t, uint8_t*, uint32_t) = 0;
};


typedef struct event_t {
    uint32_t	type;
    TimerClient* timerClient;
    uint64_t	eventID;

    uint64_t	retries;
    uint64_t	maxRetries;
    uint64_t	expireTime;
    uint64_t	expireDelay;
    uint64_t	expireIncrease;
};

typedef struct rtxEvent_t {
    uint32_t	type;
    TimerClient* timerClient;
    uint64_t	eventID;

    uint64_t	retries;
    int64_t		maxRetries;
    uint64_t	expireTime;
    uint64_t	expireDelay;
    uint64_t	expireIncrease;
    in6_addr	dstAddress;
    uint64_t	lastSend;
    uint8_t*	buffer;
    uint32_t	bufLength;

    uint8_t*	payload;
    uint16_t payloadLength;
};


typedef struct timerEvent_t {
    uint32_t	type;
    TimerClient* timerClient;
    uint64_t	eventID;

    uint64_t	retries;
    uint64_t	maxRetries;
    uint64_t	expireTime;
    uint64_t	expireDelay;
    uint64_t	expireIncrease;
    uint8_t*	buffer;
    uint32_t	bufLength;

};

typedef struct tHost_t {
    in6_addr	address;
    vector<rtxEvent_t*>	queue;
};

class Timer : ThreadFunc {

    struct in6lt {
        bool	operator()(const in6_addr& a, const in6_addr& b) const {
            return memcmp(&a, &b, sizeof(in6_addr));
        }

    };

  public:
    Timer(PacketHandler* p = NULL);
    virtual ~Timer();

    uint64_t addRTXEvent(TimerClient* client, in6_addr& dst, uint64_t expireTime,  uint64_t count, uint64_t rtxDelay, uint8_t* payload, uint16_t payloadLength, uint8_t* buffer, uint32_t bufLength);
    uint64_t addTimerEvent(TimerClient* client, uint64_t expireTime, int64_t count, uint64_t expireDelay, uint8_t* buffer, uint32_t bufferLength );


    uint32_t cancelEventNL(uint64_t);
    uint32_t cancelEventNL(event_t*);
    uint32_t cancelRTXEvent(uint64_t);
    uint32_t cancelRTXEventNL(uint64_t);
    uint32_t cancelTimerEvent(uint64_t);
    uint32_t cancelTimerEventNL(uint64_t);
    uint32_t cancelAllEvents();

  private:
    void* run(void*);
    timerEvent_t* getNextTimerEvent();
    timerEvent_t* getNextTimerEventNL();
    rtxEvent_t* getNextRTXEvent();
    rtxEvent_t* getNextRTXEventNL();
    inline uint32_t   getNumRTXEventsNL() {
        return _numRTXEvents;
    };
    inline void				incNumRTXEventsNL() {
        _numRTXEvents++;
    };
    inline void				decNumRTXEventsNL() {
        _numRTXEvents > 0 ? _numRTXEvents-- : _numRTXEvents = 0 ;
    };
    void							insertRTXEventNL(rtxEvent_t* event);

    event_t* getNextEvent();
    event_t* getNextEventNL();

    void	sendEvent(rtxEvent_t*);
    void delayRTXEvents(in6_addr*, uint32_t);

    bool	_run;
    bool	_running;

    pthread_mutex_t	_mutTimer;
    pthread_mutex_t	_mutRTXRun;
    pthread_cond_t	_condRTXRun;
    pthread_t	_thrTimer;

    uint32_t	_socket;
    uint64_t	_nextTime;
    uint64_t	_lastKey;
    uint32_t	_numRTXEvents;

//		vector< rtxEvent_t*>	_eventRTXQueue;
    vector<tHost_t*>			_hostQueue;
    vector<timerEvent_t*>	_eventTimerQueue;
    PacketHandler*	_pHandler;
    map<uint64_t, bool>	_keyMap;
};

#endif
