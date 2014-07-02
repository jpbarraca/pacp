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


#include "timer.h"
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include "exception.h"
#include "configuration.h"
#include "packetHandler.h"

Timer::Timer(PacketHandler* p) {
    pthread_mutex_init(&_mutTimer, NULL);
    pthread_mutex_init(&_mutRTXRun, NULL);
    _run = true;
    _running = false;
    _nextTime = 0xFFFFFFFF;
    _lastKey = 1;
    _numRTXEvents = 0;
    _pHandler = p;
    pthread_cond_init(&_condRTXRun, NULL);
    pthread_create(&_thrTimer, NULL, threadFunc, this);

    if(!p) {
        if ((_socket = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            MYTHROW2("Cannot open socket", strerror(errno));

        } else {
            /*
            		in6_addr  addr;
            		memset(&addr,0,sizeof(in6_addr));
            		sockaddr_in6 sock;
            		sock.sin6_addr=addr;
            		sock.sin6_family=AF_INET6;
            		sock.sin6_port=htons(conf->getSignallingPort());
            		if( bind(_socket,(sockaddr*) &sock,sizeof(sock)) < 0 ){
            			cerr<<"Cannot bind to socket: "<<strerror(errno)<<endl;
            			throw new Exception();
            		}
            */
        }
    }
}


Timer::~Timer() {
}


void* Timer::run(void*) {
//	logger << LOG_L(LOG_DEBUG) << "Timer Loop started\n";
    bool tosleep = true;
    timeval tv;

    while (_run) {
        pthread_mutex_lock(&_mutTimer);

        if (getNumRTXEventsNL() == 0  && _eventTimerQueue.size() == 0) {
            pthread_mutex_unlock(&_mutTimer);
//			logger << LOG_L(LOG_DEBUG) << "Timer locked\n";
            pthread_mutex_lock(&_mutRTXRun);

            if(!_running) {
                _running = true;
            }

            pthread_cond_wait(&_condRTXRun, &_mutRTXRun);
            pthread_mutex_unlock(&_mutRTXRun);
//			logger << LOG_L(LOG_DEBUG) << "Timer unlocked\n";

            if (!_run) {
//				logger << LOG_L(LOG_DEBUG) << "Timer: Exiting from loop\n";
                break;
            }

        } else {
//			logger << LOG_L(LOG_DEBUG) << "Timer: Getting Next event\n";
            event_t*	event = getNextEventNL();

            if (event != NULL) {
//				logger << LOG_L(LOG_DEBUG) << "Timer: Got an event\n";
                //Find if the retries exceed the maximum
                if (event->maxRetries != (uint64_t) - 1 && event->retries >= event->maxRetries ) {
//					logger << LOG_L(LOG_DEBUG) << "Timer: Event Expired. eSends=" << event->retries << " Max=" << event->maxRetries << "\n";
                    TimerClient* client = NULL;

                    if(event->type == EVENT_TYPE_RTX) {
                        rtxEvent_t* rtxe = (rtxEvent_t*) event;
                        client = rtxe->timerClient;
                        uint64_t	eventID = rtxe->eventID;
                        uint8_t*		buffer = NULL;

                        if(rtxe->bufLength) {
                            buffer = new uint8_t[rtxe->bufLength];
                        }

                        uint32_t	bufferLength = rtxe->bufLength;
                        memcpy(buffer, rtxe->buffer, bufferLength);
                        cancelRTXEventNL(eventID);
                        pthread_mutex_unlock(&_mutTimer);
                        client->eventExpired(eventID, EVENT_TYPE_RTX, buffer, bufferLength);

                        if(buffer) {
                            delete [] buffer;
                        }

                    } else {
                        timerEvent_t* tmre = (timerEvent_t*) event;
                        client = tmre->timerClient;
                        client = tmre->timerClient;
                        uint64_t	eventID = tmre->eventID;
                        uint8_t*		buffer = NULL;

                        if(tmre->bufLength) {
                            buffer = new uint8_t[tmre->bufLength];
                        }

                        uint32_t	bufferLength = tmre->bufLength;
                        memcpy(buffer, tmre->buffer, bufferLength);
                        cancelTimerEventNL(eventID);
                        pthread_mutex_unlock(&_mutTimer);
                        client->eventExpired(eventID, EVENT_TYPE_TIMER, buffer, bufferLength);

                        if(buffer) {
                            delete [] buffer;
                        }
                    }

//					logger << LOG_L(LOG_DEBUG) << "Timer: Event Expired. Client Notified\n";

                } else {
                    gettimeofday(&tv, NULL);
                    uint64_t	currTime = ((uint64_t) tv.tv_sec * 1000000) + tv.tv_usec;

//					logger << LOG_L(LOG_DEBUG) << "Timer: Event Triggering \n";

                    if ( event->expireTime && (event->expireTime / TIMER_MAX_RES > currTime / TIMER_MAX_RES)   ) { //Wait until next event or a new signal
                        pthread_mutex_unlock(&_mutTimer);
                        timespec tsp;
                        tsp.tv_sec = event->expireTime / 1000000;
                        tsp.tv_nsec = (event->expireTime % 1000000) * 1000;
//						logger << LOG_L(LOG_DEBUG) << "Timer: Waiting " << tsp.tv_sec - (currTime / 1000000)  << "s "<< tsp.tv_nsec / 1000 << "us\n";
                        //Mutex lock
                        pthread_mutex_lock(&_mutRTXRun);
                        int status = pthread_cond_timedwait(&_condRTXRun, &_mutRTXRun, &tsp);
                        pthread_mutex_unlock(&_mutRTXRun);

                        if (status == ETIMEDOUT) {
//							logger << LOG_L(LOG_DEBUG) << "Timer: Awaking with timeout\n";
                        } else {
//							logger << LOG_L(LOG_DEBUG) << "Timer: Awaking with interruption\n";
                            continue;
                        }

                    } else {
                        //Clock is completelly out of sinc! Updating.
                        gettimeofday(&tv, NULL);
                        currTime = ((uint64_t) tv.tv_sec * 1000000) + tv.tv_usec;

                        if (event->type == EVENT_TYPE_RTX) {
//							logger << LOG_L(LOG_DEBUG) << "Timer: Sending Packet\n";
                            event->retries++;
                            event->expireTime = currTime + event->expireDelay;
                            sendEvent((rtxEvent_t*) event);
                            pthread_mutex_unlock(&_mutTimer);

                        } else {
//							logger << LOG_L(LOG_DEBUG) << "Timer: Timer Event Triggered\n";
                            timerEvent_t* tmre = (timerEvent_t*) event;
                            tmre->retries++;
                            tmre->expireTime = currTime + tmre->expireDelay;
                            pthread_mutex_unlock(&_mutTimer);
                            tmre->timerClient->eventExpired(tmre->eventID, EVENT_TYPE_TIMER, tmre->buffer, tmre->bufLength);
                        } //End if

                        tosleep = true;
                    }
                }
            }
        }
    }

    return NULL;
}

uint64_t Timer::addTimerEvent(TimerClient* client, uint64_t expireTime, int64_t count, uint64_t expireDelay, uint8_t* buffer, uint32_t bufferLength ) {
    if (!client) {
        return 0;
    }

    pthread_mutex_lock(&_mutTimer);

    if(!_running) {
        int retries = 0;

        while(!_running && retries < 10) {
            pthread_mutex_unlock(&_mutTimer);
            sleep(1);
            retries++;
            pthread_mutex_lock(&_mutTimer);
        }

        if(!_running) {
            pthread_mutex_unlock(&_mutTimer);
            MYTHROW1("Timer Loop not ready after timeout");
        }
    }

    uint64_t key = ++_lastKey;

    while(_keyMap.find(key) != _keyMap.end() && key != 0) {
        key++;
    }

    _keyMap[key] = true;
    timeval tv;
    gettimeofday(&tv, NULL);
//	logger << LOG_L(LOG_DEBUG) << "Timer: AddTimerEvent:  Delay=" << expireDelay << " Key="<<key<<"\n";
    uint64_t currTime = ((uint64_t) tv.tv_sec * 1000000) + tv.tv_usec;
    timerEvent_t* event = new timerEvent_t;

    if(!event) {
        MYTHROW1("Error Allocating Memory!");
    }

    event->type = EVENT_TYPE_TIMER;
    event->timerClient = client;
    event->eventID = key;
    event->expireTime = expireTime + currTime;
    event->expireDelay = expireDelay;
    event->expireIncrease = 0;
    event->maxRetries = count;
    event->retries = 0;

    if(buffer && bufferLength)	{
        event->buffer = new uint8_t[bufferLength];

        if(!event->buffer) {
            MYTHROW1("Error Allocating Memory!");
        }

        memcpy(event->buffer, buffer, bufferLength);
        event->bufLength = bufferLength;

    } else {
        event->buffer = NULL;
        event->bufLength  = 0;
    }

    _eventTimerQueue.push_back(event);
    pthread_mutex_unlock(&_mutTimer);
//	logger << LOG_L(LOG_DEBUG) << "Timer: Signalling timer loop\n";
    pthread_cond_signal(&_condRTXRun);
    return key;
}


uint64_t Timer::addRTXEvent(TimerClient* client, in6_addr& dst, uint64_t expireTime,  uint64_t count, uint64_t rtxDelay, uint8_t* payload, uint16_t payloadLength, uint8_t* buffer, uint32_t bufLength) {
    if (!payload || !payloadLength) {
        MYTHROW1("AddRTXEvent without Payload!!");
        return 0;
    }

    pthread_mutex_lock(&_mutTimer);
    uint64_t	key = ++_lastKey;

    while(_keyMap.find(key) != _keyMap.end() && key != 0) {
        key++;
    }

    _keyMap[key] = true;

    if(!_running) {
        int retries = 0;

        while(!_running && retries < 10) {
            pthread_mutex_unlock(&_mutTimer);
            sleep(1);
            retries++;
            pthread_mutex_lock(&_mutTimer);
        }

        if(!_running) {
            pthread_mutex_unlock(&_mutTimer);
            MYTHROW1("Timer Loop not ready after timeout");
        }
    }

    timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t	currTime = ((uint64_t) tv.tv_sec * 1000000) + tv.tv_usec;
    logger << LOG_L(LOG_DEBUG) << "Timer: Adding a RTX Event with key=" << key << "\n";
    rtxEvent_t* event = new rtxEvent_t;
    event->type = EVENT_TYPE_RTX;
    event->timerClient = client;
    event->eventID = key;
    event->retries = 0;
    event->maxRetries = count;
    event->lastSend = 0;
    event->expireTime = currTime + expireTime;
    event->expireDelay = rtxDelay;
    event->expireIncrease = 0;
    memcpy(&event->dstAddress, &dst, sizeof(in6_addr));
    event->buffer = new uint8_t[bufLength];
    memcpy(event->buffer, buffer, bufLength);
    event->bufLength = bufLength;
    memcpy(&event->dstAddress, &dst, sizeof(in6_addr));
    event->payload = new uint8_t[payloadLength];
    memcpy(event->payload, payload, payloadLength);
    event->payloadLength = payloadLength;
    memcpy(&event->dstAddress, &dst, sizeof(in6_addr));
    insertRTXEventNL(event);
    logger << LOG_L(LOG_DEBUG) << "Timer: Signalling Timer loop\n";
    pthread_cond_signal(&_condRTXRun);
    pthread_mutex_unlock(&_mutTimer);
    return key;
}

void Timer::insertRTXEventNL(rtxEvent_t* event) {
    if(!event) {
        return;
    }

    vector<tHost_t*>::iterator itHost = _hostQueue.begin();
    tHost_t*	host = NULL;

    while(itHost != _hostQueue.end()) {
        if(!memcmp(&event->dstAddress, &(*itHost)->address, sizeof(in6_addr))) {
            host = *itHost;
            break;
        }

        itHost++;
    }

    if(!host) {
        host = new tHost_t;
        memcpy(&host->address, &event->dstAddress, sizeof(in6_addr));
        _hostQueue.push_back(host);
    }

    incNumRTXEventsNL();
    host->queue.push_back(event);
    return;
}


event_t* Timer::getNextEvent() {
    pthread_mutex_lock(&_mutTimer);
    event_t* e = getNextEventNL();
    pthread_mutex_unlock(&_mutTimer);
    return e;
}

event_t* Timer::getNextEventNL() {
    //Find next Event in rtxevents
    timerEvent_t*	et = NULL;
    rtxEvent_t*	rt = NULL;

    if(_eventTimerQueue.size() > 0) {
        et = getNextTimerEventNL();
    }

    if(getNumRTXEventsNL() > 0) {
        rt = getNextRTXEventNL();
    }

    if(!et && !rt) {
        return (event_t*) NULL;
    }

    if(!et) {
        return (event_t*) rt;
    }

    if(!rt) {
        return (event_t*) et;
    }

    if(et->expireTime > rt->expireTime) {
        return (event_t*) rt;

    } else {
        return (event_t*) et;
    }
}


timerEvent_t*	Timer::getNextTimerEventNL() {
    vector<timerEvent_t*>::iterator	itTimer = _eventTimerQueue.begin();
    timerEvent_t* event = *_eventTimerQueue.begin();

    while(itTimer != _eventTimerQueue.end()) {
        if(event->expireTime > (*itTimer)->expireTime) {
            event = *itTimer;
        }

        itTimer++;
    }

    return event;
}

rtxEvent_t*	Timer::getNextRTXEventNL() {
    if(!getNumRTXEventsNL()) {
        return NULL;
    }

    vector<tHost_t*>::iterator	itHost = _hostQueue.begin();
    rtxEvent_t* event = NULL;

    while(itHost != _hostQueue.end()) {
        tHost_t* host = *itHost;
        vector<rtxEvent_t*>::iterator itEvent = host->queue.begin();

        while(itEvent != host->queue.end()) {
            if(!event) {
                event = *itEvent;

            } else if((*itEvent)->expireTime < event->expireTime) {
                event = (*itEvent);
            }

            itEvent++;
        }

        itHost++;
    }

    return event;
}


void Timer::sendEvent(rtxEvent_t* event) {
    struct sockaddr_in6	sa;
    memset(&sa, 0, sizeof(struct sockaddr_in6));
    memcpy(&sa.sin6_addr, &event->dstAddress, sizeof(in6_addr));
    sa.sin6_port = htons(conf->getSignallingPort());
    sa.sin6_family = AF_INET6;
    int ret = 0;

    if(_pHandler) {
        ret = _pHandler->sendto(event->payload, event->payloadLength, 0, (struct sockaddr*) & sa, sizeof(sa));

    } else {
        ret = sendto(_socket, event->payload, event->payloadLength, 0, (struct sockaddr*) & sa, sizeof(sa));
    }

    logger << LOG_L(LOG_DEBUG) << "Timer: Packet sent with ret=" << ret << "\n";
}


uint32_t Timer::cancelEventNL(event_t* event) {
    if(!event) {
        return EVENT_NOTFOUND;
    }

    if(event->type == EVENT_TYPE_RTX) {
        return cancelRTXEventNL(event->eventID);

    } else {
        return cancelTimerEventNL(event->eventID);
    }
}

uint32_t Timer::cancelEventNL(uint64_t eventID) {
    uint32_t status = cancelRTXEventNL(eventID);

    if(status != EVENT_OK) {
        status = cancelTimerEventNL(eventID);
    }

    if (status != EVENT_OK) {
        logger << LOG_L(LOG_DEBUG) << "Timer: Could not find the event to delete\n";
        return EVENT_NOTFOUND;

    } else {
        pthread_cond_signal(&_condRTXRun);	//Awaking Main loop because queue as changed.
        return EVENT_OK;
    }
}

uint32_t	Timer::cancelRTXEvent( uint64_t eventID) {
    pthread_mutex_lock(&_mutTimer);
    uint32_t status = cancelRTXEventNL(eventID);
    pthread_mutex_unlock(&_mutTimer);
    return status;
}



uint32_t	Timer::cancelRTXEventNL( uint64_t eventID) {
    vector<tHost_t*>::iterator	itHost = _hostQueue.begin();
    //tHost_t* host = *_hostQueue.begin();
    logger << LOG_L(LOG_DEBUG) << "Timer:: CancelRTXEventNL: " << eventID << "\n";

    while(itHost != _hostQueue.end()) {
        if(!(*itHost)->queue.size()) {
            continue;
        }

        vector<rtxEvent_t*>::iterator itRTX = (*itHost)->queue.begin();

        while( itRTX != (*itHost)->queue.end()) {
            rtxEvent_t* event = *itRTX;

            if( event->eventID == eventID ) {
                if(event->buffer) {
                    delete [] event->buffer;
                }

                if(event->payload) {
                    delete [] event->payload;
                }

                delete event;
                (*itHost)->queue.erase(itRTX);
                decNumRTXEventsNL();
                _keyMap.erase(eventID);
                logger << LOG_L(LOG_DEBUG) << "Timer:: Event " << eventID << " Found\n";
                return EVENT_OK;
            }

            itRTX++;
        }

        itHost++;
    }

    logger << LOG_L(LOG_DEBUG) << "Timer:: Event " << eventID << " Not Found\n";
    return EVENT_NOTFOUND;
}


uint32_t	Timer::cancelTimerEvent( uint64_t eventID) {
    pthread_mutex_lock(&_mutTimer);
    uint32_t status = cancelTimerEventNL(eventID);
    pthread_mutex_unlock(&_mutTimer);
    return status;
}

uint32_t	Timer::cancelTimerEventNL( uint64_t eventID) {
    vector<timerEvent_t*>::iterator	itTimer = _eventTimerQueue.begin();
    //timerEvent_t* event = *_eventTimerQueue.begin();

    while(itTimer != _eventTimerQueue.end()) {
        if((*itTimer)->eventID == eventID) {
            if((*itTimer)->buffer) {
                delete [] (*itTimer)->buffer;
            }

            delete *itTimer;
            (*itTimer) = NULL;
            _eventTimerQueue.erase(itTimer);
            _keyMap.erase(eventID);
            return EVENT_OK;
        }

        itTimer++;
    }

    return EVENT_NOTFOUND;
}
