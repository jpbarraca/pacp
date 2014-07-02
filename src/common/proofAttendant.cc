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


#include "log.h"
#include "sessionManager.h"
#include "packet.h"
#include "proofAttendant.h"
#include "sessionManager.h"
#include "timer.h"
#include <sys/time.h>
#include "exception.h"
#include <pthread.h>
#include "keyManager.h"

#define PA_SNPROOFS_TRIGGER		50
#define PA_REPORT_RETRIE_TIMEOUT	60*1000000 //60 seconds to a retransmit

ProofAttendant::ProofAttendant(Timer* t, KeyManager* km) {
    logger << LOG_L(LOG_DEBUG) << "ProofAttendant created\n";
    pthread_mutex_init(&_mutProofs, NULL);
    pthread_cond_init(&_condRun, NULL);
    _timer = t;
    _km = km;
    pthread_create(&_reportThread, NULL, threadFunc, this);
}

/*  In the future this should save
    the existing proofs to the permanent DB.

	 TODO: SAVE proofs to HD
*/

ProofAttendant::~ProofAttendant() {
    return;
    logger << LOG_L(LOG_DEBUG) << "Stopping ReportHandler:";
    _runReportHandler = false;
    pthread_cond_signal(&_condRun);
    logger << "Done\n";
    //Free all ProofManagers
    logger << LOG_L(LOG_DEBUG) << "Flushing ProofAttendant\n";
    pthread_mutex_lock(&_mutProofs);
    map<in6_addr, paProofManager_t*, in6lrt>::iterator itPM = _proofManagers.begin();

    while (itPM != _proofManagers.end()) {
        delete (*itPM).second;
        (*itPM).second = NULL;
        _proofManagers.erase(itPM);
        itPM++;
    }

    //Free all Sessions
    map<uint64_t, paSession_t*>::iterator itSession = _proofSessions.begin();

    while (itSession != _proofSessions.end()) {
        //Free  routes
        map<uint32_t, paRoute_t*>::iterator itRoute = (*itSession).second->routes.begin();

        while ( itRoute != (*itSession).second->routes.end()) {
            //Free  Proofs
            vector<paProof_t*>::iterator itProof = (*itRoute).second->proofs.begin();

            while (itProof != (*itRoute).second->proofs.end()) {
                delete *itProof;
                *itProof = NULL;
                (*itRoute).second->proofs.erase(itProof);
            } //Proofs

            delete (*itRoute).second;
            (*itRoute).second = NULL;
            (*itSession).second->routes.erase(itRoute);
            itRoute++;
        } //Routes

        delete (*itSession).second;
        (*itSession).second = NULL;
        _proofSessions.erase(itSession);
        itSession++;
    } //Sessions

    pthread_mutex_unlock(&_mutProofs);
}


/*
	Collect a proof for a later report

*/
void ProofAttendant::collectProof(in6_addr* proofManager, pktCmn_t* packet) {
    logger << LOG_L(LOG_DEBUG) << "Collecting Proof\n";

    if (!packet->session) {
        logger << LOG_L(LOG_ERROR) << "Cannot collect proof of packet w/o session or Charging Header\n";
        return ;
    }

    pthread_mutex_lock(&_mutProofs);
    paSession_t* session = getSession(packet->session->hash);

    //Set the proof manager in the session (new session)

    if (!session->proofManager) {
        session->proofManager = getProofManager(proofManager);
        memcpy(&session->src, &packet->session->srcHost, sizeof(in6_addr));
        memcpy(&session->dst, &packet->session->dstHost, sizeof(in6_addr));
        session->paTimerKey = _timer->addTimerEvent(this, SESSION_REPORT_INTERVAL, -1, SESSION_REPORT_INTERVAL, (uint8_t*) & session->hash, sizeof(uint64_t));
        packet->session->paTimerKey = session->paTimerKey;
    }

    //Initialize the Report timer	(new session)
    if (session->timeLastReport == 0) {
        session->timeLastReport = packet->timestamp;
    }

    session->timeLastProof = packet->timestamp;
    session->timeLastOperation = packet->timestamp;
    paRoute_t*	route;
    paProof_t* proof = new paProof_t;

    if (packet->ptype & PACKET_TYPE_DATA_SHDR) {
        route = getRoute(session, 0);

        if (route->proofs.size() == 0) {
            route->numberHops = 0;
            route->routeHash = 0;
        }

        proof->type = PA_PROOF_TYPE_SMALL;
        uint8_t*	hashchain = PACPHeaderSmall::getHashChain(packet);

        if (hashchain) {
            memcpy(proof->hashChain, hashchain, HEADER_HASHCHAIN_SIZE);
        }

        uint16_t sequence = PACPHeaderSmall::getSequence(packet);
        memcpy(&proof->sequence, &sequence, HEADER_SEQUENCE_SIZE);
        proof->packetLength = IPV6Packet::getPacketLength(packet) - PACPHeaderSmall::getFullLength(packet);

    } else {
        uint8_t*	routeHash = PACPHeaderFull::getRHash(packet);
        route = getRoute(session, *(uint32_t*) routeHash);

        if (route->proofs.size() == 0) {
            route->numberHops = routeHash[0];
            route->routeHash = 0;
            memcpy(&route->routeHash, routeHash, HEADER_ROUTEHASH_SIZE);
        }

        proof->type = PA_PROOF_TYPE_FULL;
        uint8_t* hashChain = PACPHeaderFull::getHashChain(packet);
        uint8_t* routeID = PACPHeaderFull::getRID(packet);
        memcpy(proof->hashChain, hashChain, CRYPTO_HASH_SIZE);
        memcpy(proof->routeID, routeID, HEADER_ROUTEID_SIZE);
        proof->index = PACPHeaderFull::getIndex(packet);
        uint16_t	sequence = PACPHeaderFull::getSequence(packet);
        memcpy(&proof->sequence, &sequence, sizeof(uint16_t));
        proof->packetLength = IPV6Packet::getPacketLength(packet) - PACPHeaderFull::getFullLength(packet);
    }

    proof->reportID = 0;
    route->proofs.push_back(proof);
    route->timeLastProof = packet->ipqhdr->timestamp_sec;
    route->unsentProofs++;
    session->unsentProofs++;
    session->storedProofs++;

    if (session->unsentProofs >= PA_SNPROOFS_TRIGGER) {
        //        ((session->timeLastProof - session->timeLastReport >= SESSION_REPORT_INTERVAL) && session->unsentProofs != 0)) {
        logger << LOG_L(LOG_DEBUG) << "Must Flush Session\n";
        packet->session->timer = NULL;
        reportAddSession(session);
        pthread_mutex_unlock(&_mutProofs);
        pthread_cond_signal(&_condRun);

    } else {
        pthread_mutex_unlock(&_mutProofs);
    }

    logger << LOG_L(LOG_DEBUG) << "ProofAttendant: Proof added\n";
}

/*
	Finds if the given address exists in the proof manager list

*/
paProofManager_t* ProofAttendant::findProofManager(in6_addr* address) {
    map<in6_addr, paProofManager_t*, in6lrt>::iterator itPM = _proofManagers.find(*address);

    if (itPM == _proofManagers.end()) {
        return NULL;
    }

    return (*itPM).second;
}

/*
	Return a new or existing proof manager

*/
paProofManager_t* ProofAttendant::getProofManager(in6_addr* address) {
    paProofManager_t* proofManager = findProofManager(address);

    if (proofManager == NULL) {
        proofManager = new paProofManager_t();
        memcpy(&proofManager->address, address, sizeof(in6_addr));
        proofManager->timeLastContact = 0;
        proofManager->active = false;
        _proofManagers[*address] = proofManager;
    }

    return proofManager;
}


/*
	Finds if the given session already exists

*/
paSession_t*	ProofAttendant::findSession(uint64_t hash) {
    map<uint64_t, paSession_t*>::iterator itSession = _proofSessions.find(hash);

    if (itSession == _proofSessions.end()) {
        return NULL;
    }

    return (*itSession).second;
}


/*
	Return a new or existing session
*/
paSession_t* ProofAttendant::getSession(uint64_t hash) {
    paSession_t* session = findSession(hash);

    if (!session) {
        session = new paSession_t();
        session->hash = hash;
        memset(&session->src, 0, sizeof(in6_addr));
        memset(&session->dst, 0, sizeof(in6_addr));
        session->timeLastOperation = 0;
        session->proofManager = NULL;
        session->unsentProofs = session->storedProofs = 0;
        session->timeLastReport = 0;
        session->paTimerKey = 0;
        _proofSessions[hash] = session;
    }

    return session;
}

/*
 	Finds if the given route exists in the session

*/
paRoute_t* ProofAttendant::findRoute(paSession_t* session, uint32_t rhash) {
    map<uint32_t, paRoute_t*>::iterator	itRoute = session->routes.find(rhash);

    if (itRoute == session->routes.end()) {
        return NULL;
    }

    return (*itRoute).second;
}

/*
	Returns a new or existing route

*/
paRoute_t*	ProofAttendant::getRoute(paSession_t* session, uint32_t rhash) {
    paRoute_t* route = findRoute(session, rhash);

    if (!route) {
        route = new paRoute_t();
        route->routeHash = rhash;
        route->timeLastProof = 0;
        route->numberHops = 0;
        route->unsentProofs = 0;
        session->routes[rhash] = route;
    }

    return route;
}

void ProofAttendant::reportAddSession(paSession_t* session) {
    if (_reportSessionQueue.find(session->hash) == _reportSessionQueue.end()) {
        _reportSessionQueue[session->hash] = session;
    }
}

void* ProofAttendant::run(void* arg) {
    _runReportHandler = true;
    pthread_mutex_init(&_mutRun, NULL);

    while (true) {
        pthread_mutex_lock(&_mutProofs);

        if (_reportSessionQueue.size() == 0) {
            pthread_mutex_unlock(&_mutProofs);
            logger << LOG_L(LOG_DEBUG) << "ProofAttendant::Run() Locked!\n";
            pthread_mutex_lock(&_mutRun);
            pthread_cond_wait(&_condRun, &_mutRun);

            if (_runReportHandler == false) {
                pthread_mutex_unlock(&_mutRun);
                break;
            }

            pthread_mutex_unlock(&_mutRun);
            logger << LOG_L(LOG_DEBUG) << "ProofAttendant::Run() Unlocked!\n";

        } else {
            logger << LOG_L(LOG_DEBUG) << "ProofAttendant::Run() Sending report for Proofs in session\n";
            map<uint64_t, paSession_t*>::iterator it = _reportSessionQueue.begin();
            paSession_t* session = (*it).second;
            (*it).second = NULL;
            _reportSessionQueue.erase(it);
            reportProofs(session);
            //Unlock the Proof mutex
            pthread_mutex_unlock(&_mutProofs);
        }
    }

    logger << LOG_L(LOG_DEBUG) << "Exiting from ProofAttendant::Run()\n";
    pthread_exit(PTHREAD_CANCELED);
    return NULL;
}

uint8_t ProofAttendant::reportProofs(paSession_t* session, uint64_t delay) {
    timeval tv;

    if(!session) {
        logger << LOG_L(LOG_ERROR) << "ProofAttendant:reportProofs No session provided\n";
        return 0xFF;
    }

    if(_keyReportMap.size()) {
        logger << LOG_L(LOG_ERROR) << "ProofAttendant:reportProofs Already reporting. Skipping\n";
        return 0xFF;
    }

    //	pthread_mutex_lock(&_mutProofs);
    gettimeofday(&tv, NULL);
    uint64_t	currTime = tv.tv_sec * 1000000 + tv.tv_usec;
    session->timeLastReport = currTime;
//	fprintf(stderr,"\n\nReportID: %llu\n",currTime);
    pktCmn_t* report = PACPReport::alloc();

    if (!report) {
        //		pthread_mutex_unlock(&_mutProofs);
        return 0xFF;
    }

    PACPReport::setReportID(report, currTime);
    PACPReport::setSessionSrc(report, &session->src);
    PACPReport::setSessionDst(report, &session->dst);
    map<uint32_t, paRoute_t*>::iterator itRoute = session->routes.begin();
    bool data = false;

    while (itRoute != session->routes.end()) {
        if (report->psize >= REPORT_MAX_SIZE) { // Packet seems to be full
            break;
        }

        paRoute_t*	route = (*itRoute).second;

        if (route->unsentProofs > 0 ) {
            if (PACPReport::addRoute(report, route->routeHash) <= 0) {
                break;
            }

            data = true;
            vector<paProof_t*>::iterator	itProofs = route->proofs.begin();

            while (itProofs != route->proofs.end()) {
                paProof_t*	proof = (*itProofs);

                if (proof->reportID == 0) {
                    if (PACPReport::addProof(report, proof->type, proof->index, proof->packetLength, proof->sequence, proof->routeID, proof->hashChain) <= 0 ) {
                        break;    //If it is full
                    }

                    route->unsentProofs--;
                    proof->reportID = currTime;
                    session->unsentProofs--;
                    session->timeLastReport = tv.tv_sec;
                }

                itProofs++;
            } //While itProofs
        } //Unsent>0

        itRoute++;
    } //While itRoute

//	fprintf(stderr,"\n\nReportID: %llu\n",currTime);
    if (data) {
        in6_addr	pm;
        memcpy(&pm, &session->proofManager->address, sizeof(in6_addr));
        //		pthread_mutex_unlock(&_mutProofs);

        if(conf->getUseCryptoControl()) {
            try {
                PACPReport::sign(report, _km->_hostKey);

            } catch(Exception e) {
                e.print();
                return 0;
            }
        }

        uint16_t	len = 0;
        uint8_t* buf = PACPReport::getBuffer(report, &len);
        uint64_t key = _timer->addRTXEvent(this, pm, delay, PACKET_RTX_COUNT, PACKET_RTX_DELAY, buf, len, (uint8_t*) &currTime, sizeof(uint64_t));
        _keyReportMap[currTime] = key;
        Packet::free(report);

    } else {
        //	pthread_mutex_unlock(&_mutProofs);
        Packet::free(report);
    }

    return 0;
}

void ProofAttendant::timerExpired(uint64_t key, uint8_t* buffer, uint32_t bufLength) {
    logger << LOG_L(LOG_DEBUG) << "ProofAttendant: Timer Expired Key=" << key << "\n";
    pthread_mutex_lock(&_mutProofs);

    if (buffer && bufLength) {
        paSession_t*	s = findSession(*(uint64_t*) buffer);

        if (s) {
            logger << LOG_L(LOG_DEBUG) << "ProofAttendant: Session found\n";

        } else {
            logger << LOG_L(LOG_DEBUG) << "ProofAttendant: Session NOT found. SID=" << *(uint64_t*) buffer << "\n";
            pthread_mutex_unlock(&_mutProofs);
            return ;
        }

        reportProofs(s);
    }

    pthread_mutex_unlock(&_mutProofs);
    return ;
}

void ProofAttendant::rtxExpired(uint64_t key, uint8_t* buffer, uint32_t bufLength) {
    uint64_t	reportID;
    memcpy(&reportID, buffer, bufLength);
    logger << LOG_L(LOG_DEBUG) << "ProofAttendant: Event " << reportID << " expired!\n";
    bool sessionFound = false;
    pthread_mutex_lock(&_mutProofs);
    map<uint64_t, paSession_t*>::iterator itSession = _proofSessions.begin();

    while (itSession != _proofSessions.end() && !sessionFound) {
        paSession_t* session = (*itSession).second;
        map<uint32_t, paRoute_t*>::iterator itRoute = session->routes.begin();

        while (itRoute != session->routes.end()) {
            paRoute_t*	route = (*itRoute).second;
            vector<paProof_t*>::iterator	itProofs = route->proofs.begin();

            while (itProofs != route->proofs.end()) {
                paProof_t*	proof = (*itProofs);

                if (proof->reportID == reportID) {
                    if (!sessionFound) {
                        sessionFound = true;
                    }

                    proof->reportID = 0;
                    route->unsentProofs++;
                    session->unsentProofs++;
                }

                itProofs++;
            } //While itProofs

            itRoute++;
        } //While itRoute

        if(sessionFound) {
            reportProofs(session, PA_REPORT_RETRIE_TIMEOUT);
        }

        itSession++;
    }

    //		cerr<<"\n";
    pthread_mutex_unlock(&_mutProofs);
}

void ProofAttendant::eventExpired(uint64_t	reportID, uint8_t type, uint8_t* buffer, uint32_t bl) {
    switch (type) {
        case EVENT_TYPE_TIMER :
            timerExpired(reportID, buffer, bl);
            break;

        case EVENT_TYPE_RTX	:
            rtxExpired(reportID, buffer, bl);
            break;

        default:
            return ;
    }
}

void ProofAttendant::reportReceived(uint64_t reportID) {
    logger << LOG_L(LOG_DEBUG) << "ProofAttendant: Deleting Proofs of report\n";
    uint64_t	key = (*_keyReportMap.find(reportID)).second;

    if(!key) {
        logger << LOG_L(LOG_DEBUG) << "ProofAttendant: Report Key not found\n";
        return;
    }

    _timer->cancelRTXEvent(key);
    _keyReportMap.erase(reportID);
    logger << LOG_L(LOG_DEBUG) << "ProofAttendant: Event Canceled\n";
    bool	found = false;
    pthread_mutex_lock(&_mutProofs);
    map<uint64_t, paSession_t*>::iterator itSession = _proofSessions.begin();

    while (itSession != _proofSessions.end()) {
        paSession_t* session = (*itSession).second;
        map<uint32_t, paRoute_t*>::iterator itRoute = session->routes.begin();

        while (itRoute != session->routes.end()) {
            paRoute_t* route = (*itRoute).second;
            vector<paProof_t*>::iterator itProofs = route->proofs.begin();

            while (itProofs != route->proofs.end()) {
                paProof_t* proof = (*itProofs);

//				fprintf(stderr,"\n\nFind ReportID: %llu, Got: %llu\n",reportID, proof->reportID);
                if (proof->reportID == reportID) {
                    delete proof;
                    (*itProofs) = NULL;
                    route->proofs.erase(itProofs);

                    if (!found) {
                        found = true;
                    }

                } else {
                    itProofs++;
                }
            }

            if (route->proofs.size() == 0) {
                delete (*itRoute).second;
                (*itRoute).second = NULL;
                session->routes.erase(itRoute);
            }

            if (found) {
                break;
            }

            itRoute++;
        }

        if (session->routes.size() == 0) {
            delete (*itSession).second;
            (*itSession).second = NULL;
            _proofSessions.erase(itSession);
        }

        if (found) {
            break;

        } else {
            itSession++;
        }
    }

    if (!found) {
        logger << LOG_L(LOG_DEBUG) << "ProofAttendant: Could not find any proof with reportID=" << reportID << "\n";
    }

    pthread_mutex_unlock(&_mutProofs);
}
