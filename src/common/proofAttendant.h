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


#ifndef _PROOF_ATTENDANT_H
#define _PROOF_ATTENDANT_H

#include <map>
#include <vector>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <pthread.h>
#include "packet.h"
#include "log.h"
#include "timer.h"

#include "threadFunc.h"

#define PA_PROOF_TYPE_FULL 0
#define PA_PROOF_TYPE_SMALL 1

class KeyManager;

using namespace std;
extern Log logger;

/*
    ProofAttendant Proof.
    This structure will store one proof until it is delivered
*/

typedef struct {
    uint8_t	type;
    uint64_t	reportID;
    uint64_t	timestamp;
    uint8_t	index;
    uint16_t	packetLength;
    uint16_t	sequence;
    uint8_t	routeID[sizeof(in6_addr)];
    uint8_t	hashChain[16];
}

paProof_t;

/*
 	ProofAttendant Route
 	Will store one route and respective proofs.
*/

typedef struct {
    uint64_t	timeLastProof;
    uint32_t	routeHash;
    uint32_t	unsentProofs;
    uint8_t	numberHops;
    vector<paProof_t*>	proofs;
}

paRoute_t;

typedef struct {
    in6_addr	address;
    uint32_t	timeLastContact;
    uint8_t	active;
}

paProofManager_t;

/*
    ProofAttendant Session
    Represents an End to End session with different Routes.
*/

typedef struct {
    in6_addr src;
    in6_addr dst;
    uint32_t	timeLastOperation;
    uint32_t	timeLastProof;
    uint32_t	timeLastReport;
    uint64_t	hash;
    uint32_t	storedProofs;
    uint32_t	unsentProofs;
    uint64_t	paTimerKey;
    paProofManager_t* proofManager;
    map<uint32_t, paRoute_t*>	routes;
}

paSession_t;


class ProofAttendant : public ThreadFunc, public TimerClient {

    struct in6lrt {
        bool operator()(const in6_addr s1, const in6_addr s2) const {
            uint8_t* a, *b;
            a = (uint8_t*) & s1;
            b = (uint8_t*) & s2;

            for (unsigned int i = 0; i < sizeof(in6_addr); i++) {
                if (b[i] > a[i]) {
                    return true;
                }
            }

            return false;
        }
    };

  public:
    ProofAttendant(Timer* t, KeyManager*);
    virtual ~ProofAttendant();

    void collectProof(in6_addr*, pktCmn_t*);
    void	reportReceived(uint64_t);
    uint8_t reportProofs(paSession_t*, uint64_t delay = 0);

    Timer*	_timer;

  protected:

    void timerExpired(uint64_t reportID, uint8_t*, uint32_t);
    void rtxExpired(uint64_t reportID, uint8_t*, uint32_t);

    paProofManager_t* findProofManager(in6_addr*);
    paProofManager_t*	getProofManager(in6_addr*);
    paSession_t*	findSession(uint64_t);
    paSession_t*	getSession(uint64_t);
    paRoute_t*	findRoute(paSession_t*, uint32_t);
    paRoute_t*	getRoute(paSession_t*, uint32_t);

    void	eventExpired(uint64_t, uint8_t, uint8_t*, uint32_t);
    void	reportAddSession(paSession_t*);
    void*	run(void*);

  private:
    uint32_t	_paStatus;

    pthread_mutex_t _mutProofs; //Session and proof structures

    pthread_mutex_t _mutRun;
    pthread_cond_t	_condRun;
    pthread_t	_reportThread;
    bool	_runReportHandler;
    KeyManager*	_km;

    map<in6_addr, paProofManager_t*, in6lrt>	_proofManagers;
    map<uint64_t, paSession_t*>	_proofSessions;
    map<uint64_t, paSession_t*>	_reportSessionQueue;
    map<uint32_t, vector<paProof_t*> >	_busyProofs;
    map<uint64_t, uint64_t> _keyReportMap;

};

#endif
