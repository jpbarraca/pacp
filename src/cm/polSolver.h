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


#ifndef _POL_SOLVER_H_
#define _POL_SOLVER_H_

#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <map>
#include <vector>
#include <threadFunc.h>
#include <packet.h>
#include <db_mysql.h>
#include <fec.h>

using namespace std;

#define SOLVER_OK			0
#define SOLVER_ERROR  1

#define PS_PROOF_STATUS_UNSOLVED		0
#define PS_PROOF_STATUS_SOLVED			1
#define PS_PROOF_STATUS_BUFFERED		2
#define PS_PROOF_STATUS_MISMATCH		3

struct psSession_t;

struct psHost_t {
    uint64_t	key;
    uint8_t	id[sizeof(in6_addr)];

    uint64_t	sentBytes;
    uint64_t	recvBytes;
    uint64_t	fwrdBytes;

    uint64_t	sentPackets;
    uint64_t	recvPackets;
    uint64_t	fwrdPackets;
};

struct psProof_t {
    uint64_t	dbID;
    uint8_t	tc;
    unsigned char	rid[sizeof(in6_addr)];
    uint32_t	index;
    //  uint32_t	rhash;
    uint8_t	hashChain[HEADER_HASHCHAIN_SIZE];
    uint16_t	size;
    uint16_t	sequence;
    psSession_t*	session;
    uint32_t	status;
};


struct psSession_t {
    uint64_t	key;
    in6_addr src;
    in6_addr	dst;
    uint32_t	rhash;
    uint32_t	nhops;
    bool solved;

    uint32_t	lastIndex;


    //Stats
    uint64_t	sentBytes;
    uint64_t	recvBytes;
    uint64_t	fwrdBytes;

    uint64_t	sentPackets;
    uint64_t	recvPackets;
    uint64_t	fwrdPackets;

    uint64_t	stsChargedBytes;
    uint32_t	stsChargedProofs;
    uint64_t	stsRewardBytes;
    uint32_t	stsRewardProofs;
    uint64_t	stsMismatchBytes;
    uint32_t	stsMismatchProofs;

    vector<psHost_t*> route;
    vector<psProof_t*> pList;
};

class PolSolver : public ThreadFunc {

  public:
    PolSolver();
    virtual	~PolSolver();

    //Index, Src, Dst, Proof, rhash, hashchain
    void addProof(uint32_t, in6_addr&, in6_addr&, uint32_t, uint8_t, uint32_t, uint8_t*, uint8_t*, uint16_t);

  protected:

    void* run(void*);
    int verifyCHash(psSession_t*, psProof_t*);
    int verifyRHash(psSession_t*, psProof_t*);

    char*	getUserSecret(in6_addr&);
    uint64_t	calculateKey(in6_addr&, in6_addr&, uint32_t);
    psHost_t* getHost(psSession_t*, gf*, unsigned int);
    int solveBrute(psSession_t*);
    int	solveMatrix(psSession_t*);
    uint32_t solvePol(psSession_t*, psProof_t*);

    void cleanSession(psSession_t*);
    psSession_t* getSession(in6_addr&, in6_addr&, uint32_t);

    psSession_t* psSessionCreate(in6_addr&, in6_addr&, uint32_t);
    void psSessionDelete(psSession_t*);

    psProof_t*	psProofCreate();
    void	psProofDelete(psProof_t*);

  private:



    pthread_mutex_t	_muxSolver;
    pthread_mutex_t	_muxSolverQueue;
    pthread_t	_ptSolver;
    pthread_cond_t	_condSolver;

    map<uint64_t, psSession_t*>	_sCache;
    vector<psProof_t*>	_sQueue;

    bool _run;
    bool _running;
    fec_parms* _fecCode;
    DB*	_db;
};

#endif
