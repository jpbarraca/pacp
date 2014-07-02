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

#include "polSolver.h"
#include "hash.h"
#include <pthread.h>
#include <sys/time.h>
#include <openssl/md5.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

PolSolver::PolSolver() {
    _fecCode = fec_new(16, GF_SIZE + 1);
    _db = new DB(conf->getDBHostname().c_str(), conf->getDBUsername().c_str(), conf->getDBPassword().c_str(), conf->getDBDatabase().c_str());
    pthread_mutex_init(&_muxSolver, NULL);
    pthread_mutex_init(&_muxSolverQueue, NULL);
    pthread_cond_init(&_condSolver, NULL);
    pthread_create(&_ptSolver, NULL, threadFunc, this);
}

PolSolver::~PolSolver() {
    _run = false;
    pthread_cond_signal(&_condSolver);
    pthread_join(_ptSolver, NULL);
    delete(_db);
}


void*	PolSolver::run(void*) {
    _running = true;
    _run = true;
    logger << LOG_L(LOG_DEBUG) << "PolSolver: Starting PolSolver Thread\n";
    bool gotData = false;

    while (_run) {
        if (!gotData) {
            struct timeval now;
            struct timespec timeout;
            gettimeofday(&now, NULL);
            timeout.tv_sec = now.tv_sec + 1;
            timeout.tv_nsec = now.tv_usec;
            pthread_mutex_lock(&_muxSolver);

            if (pthread_cond_timedwait(&_condSolver, &_muxSolver, (const timespec*) &timeout) == EINTR) {
                _run = false;
                pthread_mutex_unlock(&_muxSolver);
                break;
            }

            pthread_mutex_unlock(&_muxSolver);
            gotData = true;

        } else {
            bool unlockMutex = true;
            pthread_mutex_lock(&_muxSolverQueue);

            while (_sQueue.size() ) {
                unlockMutex = false;
                vector<psProof_t*>::iterator pi = _sQueue.begin();
                psProof_t*	proof = (*pi);
                _sQueue.erase(pi);
                pthread_mutex_unlock(&_muxSolverQueue);
                psSession_t*	session = proof->session;

                if (!session) {
                    logger << LOG_L(LOG_ERROR) << "Solving proof for unknown session!!!\n";

                } else {
                    solvePol(session, proof);
                    cleanSession(session);
                }
            }

            if (unlockMutex) {
                pthread_mutex_unlock(&_muxSolverQueue);
            }

            gotData = false;
        }
    }

    _running = false;
    return NULL;
}


uint32_t PolSolver::solvePol(psSession_t* session, psProof_t* proof) {
    if (!session || !proof) {
        return SOLVER_ERROR;
    }

    //If we need more proofs to solve the route just buffer it
    session->pList.push_back(proof);
    proof->status = PS_PROOF_STATUS_BUFFERED;

    if (session->pList.size() < session->nhops || session->pList.size() < 16 ) {
        //        logger<<LOG_L(LOG_DEBUG)<<"PolSolver: Buffering proof for session "<<session->key<<" I:"<<(int)proof->index<<" PLS: "<<dec<<session->pList.size()<<hex<<"\n";
        return SOLVER_OK;
    }

    if (session->solved) {
        //        logger<<LOG_L(LOG_DEBUG)<<"PolSolver: Solving proof for session "<<session->key<<" Method: Brute\n";
        solveBrute(session);
        return SOLVER_OK;
    }

    //   logger<<LOG_L(LOG_DEBUG)<<"PolSolver: Solving proof for session "<<session->key<<"\n";
    solveMatrix(session);
    return SOLVER_OK;
}


int PolSolver::solveBrute(psSession_t* session) {
    vector<psProof_t*>::iterator	pi = session->pList.begin();

    while (pi != session->pList.end()) {
        psProof_t*	proof = (*pi);
        uint8_t	result[sizeof(in6_addr)];
        memset(result, 0, sizeof(in6_addr));

        //First verify Charging Part of the hash

        if (verifyCHash(session, proof)) {
            session->stsChargedProofs++;
            session->stsChargedBytes += proof->size;
            session->sentPackets++;
            session->sentBytes += proof->size;
            //         	logger<<LOG_L(LOG_DEBUG)<<"PolSolver: Charging Hash Chain sucessfully verified\n";
            //Add users to the Database
            char src[256];
            char dst[256];
            inet_ntop(AF_INET6, &session->src, src, 200);
            inet_ntop(AF_INET6, &session->dst, dst, 200);
            _db->insertProof(src, dst, time(NULL), proof->size, proof->tc);
            //					_db->insertProofUser(src,DB_PACKET_SENT,proof->size);
            //					_db->insertProofUser(dst,DB_PACKET_RECEIVED,proof->size);

            if (session->nhops) { //Do we have a rewarding hash to check?
                if (verifyRHash(session, proof)) {
                    //            	logger<<LOG_L(LOG_DEBUG)<<"PolSolver: Rewarding Hash Chain sucessfully verified\n";
                    vector<psHost_t*>::iterator itHost = session->route.begin();

                    for (; itHost != session->route.end(); itHost++) {
                        char host[200];
                        inet_ntop(AF_INET6, (*itHost)->id, host, 200);
                        _db->insertProofUser(host, DB_PACKET_FORWARDED, proof->size);
                        //	            	logger<<LOG_L(LOG_DEBUG)<<"PolSolver: Adding forwarding proof for "<<host<<"\n";
                    }

                    proof->status = PS_PROOF_STATUS_SOLVED;

                } else {
                    logger << LOG_L(LOG_DEBUG) << "PolSolver: Rewarding Hash Chain could not be verified\n";
                    proof->status = PS_PROOF_STATUS_MISMATCH;
                }

            } else {
                proof->status = PS_PROOF_STATUS_SOLVED;
            }

        } else {
            logger << LOG_L(LOG_DEBUG) << "PolSolver: Charging Hash Chain could not be verified\n";
            proof->status = PS_PROOF_STATUS_MISMATCH;
        }

        pi++;
    }

    return SOLVER_OK;
}


int PolSolver::solveMatrix(psSession_t* session) {
    logger << LOG_L(LOG_DEBUG) << "PolSolver: Solving Proofs\n";

    if (session->nhops > session->pList.size()) {
        return SOLVER_ERROR;
    }

    if(session->solved == true) {
        logger << LOG_L(LOG_DEBUG) << "PolSolveR: Session already solved\n";
        solveBrute(session);
        return SOLVER_OK;
    }

    uint32_t i;
    gf** src = (gf**) new uint32_t[session->pList.size()];

    for (i = 0; i < session->pList.size(); i++) {
        src[i] = (gf*) new gf[sizeof(in6_addr)];
    }

    int*	index = (int*) new int[session->pList.size()];
    memset(index, 0, sizeof(int)*session->pList.size());
    vector<psProof_t*>::iterator pi = session->pList.begin();

    //Prepare data
    for (i = 0; i < session->pList.size(); i++) {
        psProof_t*	proof = (*pi);
        memcpy(src[i], proof->rid, sizeof(in6_addr));
        index[i] = proof->index;
        proof->status = PS_PROOF_STATUS_SOLVED;
        pi++;
    }

    logger << LOG_L(LOG_DEBUG) << "PolSolver: Solving " << session->pList.size() << " proofs\n";

    if ( fec_decode(_fecCode, src, index, sizeof(in6_addr))) {
        logger << LOG_L(LOG_WARNING) << "PolSolver: Singular Matrix\n";

        for (i = 0; i < session->pList.size(); i++) {
            delete [] src[i];
        }

        delete [] src;
        delete [] index;
        return SOLVER_OK;
    };

    logger << LOG_L(LOG_DEBUG) << "PolSolver: Proofs solved\n";

    for (i = 0; i < session->pList.size(); i++) {
        uint32_t a;

        if (src[i][0]) {
            fprintf(stderr, "Route HOP: ");
            char addrstr[200];
            inet_ntop(AF_INET6, src[i], addrstr, 200);

            for (a = 0; a < sizeof(in6_addr); a++) {
                char c = src[i][a];

                if (c < '0' || c > 'z') {
                    c = '.';
                }

                fprintf(stderr, "%c", c);
            }

            fprintf(stderr, "   -   ");
            fprintf(stderr, "Addr: %s\n", addrstr);
            psHost_t* host = getHost(session, src[i], sizeof(in6_addr));

            if (host && session->solved != true ) {
                session->solved = true;
            }

            solveBrute(session);
        }

        delete [] src[i];
    }

    delete [] src;
    delete [] index;
    return SOLVER_OK;
}

psHost_t* PolSolver::getHost(psSession_t* session, gf* src, uint32_t sz) {
    if (!session) {
        return NULL;
    }

    Fnv64_t hash_val = fnv_64a_buf(src, sz , FNV1_64A_INIT);
    vector<psHost_t*>::iterator	hostIT	= session->route.begin();

    while (hostIT != session->route.end() ) {
        if ( (*hostIT)->key == hash_val) {
            return (*hostIT);
        }

        hostIT++;
    }

    psHost_t* host = new psHost_t();
    memset(host, 0, sizeof(psHost_t));
    host->key = hash_val;
    memcpy(host->id, src, sz);
    session->route.push_back(host);
    return host;
}

void PolSolver::cleanSession(psSession_t* session) {
    vector<psProof_t*>::iterator	pi = session->pList.begin();

    while (pi != session->pList.end()) {
        psProof_t* proof = *pi;

        if (proof->status == PS_PROOF_STATUS_SOLVED) {
            session->stsRewardBytes += proof->size;
            session->stsRewardProofs ++;
            psProofDelete(proof);
            session->pList.erase(pi);

        } else if (proof->status == PS_PROOF_STATUS_MISMATCH) {
            session->stsMismatchProofs ++;
            session->stsMismatchBytes += proof->size;
            psProofDelete(proof);
            session->pList.erase(pi);

        } else {
            pi++;
        }
    }
}

void PolSolver::addProof(uint32_t index, in6_addr& src, in6_addr& dst, uint32_t rhash, uint8_t nhops, uint32_t size, uint8_t* rid, uint8_t* hashChain, uint16_t sequence ) {
    psProof_t* proof = psProofCreate();
    psSession_t*	session = getSession(src, dst, rhash);

    if (session->nhops != nhops) {
        session->nhops = nhops;
    }

    proof->index = index;
    //    proof->rhash = rhash;
    proof->session = session;
    proof->size = size;
    proof->status = PS_PROOF_STATUS_UNSOLVED;
    proof->sequence = sequence;

    if (rid && nhops) {
        memcpy(&proof->rid, rid, HEADER_ROUTEID_SIZE);
    }

    memcpy(&proof->hashChain, hashChain, HEADER_HASHCHAIN_SIZE);
    pthread_mutex_lock(&_muxSolverQueue);
    _sQueue.push_back(proof);
    pthread_mutex_unlock(&_muxSolverQueue);
    //    pthread_cond_signal(&_condSolver);
}


psSession_t* PolSolver::getSession(in6_addr& src, in6_addr& dst, uint32_t rhash) {
    psSession_t* session = NULL;
    uint64_t	key = calculateKey(src, dst, rhash);
    map<uint64_t, psSession_t*>::iterator si = _sCache.find(key);

    if (si == _sCache.end()) {
        session = psSessionCreate(src, dst, rhash);
        session->key = key;
        _sCache[key] = session;

    } else {
        session = (*si).second;
    }

    return session;
}

uint64_t PolSolver::calculateKey(in6_addr& src, in6_addr& dst, uint32_t	rhash) {
    uint8_t	buffer[2 * sizeof(in6_addr) + sizeof(uint32_t)];
    uint64_t	key = 0;
    memcpy(buffer, &src, sizeof(in6_addr));
    memcpy(buffer + sizeof(in6_addr), &dst, sizeof(in6_addr));
    memcpy(buffer + sizeof(in6_addr) * 2, &rhash, sizeof(uint32_t));
    Fnv64_t hash_val = fnv_64a_buf(buffer, 2 * sizeof(in6_addr) + sizeof(uint32_t), FNV1_64A_INIT);
    memcpy(&key, &hash_val, sizeof(uint64_t));
    return key;
}

psSession_t*	PolSolver::psSessionCreate(in6_addr& src, in6_addr& dst, uint32_t	rhash) {
    psSession_t*	session = new psSession_t();
    //Add users to the Database
    char addr[200];
    inet_ntop(AF_INET6, &src, addr, 200);
    _db->getUser(addr);
    inet_ntop(AF_INET6, &dst, addr, 200);
    _db->getUser(addr);
    memcpy(&session->src, &src, sizeof(in6_addr));
    memcpy(&session->dst, &dst, sizeof(in6_addr));
    session->rhash = rhash;
    session->nhops = 0;
    session->solved = 0;
    session->sentBytes = 0;
    session->recvBytes = 0;
    session->fwrdBytes = 0;
    session->sentPackets = 0;
    session->recvPackets = 0;
    session->fwrdPackets = 0;
    session->stsChargedBytes = 0;
    session->stsChargedProofs = 0;
    session->stsRewardBytes = 0;
    session->stsRewardProofs = 0;
    session->stsMismatchBytes = 0;
    session->stsMismatchProofs = 0;
    return session;
}

void PolSolver::psSessionDelete(psSession_t* session) {
    if (!session) {
        return ;
    }

    _sCache.erase(session->key);
    delete session;
}

psProof_t* PolSolver::psProofCreate() {
    psProof_t*	proof = new psProof_t();

    if (!proof) {
        return NULL;
    }

    memset(proof, 0, sizeof(psProof_t));
    return proof;
}

void PolSolver::psProofDelete(psProof_t* proof) {
    delete proof;
}

int PolSolver::verifyCHash(psSession_t* session, psProof_t* proof) {
    uint8_t buf1[1024];
    uint8_t buf2[128];
    int size = 0;
    memset(buf1, 0, 1024);
    memset(buf2, 0, 128);
    //Size of Packet
    memcpy(buf1, &proof->size, sizeof(uint16_t));
    size += sizeof(uint16_t);
    //Sequence Number
    memcpy(buf1, &proof->sequence, sizeof(uint16_t));
    size += sizeof(uint16_t);
    char*	secret = getUserSecret(session->src);

    if (secret) {
        memcpy(&buf1[size], secret, strlen(secret));
        size += strlen(secret);
    }

    //Src Address
    memcpy(&buf1[size], &session->src, sizeof(in6_addr));
    size += sizeof(in6_addr);
    //Dst Address
    memcpy(&buf1[size], &session->dst, sizeof(in6_addr));
    size += sizeof(in6_addr);
    MD5(buf1, size, buf2);

    if (!memcmp(proof->hashChain, buf2, session->nhops >= 1 ? HEADER_CHARGING_HASH_SIZE  : HEADER_HASHCHAIN_SIZE) ) {
        delete [] secret;
        return 1;

    } else {
        return 1;
        int a;
        fprintf(stderr, "Size: %5.5u - ", proof->size);
        fprintf(stderr, "Sequence: %5.5u - ", proof->sequence);
        fprintf(stderr, "Total Size: %u\n", size);
        fprintf(stderr, "Verify Length: %u\n", session->nhops >= 1 ? HEADER_CHARGING_HASH_SIZE : HEADER_HASHCHAIN_SIZE);

        if (secret) {
            fprintf(stderr, "Secret: %s SL:%u\n", secret, strlen(secret));

        } else {
            fprintf(stderr, "No Secret Found!\n");
        }

        fprintf(stderr, "RCV: ");

        for (a = 0; a < 16; a++) {
            fprintf(stderr, "%2.2x ", proof->hashChain[a]);
        }

        fprintf(stderr, "\n");
        fprintf(stderr, "CAL: ");

        for (a = 0; a < 16; a++) {
            fprintf(stderr, "%2.2x ", buf2[a]);
        }

        fprintf(stderr, "\n");
        delete [] secret;
        return 0;
    }
}

int PolSolver::verifyRHash(psSession_t*	session, psProof_t* proof) {
    return 1;
}

char*	PolSolver::getUserSecret(in6_addr& addr) {
    //Add users to the Database
    char saddr[200];
    inet_ntop(AF_INET6, &addr, saddr, 200);
    return _db->getSecretByID(saddr);
}

