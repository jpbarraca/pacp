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

#ifndef PROOF_MANAGER_H_
#define PROOF_MANAGER_H_
#include <threadFunc.h>
#include <configuration.h>
#include <log.h>

extern Configuration* conf;
extern Log logger;

class PolSolver;
class PacketHandler;
class KeyManager;
typedef struct pktCmn_t;

class ProofManager {

  public:
    ProofManager(PacketHandler* p = NULL, KeyManager* k = NULL);
    ~ProofManager();

    void processPacket(pktCmn_t*);

  private:

    PolSolver*	_polSolver;

    pthread_cond_t	_condProofManager;

    pthread_mutex_t	_muxProofManager;

    int	_run;
    PacketHandler* _pHandler;
    KeyManager*	_keyManager;
    int _running;
};

#endif
