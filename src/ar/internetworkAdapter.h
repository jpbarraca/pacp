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

#ifndef INTERNETWORK_ADAPTER_H
#define INTERNETWORK_ADAPTER_H
#include <string>
#include "configuration.h"

class PacketHandler;
class ProofAttendant;
class SessionManager;
class RoutingClient;
class Timer;
class A4CClient;
class KeyManager;

typedef struct pktCmn_t;
typedef struct in6_addr;
typedef struct fec_parms;

extern Configuration* conf;

class InternetworkAdapter {
  public:
    InternetworkAdapter();
    ~InternetworkAdapter();
    int run();


    //Packet Processing methods
    int processPacketDataIn(pktCmn_t*);
    int processPacketDataOut(pktCmn_t*);
    int processPacketDataFwr(pktCmn_t*);

    int processPacketSigIn(pktCmn_t*);
    int processPacketSigOut(pktCmn_t*);
    int processPacketSigFwr(pktCmn_t*);

  private:
    PacketHandler*	_pHandler;
    ProofAttendant* _proofAttendant;
    SessionManager* _sessionManager;
    RoutingClient*  _routingClient;
    A4CClient*			_a4cClient;
    Timer* _timer;
    KeyManager* _keyManager;

    bool _run;
    bool _running;
    in6_addr*		_currentProofManager;
    fec_parms*	_fecCode;

};

#endif
