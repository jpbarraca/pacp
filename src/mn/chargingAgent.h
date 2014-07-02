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


#ifndef _CHARGING_AGENT_H
#define _CHARGING_AGENT_H
#include <string>
#include "configuration.h"

class Timer;
class PacketHandler;
class ProofAttendant;
class SessionManager;
class RoutingClient;
class GWInfoClient;
class A4CClient;
class KeyManager;

typedef struct pktCmn_t;
typedef struct in6_addr;
typedef struct fec_parms;

extern Configuration* conf;

/** Charging Agent Class */
/**
 	This class executes the protocol logic
 	for charging at the Mobile Node
*/
class ChargingAgent {
  public:
    /** The Constructor */
    ChargingAgent();
    /** The Destructor */
    ~ChargingAgent();

    /** The main loop of the class */
    int run();


    /** Processes a Data Packet Comming in
    	@param A packet structure
    	@return The resulting code (ACCEPT, DROP, HOLD)
    */
    int processPacketDataIn(pktCmn_t*);

    /** Processes a Data Packet Going Out
    	@param A packet structure
    	@return The resulting code (ACCEPT, DROP, HOLD)
    */
    int processPacketDataOut(pktCmn_t*);

    /** Processes a Data Packet being forwarded
    	@param A packet structure
    	@return The resulting code (ACCEPT, DROP, HOLD)
    */
    int processPacketDataFwr(pktCmn_t*);

    /** Processes a Signalling Packet Comming in
    	@param A packet structure
    	@return The resulting code (ACCEPT, DROP, HOLD)
    */
    int processPacketSigIn(pktCmn_t*);

    /** Processes a Signalling Packet Going out
    	@param A packet structure
    	@return The resulting code (ACCEPT, DROP, HOLD)
    */
    int processPacketSigOut(pktCmn_t*);

    /** Processes a Signalling Packet being forwarded
    	@param A packet structure
    	@return The resulting code (ACCEPT, DROP, HOLD)
    */
    int processPacketSigFwr(pktCmn_t*);

    /** Processes a White packet. Automatically accepted
    	@param A packet structure
    	@return The resulting code (ACCEPT)
    */
    int processPacketWhite(pktCmn_t*);

  private:
    PacketHandler*	_pHandler;
    ProofAttendant* _proofAttendant;
    SessionManager* _sessionManager;
    RoutingClient*  _routingClient;
    GWInfoClient*	_gwInfoClient;
    A4CClient*		_a4cClient;
    KeyManager*	_keyManager;


    static bool _run;
    static bool _running;
    uint32_t		socket;
    Timer*		_timer;
    fec_parms*	_fecCode;
    in6_addr*		_currentProofManager;

};
#endif
