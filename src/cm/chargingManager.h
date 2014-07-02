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

#ifndef CHARGING_MANAGER_H_
#define CHARGING_MANAGER_H_
#include <threadFunc.h>
#include <configuration.h>
#include <log.h>
#include <keyManager.h>

extern Configuration* conf;
extern Log logger;

class ProofManager;
class PacketHandler;
class A4CManager;
class FlowManager;

class ChargingManager {

  public:
    ChargingManager();
    ~ChargingManager();

    void run();
    void stop();

  private:
    void processPacket(uint8_t*, uint32_t, sockaddr_in6&);

    ProofManager*	_pManager;
    A4CManager*	_a4cManager;
    FlowManager*	_flowManager;
    PacketHandler*	_pHandler;
    KeyManager*		_keyManager;

    pthread_t	_ptChargingManager;

    pthread_cond_t	_condChargingManager;

    pthread_mutex_t	_muxChargingManager;

    int	_socket;

    int	_run;

    int _running;
};

#endif
