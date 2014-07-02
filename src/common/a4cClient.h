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

#ifndef _A4C_CLIENT_H_
#define _A4C_CLIENT_H_

#include <map>
#include <vector>
#include <pthread.h>
#include "timer.h"

using namespace std;

#define A4CCLIENT_CONNECT_OK			0
#define A4CCLIENT_CONNECT_ONGOING	1
#define A4CCLIENT_CONNECT_NOT			2

#define A4CCLIENT_RECONNECT_DELAY	60	//seconds

class Timer;
class PacketHandler;
typedef struct pktCmn_t;
class KeyManager;

class A4CClient : public TimerClient {

  public:
    A4CClient(Timer*, PacketHandler*, KeyManager*);
    virtual ~A4CClient();

    string& 	getUserSecret();
    uint8_t		getConnectStatus();
    void			connect(in6_addr*, uint32_t delay = 0);
    void			responseReceived(pktCmn_t*);
    void			eventExpired(uint64_t, uint8_t, uint8_t*, uint32_t);
  private:

    void expireTimer(uint64_t, uint8_t*, uint16_t);
    void expireRTX(uint64_t, uint8_t*, uint16_t);

    uint16_t	_status;
    uint64_t	_connectKey;
    Timer*	_timer;
    KeyManager* _km;

    PacketHandler* _pHandler;
};

#endif
