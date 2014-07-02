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


#ifndef _PACKET_HANDLER_H
#define _PACKET_HANDLER_H

//System includes
extern "C"
{
#include <libipq.h>
}

#include <queue>
#include "log.h"
#include "configuration.h"
#include <sys/types.h>
#include <sys/socket.h>

#define IPQ_READ_TIMEOUT	500000

typedef struct pktCmn_t;

extern Log logger;
extern Configuration* conf;

class PacketHandler {
  public:
    PacketHandler(const bool useIPQ = true, const int timeout = IPQ_READ_TIMEOUT);
    ~PacketHandler();

    void	insert(pktCmn_t*);
    pktCmn_t* getPacket(const int timeout = IPQ_READ_TIMEOUT);
    void setVerdict(pktCmn_t*, const int );

    uint32_t sendto(uint8_t* buf, uint16_t len, int flags, sockaddr* to, socklen_t tolen);

    pktCmn_t*	readSocket(uint32_t);
  private:
    struct ipq_handle* ipqHandle;
    long _lastTimeout;

    pthread_mutex_t	_mutPHandler;
    pthread_mutex_t	_mutPHSocket;
    bool _useIPQ;
    queue<pktCmn_t*>	_processQueue;
    uint32_t	_socket;

};

#endif
