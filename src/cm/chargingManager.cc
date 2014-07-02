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

#include "chargingManager.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <packet.h>
#include <packetHandler.h>
#include "chargingManager.h"
#include "proofManager.h"
#include "a4cManager.h"
#include "flowManager.h"

#define SOCKET_READ_TIMEOUT 500

ChargingManager::ChargingManager() {
    _run = false;
    _running = false;
    pthread_mutex_init(&_muxChargingManager, NULL);
    pthread_cond_init(&_condChargingManager, NULL);
    _pManager = NULL;
    _flowManager = NULL;
    _pHandler = NULL;
    _a4cManager = NULL;
    _keyManager = NULL;
}

ChargingManager::~ChargingManager() {
    _run = false;
    logger << LOG_L(LOG_ERROR) << "ChargingManager: Stopping chargingmanager\n";
}

void ChargingManager::run() {
    _run = true;
    _running = true;
    //initializing socket.

    if(!_keyManager) {
        _keyManager = new KeyManager();
    }

    _keyManager->_opKey = _keyManager->loadRSAname((char*) conf->getOperatorRSAKeyFile().c_str() );
    _keyManager->_hostKey = _keyManager->loadECname((char*) conf->getHostKeyFile().c_str() );

    if(!_pHandler) {
        _pHandler = new PacketHandler(false);
    }

    if(!_pManager) {
        _pManager = new ProofManager(_pHandler, _keyManager);
    }

    if(!_flowManager) {
        _flowManager = new FlowManager(_pHandler, _keyManager);
    }

    if(!_a4cManager) {
        _a4cManager  = new A4CManager(_pHandler, _keyManager);
    }

    while(_run) {
        pktCmn_t*	pkt = _pHandler->getPacket();

        if(!pkt) {
            continue;
        }

        logger << LOG_L(LOG_DEBUG) << "ChargingManager:run: Got packet\n";

        if(pkt->ptype & PACKET_TYPE_SIG_REP) {
            _pManager->processPacket(pkt);

        } else if(pkt->ptype & PACKET_TYPE_SIG_FAUTH) {
            _flowManager->processPacket(pkt);

        } else if(pkt->ptype & PACKET_TYPE_SIG_SINIT) {
            _a4cManager->processPacket(pkt);

        } else {
            logger << LOG_L(LOG_DEBUG) << "ChargingManager:run: Unknown packet type\n";
        }

        Packet::free(pkt);
    }

    _running = false;
}
