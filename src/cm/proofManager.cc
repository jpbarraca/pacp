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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <packet.h>
#include "polSolver.h"
#include "packetHandler.h"
#include "proofManager.h"
#include "keyManager.h"

ProofManager::ProofManager(PacketHandler* p, KeyManager* km) {
    _run = false;
    _running = false;
    _polSolver = new PolSolver();
    _pHandler = p;
    _keyManager	= km;
    pthread_mutex_init(&_muxProofManager, NULL);
    pthread_cond_init(&_condProofManager, NULL);
}

ProofManager::~ProofManager() {
    _run = false;
    logger << LOG_L(LOG_ERROR) << "ProofManager: Stopping proofmanager\n";

    if (_running) {
        logger << LOG_L(LOG_ERROR) << "ProofManager: Could not terminate process\n";
    }

    delete _polSolver;
    pthread_cond_signal(&_condProofManager);
}

void ProofManager::processPacket(pktCmn_t* report) {
    if (!report || !report->ptype & PACKET_TYPE_SIG_REP) {
        return ;
    }

    logger << LOG_L(LOG_DEBUG) << "\nProofManager: Received a Report\n";

    //Check signature
    if(false && _keyManager && conf->getUseCryptoControl()) {
        kmKey_t* key = _keyManager->findKey(IPV6Packet::getSrc(report));

        if(!key) {
            logger << LOG_L(LOG_WARNING) << "ProofManager: Report FAILED because no Node Key Found!\n";
            return;
        }

        if(!PACPReport::verifySig(report, key)) {
            logger << LOG_L(LOG_WARNING) << "ProofManager: Report FAILED Signature Verification\n";
            return;
        };
    }

    pktCmn_t*	response = PACPReportResponse::alloc();
    uint64_t	reportID = PACPReport::getReportID(report);
    PACPReportResponse::setReportID(response, reportID);
    PACPReportResponse::pack(response);

    //Sign packet
    if(_keyManager && conf->getUseCryptoControl()) {
        PACPReportResponse::sign(response, _keyManager->_hostKey);
    }

    //Send response to reporting node
    uint16_t len = 0;
    uint8_t*	buffer = PACPReportResponse::getBuffer(response, &len);
    report->ipv6sock->sin6_port = ntohs(conf->getSignallingPort());
    _pHandler->sendto(buffer, len, 0, (sockaddr*) report->ipv6sock, sizeof(sockaddr_in6));
    //Packet sent. Now lets process what we got
    buffer = PACPReport::getBuffer(report, &len);
    char	sessionSrc[200];
    char	sessionDst[200];
    char	nodeAddress[200];
    in6_addr	srcIP;
    in6_addr dstIP;
    in6_addr	reportIP;
    uint8_t*	buffi = buffer;
    memcpy(&srcIP, PACPReport::getSessionSrc(report), sizeof(in6_addr));
    memcpy(&dstIP, PACPReport::getSessionDst(report), sizeof(in6_addr));
    memcpy(&reportIP, &report->ipv6sock->sin6_addr, sizeof(in6_addr));
    inet_ntop(AF_INET6, &srcIP, sessionSrc, 200);
    inet_ntop(AF_INET6, &dstIP, sessionDst, 200);
    //	inet_ntop(AF_INET6,reportIP,nodeAddress,200);
    inet_ntop(AF_INET6, &report->ipv6sock->sin6_addr, nodeAddress, 200);
    uint8_t	nroutes = PACPReport::getNumberRoutes(report);
    logger << LOG_L(LOG_DEBUG) << "ProofManager: Reporting Node=" << nodeAddress << "\n";
    logger << LOG_L(LOG_DEBUG) << "ProofManager: Session SRC=" << sessionSrc << "   DST=" << sessionDst << "\n";
    logger << LOG_L(LOG_DEBUG) << "ProofManager: ReportID=" << reportID << "\n";
    logger << LOG_L(LOG_DEBUG) << "ProofManager: NumberOfRoutes=" << (uint16_t) nroutes << "\n";
    uint32_t currRoute = 1;
    uint32_t	totalBytes = 0;
    buffi = PACPReport::getDataStart(report);

    while (currRoute <= nroutes) {
        uint32_t nproofs, currProof, nhops;
        uint32_t	routeBytes = 0;
        uint32_t rhash = 0;
        memcpy(&rhash, buffi, sizeof(uint32_t));
        nhops = buffi[0];
        buffi += sizeof(uint32_t);
        currRoute ++;
        nproofs = buffi[0];
        buffi += 1;
        currProof = 0;
        logger << LOG_L(LOG_DEBUG) << "ProofManager:  Route(" << currRoute << ") Hop=" << nhops << " Proofs= " << nproofs << " Rhash=" << rhash << "\n";
        //Small Proofs

        if (nhops == 0) {
            while (currProof < nproofs) {
                currProof++;
                uint16_t ipSize = ntohs(*((uint16_t*) buffi)) + 40;
                buffi += 2;
                routeBytes += ipSize;
                totalBytes += ipSize;
                uint16_t sequence = ntohs(*((uint16_t*) buffi));
                buffi += 2;
                //			logger<<LOG_L(LOG_DEBUG)<<"ProofManager:   Proof("<<currProof<<"/"<<nproofs<<") Size="<<ipSize<<" Sequence="<<sequence<<"\n";
                _polSolver->addProof(0, srcIP, dstIP, rhash, 0, ipSize, NULL , buffi, sequence);
                buffi += CRYPTO_HASH_SIZE;
            }

        } else { //FULL PROOFS
            while (currProof < nproofs) {
                currProof++;
                uint16_t index = buffi[0];
                buffi++;
                uint16_t ipSize = ntohs(*((uint16_t*) buffi)) + 40;
                buffi += 2;
                routeBytes += ipSize;
                totalBytes += ipSize;
                uint16_t sequence = ntohs( *((uint16_t*) buffi) );
                buffi += 2;
                uint8_t* rid = buffi;
                buffi += sizeof(in6_addr);
                //		logger<<LOG_L(LOG_DEBUG)<<"ProofManager:   Proof("<<currProof<<")  Size="<<ipSize<<" Sequence="<<sequence<<" Index="<<hex<<index<<"\n";
                _polSolver->addProof(index, srcIP, dstIP, rhash, nhops, ipSize, rid, buffi, sequence);
                buffi += CRYPTO_HASH_SIZE;
            }
        } //Full Proofs

        logger << LOG_L(LOG_DEBUG) << "ProofManager: RouteBytes: " << routeBytes << "\n";
    }

    logger << LOG_L(LOG_DEBUG) << "ProofManager: TotalReportBytes: " << totalBytes << "\n";
}
