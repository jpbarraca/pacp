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


#include <sys/time.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include "log.h"
#include "gwInfoClient.h"
#include "timer.h"
#include "exception.h"
#include "string.h"
#include "errno.h"
#include "arpa/inet.h"

#define GWINFO_RECONNECT_DELAY	10				//Seconds
#define GWINFO_POLLING_DELAY		1					//Seconds
#define GWINFO_SOCKET_NAME	"/tmp/socket_ACRA-GWINFO"

struct gwInfoMsg_t {
    /* GW_INFO Message */
    u_int8_t	opt_len;				/* Option Length */
    //    u_int8_t	      reserved;				/* Reserved */
    u_int8_t	ifIndex;				/* IF Index*/
    u_int16_t	connect;				/* neighbor connectivity */
    u_int8_t pref_len;				/* Prefixe Length */
    u_int8_t	dist;						/* Distance */
    u_int16_t	seq;						/* Sequence number */

    struct in6_addr gw_addr;				/* Gateway Global Address */

    struct in6_addr source_addr;		/* Source IP Address (multicast use only) */

    struct in6_addr sender_addr;		/* Sender IP Address (multicast use only) */
};


GWInfoClient::GWInfoClient() {
    logger << LOG_L(LOG_DEBUG) << "GWInfoClient created\n";
    _run = true;
    pthread_cond_init(&_gwInfoCond, NULL);
    pthread_mutex_init(&_gwInfoMutex, NULL);
    pthread_create(&_gwInfoThread, NULL, threadFunc, this);
}


GWInfoClient::~GWInfoClient() {
    logger << LOG_L(LOG_DEBUG) << "Stopping GWInfoClient: ";
    _run = false;
    pthread_cond_signal(&_gwInfoCond);
    //	pthread_join(_gwInfoThread,NULL);
    //	pthread_kill(_gwInfoThread,15);
    logger << "Done\n";
}

void* GWInfoClient::run(void*) {
    logger << LOG_L(LOG_DEBUG) << "GWInfoClient: Thread created\n";
    int sock = 0, len = 0;
    bool connected = false;
    sockaddr_un	sockName;
    sockName.sun_family = AF_UNIX;
    strcpy(sockName.sun_path, GWINFO_SOCKET_NAME);
    len = strlen(sockName.sun_path) + sizeof(sockName.sun_family);
    sock = socket(PF_UNIX, SOCK_DGRAM, 0);
    unlink(GWINFO_SOCKET_NAME);

    while (_run) {
        while (_run && !connected) {
            //			int f = access(GWINFO_SOCKET_NAME,R_OK | W_OK );
            struct timeval now;
            struct timespec timeout;
            //	  if(!f) {
            logger << LOG_L(LOG_DEBUG) << "GWInfoClient: Socket exists... binding\n";

            if (!bind(sock, (sockaddr*) &sockName, sizeof(sockaddr_un))) {
                logger << LOG_L(LOG_DEBUG) << "GWInfoClient: Socket binded\n";
                connected = true;
                break;

            } else {
                int errnum = errno;
                logger << LOG_L(LOG_DEBUG) << "GWInfoClient: Could not bind: " << strerror(errnum) << "\n";
                unlink(GWINFO_SOCKET_NAME);
            }

            //		}else
            //			logger<<LOG_L(LOG_DEBUG)<<"GWInfoClient: Socket not existing or without rights\n";
            pthread_mutex_lock(&_gwInfoMutex);
            gettimeofday(&now, NULL);
            timeout.tv_sec = now.tv_sec + GWINFO_RECONNECT_DELAY;
            timeout.tv_nsec = now.tv_usec;

            if (pthread_cond_timedwait(&_gwInfoCond, &_gwInfoMutex, (const timespec*) &timeout) == EINTR) {
                _run = false;
                pthread_mutex_unlock(&_gwInfoMutex);
                break;
            }

            pthread_mutex_unlock(&_gwInfoMutex);
        } //Find socket

        if (!_run) {
            break;
        }

        ;

        fd_set rfds;

        struct timeval tv;

        int retval;

        int32_t	rb;

        gwInfoMsg_t buffer;

        FD_ZERO(&rfds);

        FD_SET(sock, &rfds);

        uint32_t	nsocks = sock + 1;

        tv.tv_sec = GWINFO_POLLING_DELAY;

        tv.tv_usec = 0;

        retval = select(nsocks, &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            perror("select()");

        } else if (retval == EINTR) {
            logger << LOG_L(LOG_DEBUG) << "GWInfoClient: Reading expired (" << retval << ")\n";
            continue;
        }

        //We have something?
        rb = read(sock, &buffer, 2000);

        if (rb != sizeof(gwInfoMsg_t)) {
            logger << LOG_L(LOG_DEBUG) << "GWInfoClient: Got corrupted data." << sizeof(gwInfoMsg_t) << ":" << rb << "\n";
            continue;
        }

        char addr[200];
        inet_ntop(AF_INET6, &buffer.gw_addr, addr, sizeof(in6_addr));
//		conf->setDefaultChargingManager(buffer.gw_addr);

        if (strlen(addr)) {
//			logger << LOG_L(LOG_DEBUG) << "GWInfoClient: GW: " << addr << "\n";
//		logger << LOG_L(LOG_DEBUG) << "GWInfoClient: GW PrefLen: " << (int) buffer.pref_len << "\n";
        }
    }

    close(sock);
    return NULL;
}
