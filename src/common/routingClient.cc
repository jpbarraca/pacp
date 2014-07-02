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


#include "routingClient.h"

extern "C"
{
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
}

#include <iostream>
#include "log.h"

#define AODV_PACP_INTERFACE_PATH  "/tmp/aodv_macp.sock"
#define PACP_INTERFACE_PATH "/tmp/pacp.sock"

extern Log logger;

/* Message Header */

typedef struct {
    uint32_t code;
    uint32_t size; //bytes
}

msgHdr_t;

#define MSG_GET_NEXT_HOP_LIST       1
#define MSG_NEXT_HOP_LIST           2

typedef struct {

    struct in6_addr dst;
}

msgGetNextHopList_t;


typedef struct {

    struct in6_addr dst;
    uint32_t	nb_path;                //append to this structure a list of next hop
    in6_addr	nextHop[];
}

msgNextHopList_t;

char* ip6_to_str(struct in6_addr addr) {
    char* str;
    static char ip6_buf[4][40];
    static int count = 0;
    int which;
    which = (count % 4);
    bzero(ip6_buf[which], 40);
    sprintf(ip6_buf[which], "%x:%x:%x:%x:%x:%x:%x:%x",
            (int)ntohs(addr.s6_addr16[0]), (int)ntohs(addr.s6_addr16[1]),
            (int)ntohs(addr.s6_addr16[2]), (int)ntohs(addr.s6_addr16[3]),
            (int)ntohs(addr.s6_addr16[4]), (int)ntohs(addr.s6_addr16[5]),
            (int)ntohs(addr.s6_addr16[6]), (int)ntohs(addr.s6_addr16[7]));
    //printf("count = %d, which = %d\n", count, which);
    str = ip6_buf[which];
    count++;
    return str;
}

RoutingClient::RoutingClient(uint8_t rp) {
    _routingProto = rp;

    if (rp == ROUTING_PROTO_STATIC) {
        logger << LOG_L(LOG_INFO) << "RoutingClient: Setting STATIC Routing\n";
        _rtsocket = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    } else if (rp == ROUTING_PROTO_AODV) {
        signal(SIGPIPE, SIG_IGN);
        logger << LOG_L(LOG_INFO) << "RoutingClient: Setting AODV Routing\n";
        _aodvConnected = connectAODV();
    }

    _lastClean = 0;
}

RoutingClient::~RoutingClient() {
}

bool RoutingClient::connectAODV() {
    logger << LOG_L(LOG_DEBUG) << "RoutingClient: Connecting to AODV at " << AODV_PACP_INTERFACE_PATH << "\n";
    memset(&_sockAodv, 0, sizeof(_sockAodv));
    _sockAodv.sun_family = AF_UNIX;
    strncpy (_sockAodv.sun_path, AODV_PACP_INTERFACE_PATH, sizeof (_sockAodv.sun_path) - 1);
    _sockASize = sizeof(_sockAodv);
    _aodvSocket = socket(PF_LOCAL, SOCK_STREAM, 0);

    if (_aodvSocket <= 0) {
        perror("ERROR: RoutingClient: Error creating AODV Socket: ");
        return false;
    }

    logger << LOG_L(LOG_DEBUG) << "RoutingClient: AODV: Socket=" << _aodvSocket << "\n";

    if (connect(_aodvSocket, (sockaddr*) &_sockAodv, _sockASize)) {
        logger << LOG_L(LOG_DEBUG) << ("ERROR: RoutingClient: Could not connect AODV: ");
        close(_aodvSocket);
        return false;
    }

    logger << LOG_L(LOG_DEBUG) << "RoutingClient: Connected to AODV\n";
    return true;
}

void RoutingClient::updateRT() {
}

int8_t RoutingClient::directRoute(in6_addr* address) {
    switch (_routingProto) {
        case ROUTING_PROTO_STATIC:
            return directRoute_kernel(address);

        case ROUTING_PROTO_AODV:
            return directRoute_aodv(address);
            //	case ROUTING_PROTO_OLSR:  	return directRoute_olsr(address);
    }

    return -1;
}

int8_t RoutingClient::directRoute_aodv(in6_addr* address) {
    uint8_t	buffer[sizeof(msgHdr_t) + sizeof(msgGetNextHopList_t)];
    uint8_t	recvBuffer[1024];
    uint32_t	currTime = time(NULL);
    routingTableEntry_t* rt = getRTEntry(address);
    logger << LOG_L(LOG_DEBUG) << "RoutingClient: AODV: Checking route\n";

    //Check if cache still valid

    if (((currTime - rt->lastUpdate) < ROUTE_CACHE_ENTRY_TIMEOUT)) {
        if (rt->lastResult >= 0) {
            logger << LOG_L(LOG_DEBUG) << "RoutingClient: AODV: Answer from cache\n";
            return rt->lastResult;
        }
    }

    if (!_aodvConnected) {
        _aodvConnected = connectAODV();

        if (!_aodvConnected) {
            return false;
        }
    }

    memset(buffer, 0, sizeof(buffer));
    msgHdr_t* msgHead = (msgHdr_t*) buffer;
    msgGetNextHopList_t* msgGNH = (msgGetNextHopList_t*) (buffer + sizeof(msgHdr_t));
    msgHead->code = MSG_GET_NEXT_HOP_LIST;
    msgHead->size = sizeof(msgGetNextHopList_t);
    memcpy(&msgGNH->dst, address, sizeof(in6_addr));
    logger << LOG_L(LOG_DEBUG) << "RoutingClient: AODV is connected, sending request with size=" << sizeof(msgGetNextHopList_t) + sizeof(msgHdr_t) << " ms=" << msgHead->size << "\n";

    if (send(_aodvSocket, buffer, sizeof(msgHdr_t) + sizeof(msgGetNextHopList_t), 0) < 0) {
        logger << LOG_L(LOG_DEBUG) << "RoutingClient: Error communicating with AODV.\n";

        if(rt && rt->lastResult >= 0) {
            logger << LOG_L(LOG_DEBUG) << "RoutingClient: Answer from cache.\n";
            return rt->lastResult;
        }

        logger << LOG_L(LOG_DEBUG) << "RoutingClient: Assuming not neighbour.\n";
//		perror("send()");
        _aodvConnected = false;
        close(_aodvSocket);
        return false;
    }

    logger << LOG_L(LOG_DEBUG) << "RoutingClient: AODV: Request Sent \n";
    fd_set socks;
    FD_ZERO(&socks);
    FD_SET(_aodvSocket, &socks);
    timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    int ret = select(_aodvSocket + 1, &socks, NULL, NULL, &tv);

    if (ret == 0) {
        cerr << "Timeout While waiting for answer from AODV\n";
        return false;
    }

    if (ret < 0) {
        cerr << "Error reading from AODV socket. Assuming not neighbour\n";
        perror("select()");
        return false;
    }

    //Clean the buffer
    memset(recvBuffer, 0, sizeof(recvBuffer));
    int len = recv(_aodvSocket, recvBuffer, sizeof(recvBuffer), 0);

    if (len < 0) {
        logger << LOG_L(LOG_ERROR) << "RoutingClient: Error reading from AODV socket. Assuming not neighbour\n";
        _aodvConnected = false;
        close(_aodvSocket);
        return false;
    }

    msgHead = (msgHdr_t*) recvBuffer;
    msgNextHopList_t*	msgNHL = (msgNextHopList_t*) (recvBuffer + sizeof(msgHdr_t));

    if (msgHead->code != MSG_NEXT_HOP_LIST) {
        logger << LOG_L(LOG_DEBUG) << "RoutingClient: AODV: Unknown message from AOMDV Code=" << hex << msgHead->code << dec << "\n";
        return false;
    }

    if (msgHead->size < sizeof(in6_addr)) {
        logger << LOG_L(LOG_DEBUG) << "RoutingClient: AODV: Invalid message size with " << msgHead->size << " b\n";
        return false;
    }

    /*
    	if(memcmp(&msgNHL->dst,address,sizeof(in6_addr)))
    	{
    		logger<<LOG_L(LOG_DEBUG)<<"RoutingClient: AODV: Got a response for an invalid destination\n";
    	        logger<<LOG_L(LOG_DEBUG)<<"RoutingClient: AODV: Req: "<<ip6_to_str(*address)<<" Got: "<<ip6_to_str(msgNHL->dst)<<"\n";

    		return false;
    	}
    */
    logger << LOG_L(LOG_DEBUG) << "RoutingClient: AODV: Got " << msgNHL->nb_path << " entries\n";
    unsigned int i;

    for (i = 0; i < msgNHL->nb_path; i++) {
        if (!memcmp(&msgNHL->nextHop[i], address, sizeof(in6_addr))) {
            rt->lastUpdate = currTime;
            rt->lastResult = true;
            //			logger<<LOG_L(LOG_DEBUG)<<"RoutingClient: AODV: Direct Route: Dst: "<<ip6_to_str(*address)<<" NXT: "<<ip6_to_str(msgNHL->nextHop[i])<<"\n";
            logger << LOG_L(LOG_DEBUG) << "RoutingClient: AODV: Direct Route\n";
            return true;
        }
    }

    //	logger<<LOG_L(LOG_DEBUG)<<"RoutingClient: AODV: NOT a Direct Route: Dst: "<<ip6_to_str(*address)<<" NXT: "<<ip6_to_str(msgNHL->nextHop[i])<<"\n";
    logger << LOG_L(LOG_DEBUG) << "RoutingClient: AODV: NOT a Direct Route\n";
    rt->lastUpdate = currTime;
    rt->lastResult = false;
    return false;
}

int8_t RoutingClient::directRoute_kernel(in6_addr* address) {
    uint32_t	currTime = time(NULL);
    routingTableEntry_t* rt = getRTEntry(address);

    //Check if cache still valid

    if (currTime - rt->lastUpdate < ROUTE_CACHE_ENTRY_TIMEOUT && rt->lastResult != -1) {
//		fprintf(stderr,"In Cache\n");
        return rt->lastResult;

    } else {
//	fprintf(stderr,"Not in Cache Time: %d, Res: %d\n", currTime - rt->lastUpdate, rt->lastResult);
    }

    uint32_t nlsockfd, len;
    struct sockaddr_in6 mnaddr;
//	struct sockaddr_in6 addr;
    struct {

        struct nlmsghdr n;

        struct rtmsg r;
        char data[1024];
    }
    req;
    struct rtattr* attr;
    bzero(&mnaddr, sizeof(mnaddr));
    mnaddr.sin6_family = AF_INET6;
    memcpy(&mnaddr.sin6_addr, address, sizeof(in6_addr));
    nlsockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (nlsockfd < 0) {
        fprintf(stderr, "Error 2 from kernel consulting rt table\n");
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len =
        NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.r))) +
        RTA_LENGTH(sizeof(mnaddr.sin6_addr));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type = RTM_GETROUTE;
    req.r.rtm_family = AF_INET6;
    req.r.rtm_dst_len = sizeof(in6_addr);
    attr = (rtattr*)(void*) (
               ((char*) & req) + NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.r)))
           );
    attr->rta_type = RTA_DST;
    attr->rta_len = RTA_LENGTH(sizeof(mnaddr.sin6_addr));
    memcpy(RTA_DATA(attr), &mnaddr.sin6_addr, sizeof(mnaddr.sin6_addr));

    if (send(nlsockfd, &req, req.n.nlmsg_len, 0) < 0) {
        close(nlsockfd);
        fprintf(stderr, "Error 3 from kernel consulting rt table\n");
        return -1;
    }

    len = recv(nlsockfd, &req, sizeof(req), 0);

    if (len < 0) {
        close(nlsockfd);
        fprintf(stderr, "Error 4 from kernel consulting rt table\n");
        return -1;
    }

    close(nlsockfd);

    if (len < sizeof(struct nlmsghdr)) {
        fprintf(stderr, "Error 5 from kernel consulting rt table\n");
        return -1;
    }

    if (len < req.n.nlmsg_len) {
        fprintf(stderr, "Error 6 from kernel consulting rt table\n");
        return -1;
    }

    if (req.n.nlmsg_type == NLMSG_ERROR) {
        fprintf(stderr, "Error 7 from kernel consulting rt table\n");
        return -1;
    }

    len -= NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.r)));

    while (len > sizeof(*attr) && len > attr->rta_len) {
//		printf("RTA_TYPE: %d\n",attr->rta_type);
        if(attr->rta_type == RTA_GATEWAY) {
            in6_addr* gw = ((in6_addr*) RTA_DATA(attr) );

//			printf("REQ: %s GOT: %s\n",ip6_to_str(*address),ip6_to_str(*gw));
            if(!memcmp(gw, address, sizeof(in6_addr))) {
                rt->lastUpdate = currTime;
                rt->lastResult = 1;
                //			fprintf(stderr,"Returning 1: %u\n", currTime);
                //			return 1;

            } else {
                rt->lastUpdate = currTime;
                rt->lastResult = 0;
//				fprintf(stderr,"Returning 0\n");
                //			return 0;
            }
        }

        len -= attr->rta_len;
        attr = (rtattr*) (((char*) attr) + attr->rta_len);
    }

    if(rt->lastUpdate == currTime) {
        return rt->lastResult;

    } else {
        return -1;
    }
}

bool RoutingClient::isNextHop(in6_addr* address) {
    if (directRoute(address) <= 0) {
        return false;
    }

    return true;
}

routingTableEntry_t* RoutingClient::getRTEntry(in6_addr* address) {
    vector<routingTableEntry_t*>::iterator itRoute = _routeCache.begin();
    uint32_t	currTime = time(NULL);

    //First clean old entries, if

    if (currTime - _lastClean > 30) {
        _lastClean = currTime;

        while (itRoute != _routeCache.end()) {
            if (currTime - (*itRoute)->lastUpdate > ROUTE_CACHE_ENTRY_EXPIRE ) {
                delete (*itRoute);
                (*itRoute) = NULL;
                _routeCache.erase(itRoute);

            } else {
                itRoute++;
            }
        }
    }

    while (itRoute != _routeCache.end()) {
        if (!memcmp(address, &(*itRoute)->address, sizeof(in6_addr))) {
//			fprintf(stderr,"RT Found\n");
            return (*itRoute);
        }

        itRoute++;
    }

    routingTableEntry_t*	rt = new routingTableEntry_t;
    memcpy(&rt->address, address, sizeof(in6_addr));
    rt->lastResult = -1;
    rt->lastUpdate = 0;
    _routeCache.push_back(rt);
//	fprintf(stderr,"RT NOT Found\n");
    return rt;
}
