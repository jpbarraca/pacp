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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "db_mysql.h"

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

int DB::init(const char* host, const char* uname, const char* secret, const char* dbname) {
    mysql_init(&mysql);

    if (!mysql_real_connect
            (&mysql, ((host) ? host : DB_HOST), ((uname) ? uname : DB_USERNAME),
             ((secret) ? secret : DB_PASSWD), ((dbname) ? dbname : DB_DATABASE), 0,
             NULL, 0)) {
        logger << LOG_L(LOG_ERROR) << "DB: " << mysql_error(&mysql) << "\n";
        return DB_ERR;
    }

    _initialized = true;
    logger << LOG_L(LOG_INFO) << "Database Initialized...\n";
    return DB_OK;
}

int DB::getUser(const char* uid) {
    if (!_initialized) {
        return DB_ERR;
    }

    char query[200];
    MYSQL_RES* res;
    int ret = 0;

    if (!uid) {
        return DB_ERR;
    }

    sprintf(query, "SELECT id from User WHERE userid=\"%s\"\n", uid);
    ret = mysql_query(&mysql, query);

    if (ret) {
        logger << LOG_L(LOG_ERROR) << "DB: getUser: " << mysql_error(&mysql) << "\n";
        return DB_ERR;
    }

    res = mysql_use_result(&mysql);

    if (res && mysql_fetch_row(res)) {
        mysql_free_result(res);
        return DB_OK;
    }

    mysql_free_result(res);
    in6_addr addr;
    inet_pton(AF_INET6, uid, &addr);
    struct hostent* host = gethostbyaddr(&addr, sizeof(in6_addr), AF_INET6);

    if (host && strlen(host->h_name)) {
        insertUser(uid, host->h_name, "secret", "");

    } else {
        insertUser(uid, uid, "secret", "");
    }

    //	 free(host);
    return DB_OK;
}

int DB::insertUser(const char* uid, const char* name, const char* secret, const char* comment) {
    char query[200];

    if (!_initialized) {
        return DB_ERR;
    }

    if (!uid || !secret) {
        return DB_ERR;
    }

    strcpy(query, "INSERT INTO User (userid, name, secret");

    if (comment) {
        strcat(query, ", comment");
    }

    strcat(query, ") VALUES (");
    sprintf(query, "%s\"%s\",\"%s\",\"%s\"", query, uid, name, secret);

    if (comment) {
        sprintf(query, "%s, \"%s\"", query, comment);
    }

    strcat(query, ")");

    if (mysql_query(&mysql, query)) {
        logger << LOG_L(LOG_ERROR) << "DB: insertUser: " << mysql_error(&mysql) << "\n";
        return DB_ERR;
    }

    return DB_OK;
}

int DB::insertProof(const char* fromid, const char* toid, unsigned int timestamp, unsigned short length, unsigned char priority) {
    MYSQL_RES* res;
    char query[512];

    if (!_initialized) {
        return DB_ERR;
    }

    getUser(fromid);
    getUser(toid);
    // see if the user exists
    sprintf(query, "SELECT id FROM Session WHERE fromid=\"%s\" AND toid=\"%s\"", fromid, toid);

    if (mysql_query(&mysql, query)) {
        logger << LOG_L(LOG_ERROR) << "DB: insertProof: " << mysql_error(&mysql) << "\n";
        return DB_ERR;
    }

    if ((res = mysql_use_result(&mysql)) == NULL) {
        logger << LOG_L(LOG_ERROR) << "DB: insertProof: " << mysql_error(&mysql) << "\n";
        return DB_ERR;
    }

    if (!mysql_fetch_row(res)) {
        mysql_free_result(res);
        sprintf(query, "INSERT INTO Session (fromid,toid,starttime,endtime) VALUES (\"%s\",\"%s\",%u,%u)", fromid, toid, timestamp, timestamp);

        if (mysql_query(&mysql, query)) {
            logger << LOG_L(LOG_ERROR) << "DB: insertProof: " << mysql_error(&mysql) << "\n";
            return DB_ERR;
        }

    } else {
        mysql_free_result(res);
    }

    sprintf(query, "UPDATE Session SET endtime=%u, npackets=npackets+1, nbytes=nbytes+%u  WHERE fromid=\"%s\" AND toid=\"%s\" ", timestamp, length, fromid, toid);

    if (mysql_query(&mysql, query)) {
        logger << LOG_L(LOG_ERROR) << "DB: insertProof: " << mysql_error(&mysql) << "\n";
        return DB_ERR;
    }

    int err = insertProofUser(fromid, DB_PACKET_SENT, length);

    if (err != DB_OK) {
        return err;
    }

    return insertProofUser(toid, DB_PACKET_RECEIVED, length);
}

int DB::insertProofUser(const char* userid, int charge, int size) {
    // MYSQL_ROW row;
    char query[200];

    if (!_initialized) {
        return DB_ERR;
    }

    getUser(userid);

    switch (charge) {
        //Sent
        case DB_PACKET_SENT:
            sprintf(query, "UPDATE User SET psent=psent+1, bsent=bsent+%u WHERE userid=\"%s\"", size, userid);
            break;

        //Recvd

        case DB_PACKET_RECEIVED:
            sprintf(query, "UPDATE User SET preceived=preceived+1, breceived=breceived+%u WHERE userid=\"%s\"", size, userid);
            break;

        //Fwr

        case DB_PACKET_FORWARDED:
            sprintf(query, "UPDATE User SET pforwarded=pforwarded+1, bforwarded=bforwarded+%u WHERE userid=\"%s\"", size, userid);
            break;
    }

    if (mysql_query(&mysql, query)) {
        logger << LOG_L(LOG_ERROR) << "DB: insertProofUser" << mysql_error(&mysql) << "\n";
        return DB_ERR;
    }

    return DB_OK;
}


char* DB::getUserByID(const char* id) {
    MYSQL_RES* res;
    MYSQL_ROW row;
    char query[200];

    if (!_initialized) {
        return NULL;
    }

    sprintf(query, "SELECT userid FROM User WHERE userid=\"%s\"", id);

    if (mysql_query(&mysql, query)) {
        logger << LOG_L(LOG_ERROR) << "DB: GetUserByID: " << mysql_error(&mysql) << "\n";
        return NULL;
    }

    res = mysql_use_result(&mysql);

    if ((row = mysql_fetch_row(res))) {
        char* name = new char[strlen(row[0]) + 1];
        memcpy(name, row[0], strlen(row[0]) + 1);
        mysql_free_result(res);
        return name;
    }

    return NULL;
}

char* DB::getSecretByID(const char* id) {
    MYSQL_RES* res = NULL;
    MYSQL_ROW row;
    char query[200];

    if (!_initialized) {
        return NULL;
    }

    //    getUser(id);
    sprintf(query, "SELECT secret FROM User WHERE userid=\"%s\"", id);

    if (mysql_query(&mysql, query)) {
        logger << LOG_L(LOG_ERROR) << "DB: GetSecretByID: " << mysql_error(&mysql) << "\n";
        return NULL;
    }

    res = mysql_use_result(&mysql);

    if ( (row = mysql_fetch_row(res)) ) {
        char* secret = new char[strlen(row[0]) + 1];
        strcpy(secret, row[0]);
        mysql_free_result(res);
        return secret;
    }

    mysql_free_result(res);
    getUser(id);
    return getSecretByID(id);
}
