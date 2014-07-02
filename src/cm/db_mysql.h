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

#ifndef DB_INTERFACE_H
#define DB_INTERFACE_H

#include <mysql/mysql.h>
#include <stdint.h>
#include <log.h>

#define DB_HOST		"127.0.0.1"
#define DB_USERNAME	"root"
#define DB_PASSWD	""
#define DB_DATABASE	"pacp"

#define DB_OK	0
#define DB_ERR	-1

#define DB_PACKET_SENT 0
#define DB_PACKET_RECEIVED 1
#define DB_PACKET_FORWARDED 2

#define USER_DEFAULT_SECRET = "secret"

extern Log logger;

class DB {

  public:
    DB( const char* host = DB_HOST, const char* uname = DB_USERNAME, const char* passwd = DB_PASSWD, const char* dbname = DB_DATABASE) {
        _initialized = false;
        init(host, uname, passwd, dbname);
    }

    ~DB() {
        mysql_close(&mysql);
    }


    int init(const char* host, const char* uname, const char* pass, const char* dbname);
    int getUser(const char* uid);
    int insertUser(const char* uid, const char* name, const char* pass, const char* comment);
    //    uint64_t insertPacket(const char* fromid, const char* toid, uint32_t timestamp, unsigned short length, uint8_t priority, uint64_t *packet_id);
    int insertProofUser(const char* userid, int charge, int size);
    char* getUserByID(const char* uid);
    char* getSecretByID(const char* uid);

    int insertProof(const char*, const char*, unsigned int, short unsigned int, unsigned char);

  private:
    MYSQL mysql;
    bool _initialized;
};

#endif
