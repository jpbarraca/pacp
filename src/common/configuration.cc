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

#include <fstream>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "exception.h"
#include "configuration.h"
extern "C"
{
#include <getopt.h>
}

#include "log.h"

static struct option clOptions[] = {
    {
        "loglevel", 1, 0, 'l'
    },

    {"quiet", 0, 0, 'q'},
    {"config", 1, 0, 'c'},
    {0, 0, 0, 0}
};

Configuration::Configuration() {
    setDefaults();
}

Configuration::Configuration(char* confFile) {
    setDefaults();
    _confFileNeeded = true;

    if( readFile(confFile) < 0 ) {
        MYTHROW1("Unable to open configuration file");
    }
}

void Configuration::setDefaults() {
    _logLevel = LOG_INFO;
    _quiet = false;
    char aux[100];
    gethostname(aux, 16);
    _useCryptoData = _useCryptoControl = false;
    _userID = aux;
    _routingProto = ROUTING_PROTO_STATIC;
    _opRSAKeyFile = "/etc/pacp/opRSAkey.pem";
    _opECKeyFile = "/etc/pacp/opECkey.pem";
    _hostKeyFile = "/etc/pacp/hostkey.pem";
    _userSecret = "secret";
    _networkSecret = "secret";
    _useFilterMark = true;
    _signallingPort = 0;
    _chargingManagerSignallingPort = 9999;
    _signallingPort = 9999;
    _confFileLoaded = false;
    _confFileNeeded = false;
    _coreDevName = "";
    _adhocDevName = "";
    _startupCommand = "";
    _terminateCommand = "";
    _confFileLoaded = false;
    _authenticate = false;
    //Database
    _dbHostname = "127.0.0.1";
    _dbDatabase = "pacp";
    _dbUsername = "root";
    _dbPassword = "";
    memset(&_networkAdhocAddress, 0, sizeof(in6_addr));
    memset(&_networkAdhocAddressMask, 0, sizeof(in6_addr));
    memset(&_networkCoreAddress, 0, sizeof(in6_addr));
    memset(&_networkCoreAddressMask, 0, sizeof(in6_addr));
    memset(&_chargingManagerAddress, 0, sizeof(in6_addr));
    memset(&_nodeAddress, 0, sizeof(in6_addr));
    _chargingManagerAddress_set = false;
}

int Configuration::readCLine(int argc, char* const argv[]) {
    int optIndex = 0;
    int opt = 0;

    while (1) {
        opt = getopt_long (argc, argv, "l:c:q" , clOptions, &optIndex);

        if (opt == -1) {
            break;
        }

        switch (opt) {
            case '?': {
                logger << LOG_L(LOG_DEBUG) << "Usage Information: " << "\n";
                logger << LOG_L(LOG_DEBUG) << "\n";
                logger << LOG_L(LOG_DEBUG) << "  -l N        - Set the log level. 0=NONE ... 6=DEBUG" << "\n";
                logger << LOG_L(LOG_DEBUG) << "  -q          - Quiet mode" << "\n";
                logger << LOG_L(LOG_DEBUG) << "  -c file     - Load settings from config file" << "\n";
                logger << LOG_L(LOG_DEBUG) << "\n";
                return -1;
            }

            case 'l': {
                sscanf(optarg, "%d", &_logLevel);

                if (_logLevel > LOG_DEBUG) {
                    _logLevel = LOG_DEBUG;
                }

                break;
            }

            case 'q': {
                _quiet = true;
                break;
            }

            case 'c': {
                sscanf(optarg, "%s", _configFile);
                readFile(_configFile);
                break;
            }
        }
    }

    if (_confFileNeeded && !_confFileLoaded) {
        logger << LOG_L(LOG_DEBUG) << "Must specifiy conf file or use the default one" << "\n";
        return -1;
    }

    return 0;
}

int Configuration::readFile(char* filename) {
    fstream confFile(filename, ios::in);

    if (!confFile.is_open()) {
        return -1;
    }

    //	logger<<LOG_L(LOG_DEBUG)<<"Open "<<filename<<" for read was successful\n";
    confFile.seekg(0);
    _confFileLoaded = true;
    char	line[1024];
    memset(line, 0, 1024);

    while (confFile >> line) {
        if (line[0] == 0) {
            return 0;
        }

        if ( line[0] == '#' || line[0] == ' ') {
            continue;
        }

        //Upcase until we find an equal '='
        unsigned int i = 0;

        for (i = 0; i < strlen(line); i++) {
            if (line[i] >= 'a' && line[i] <= 'z') {
                line[i] -= 32;

            } else if (line[i] == '=') {
                break;
            }
        }

        if (!strncmp(line, "FILTERMARK=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param) {
                logger << LOG_L(LOG_DEBUG) << "Invalid value for parameter FILTERMARK: " << param << "\n";
                confFile.close();
                return -1;
            }

            if (!strcmp(param, "true")) {
                logger << LOG_L(LOG_DEBUG) << "-  Enabling Filter Mark\n";
                _useFilterMark = true;

            } else if (!strcmp(param, "false")) {
                logger << LOG_L(LOG_DEBUG) << "-  Disabling Filter Mark\n";
                _useFilterMark = false;

            } else {
                logger << LOG_L(LOG_DEBUG) << "Invalid value for parameter FILTERMARK\n";
                logger << LOG_L(LOG_DEBUG) << param << "\n";
                confFile.close();
                return -1;
            }

            continue;
        }

        if (!strncmp(line, "CHARGINGMANAGER.ADDRESS=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || inet_pton(AF_INET6, param, &_chargingManagerAddress) < 0) {
                logger << LOG_L(LOG_DEBUG) << "Error setting chargingmanager.address\n";
                confFile.close();
                return -1;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  DefaultChargingManager: " << param << "\n";
                _chargingManagerAddress_set = true;
            }

            continue;
        }

        if (!strncmp(line, "SIGNALLING.PORT=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");
            _signallingPort = 0;
            sscanf(param, "%u", &_signallingPort);

            if (!param || _signallingPort == 0 ) {
                logger << LOG_L(LOG_DEBUG) << "Error setting signalling.port\n";
                confFile.close();
                return -1;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  SignallingPort: " << _signallingPort << "\n";
            }

            continue;
        }

        if (!strncmp(line, "CHARGINGMANAGER.SIGNALLING.PORT=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");
            _signallingPort = 0;
            sscanf(param, "%u", &_chargingManagerSignallingPort);

            if (!param || _chargingManagerSignallingPort == 0 ) {
                logger << LOG_L(LOG_DEBUG) << "Error setting chargingmanager.signalling.port\n";
                confFile.close();
                return -1;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  ChargingManagerSignallingPort: " << _chargingManagerSignallingPort << "\n";
            }

            continue;
        }

        if (!strncmp(line, "NETWORK.ADHOC.ADDRESS=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || inet_pton(AF_INET6, param, &_networkAdhocAddress) < 0) {
                logger << LOG_L(LOG_DEBUG) << "Error setting ad-hoc address\n";
                confFile.close();
                return -1;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  Adhoc Network Address: " << param << "\n";
            }

            continue;
        }

        if (!strncmp(line, "NETWORK.ADHOC.ADDRESS.MASK=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || inet_pton(AF_INET6, param, &_networkAdhocAddressMask) < 0) {
                logger << LOG_L(LOG_DEBUG) << "Error setting ad-hoc address mask\n";
                confFile.close();
                return -1;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  Adhoc Network Address Mask: " << param << "\n";
            }

            continue;
        }

        if (!strncmp(line, "NODE.ADDRESS=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || inet_pton(AF_INET6, param, &_nodeAddress) < 0) {
                logger << LOG_L(LOG_DEBUG) << "Error setting Node address\n";
                confFile.close();
                return -1;
            }

            logger << LOG_L(LOG_DEBUG) << "-  node Address: " << param << "\n";
            _userID = param;
//			memcpy(_userID, &_nodeAddress, sizeof(in6_addr));
            continue;
        }

        if (!strncmp(line, "NETWORK.CORE.ADDRESS=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || inet_pton(AF_INET6, param, &_networkCoreAddress) < 0) {
                logger << LOG_L(LOG_DEBUG) << "Error setting core address\n";
                confFile.close();
                return -1;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  Core Network Address: " << param << "\n";
            }

            continue;
        }

        if (!strncmp(line, "NETWORK.CORE.ADDRESS.MASK=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || inet_pton(AF_INET6, param, &_networkCoreAddressMask) < 0) {
                logger << LOG_L(LOG_DEBUG) << "Error setting core address mask\n";
                confFile.close();
                return -1;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  Core Network Address Mask: " << param << "\n";
            }

            continue;
        }

        if (!strncmp(line, "NETWORK.CORE.INTERFACE=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || !strcmp(param, "")) {
                logger << LOG_L(LOG_DEBUG) << "Error setting core interface\n";
                confFile.close();
                return -1;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  Core Network Interface: " << param << "\n";
            }

            _coreDevName = param;
            continue;
        }

        if (!strncmp(line, "NETWORK.ADHOC.INTERFACE=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || !strcmp(param, "")) {
                logger << LOG_L(LOG_DEBUG) << "Error setting adhoc interface\n";
                confFile.close();
                return -1;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  Adhoc Network Interface: " << param << "\n";
            }

            _adhocDevName = param;
            continue;
        }

        if (!strncmp(line, "COMMAND.STARTUP=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || !strcmp(param, "" ) ) {
                _terminateCommand = "";
                continue;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  Startup Command: " << param << "\n";
            }

            _startupCommand = param;
            continue;
        }

        if (!strncmp(line, "COMMAND.TERMINATE=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || !strcmp(param, "" ) ) {
                _terminateCommand = "";
                continue;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  Terminate Command: " << param << "\n";
            }

            _terminateCommand = param;
            continue;
        }

        if (!strncmp(line, "DB.HOSTNAME=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || !strcmp(param, "" ) ) {
                continue;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  DB Hostname: " << param << "\n";
            }

            _dbHostname = param;
            continue;
        }

        if (!strncmp(line, "DB.DATABASE=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || !strcmp(param, "" ) ) {
                continue;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  DB Name: " << param << "\n";
            }

            _dbDatabase = param;
            continue;
        }

        if (!strncmp(line, "DB.USERNAME=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || !strcmp(param, "" ) ) {
                continue;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  DB Username: " << param << "\n";
            }

            _dbUsername = param;
            continue;
        }

        if (!strncmp(line, "DB.PASSWORD=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param ) {
                continue;

            } else {
                _dbPassword = param;
                logger << LOG_L(LOG_DEBUG) << "-  DB Password: ";
                unsigned int j;

                for(j = 0; j < strlen(param); j++) {
                    logger << LOG_L(LOG_DEBUG) << "*";
                }

                logger << LOG_L(LOG_DEBUG) << "\n";
            }

            continue;
        }

        if (!strncmp(line, "CHARGINGMANAGER.AUTH=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param ) {
                continue;

            } else {
                if(!strcmp(param, "NO") || !strcmp(param, "FALSE") || !strcmp(param, "no") || !strcmp(param, "false")) {
                    _authenticate = false;

                } else {
                    if(!strcmp(param, "YES") || !strcmp(param, "TRUE") || !strcmp(param, "yes") || !strcmp(param, "true")) {
                        _authenticate = true;
                    }
                }

                logger << LOG_L(LOG_DEBUG) << "-  ChargingManager Auth: " << _authenticate << "\n";
            }

            continue;
        }

        if (!strncmp(line, "ROUTING.PROTO=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (param ) {
                if(!strcmp(param, "STATIC") || !strcmp(param, "static")) {
                    _routingProto = ROUTING_PROTO_STATIC;

                } else if(!strcmp(param, "AODV") || !strcmp(param, "aodv")) {
                    _routingProto = ROUTING_PROTO_AODV;

                } else if(!strcmp(param, "OLSR") || !strcmp(param, "olsr")) {
                    _routingProto = ROUTING_PROTO_OLSR;
                }

                logger << LOG_L(LOG_DEBUG) << "-  Routing Proto: " << param << "\n";
            }

            continue;
        }

        if (!strncmp(line, "OPERATOR.RSAKEY.FILE=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || !strcmp(param, "" ) ) {
                continue;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  Operator RSA Key file: " << param << "\n";
            }

            _opRSAKeyFile = param;
            continue;
        }

        if (!strncmp(line, "OPERATOR.ECKEY.FILE=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || !strcmp(param, "" ) ) {
                continue;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  Operator EC Key file: " << param << "\n";
            }

            _opECKeyFile = param;
            continue;
        }

        if (!strncmp(line, "HOST.ECKEY.FILE=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || !strcmp(param, "" ) ) {
                continue;

            } else {
                logger << LOG_L(LOG_DEBUG) << "-  Host EC Key file: " << param << "\n";
            }

            _hostKeyFile = param;
            continue;
        }

        if (!strncmp(line, "CRYPTO.CONTROL.ENABLE=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || !strcmp(param, "" ) ) {
                continue;

            } else if(!strncmp(param, "true", 4) || !strncmp(param, "TRUE", 4)) {
                _useCryptoControl = true;
                logger << LOG_L(LOG_DEBUG) << "-  Enabling Crypto for Control Packets\n";

            } else {
                _useCryptoControl = false;
                logger << LOG_L(LOG_DEBUG) << "-  Disabling Crypto for Control Packets\n";
            }

            continue;
        }

        if (!strncmp(line, "CRYPTO.DATA.ENABLE=", i)) {
            strtok(line, "=");
            char* param = strtok(NULL, "=");

            if (!param || !strcmp(param, "" ) ) {
                continue;

            } else if(!strncmp(param, "true", 4) || !strncmp(param, "TRUE", 4)) {
                _useCryptoData = true;
                logger << LOG_L(LOG_DEBUG) << "-  Enabling Crypto for Data Packets\n";

            } else {
                _useCryptoData = false;
                logger << LOG_L(LOG_DEBUG) << "-  Disabling Crypto for Data Packets\n";
            }

            continue;
        }

        cout << "Unknown option in config file: -->" << line << "<-- i=" << i << "\n";
    }

    //using the default port
    if (_signallingPort && ! _chargingManagerSignallingPort) {
        _chargingManagerSignallingPort = _signallingPort;
    }

    _confFileLoaded = true;
    confFile.close();
    return 0;
}
