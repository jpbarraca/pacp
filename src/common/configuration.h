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

//configuration.h
//Definition of the configuration class

#ifndef _CONFIGURATION_H
#define _CONFIGURATION_H
extern "C"
{
#include <getopt.h>
};

#include "log.h"
#include <netinet/ip6.h>
#include "routingClient.h"

#define CONF_USERID_SIZE  sizeof(in6_addr)

extern Log logger;

class Configuration {

  public:
    Configuration();
    Configuration(char*);
    ~Configuration() {};

    /**
        Parses and loads a configuration from a command line
        \param nargs The number of arguments
        \param args The actual arguments
        \return The error code of the operation
    */
    int readCLine(int nargs, char* const args[]);

    /**
        Parses and loads a configuration from a file
        \param filename The filename with path to load
        \return The error code of the operation
    */
    int readFile(char* filename);

    /**
        Returns wether the configuration file was already loaded
        \return Boolean response
    */
    bool	confFileLoaded() {
        return _confFileLoaded;
    }

    /**
        Initializes configuration with default values
    */
    void setDefaults();

    /**
        Returns the Log level configured
        \return log level configured
    */
    inline int getLogLevel() {
        return (_quiet ? LOG_NONE : _logLevel);
    }

    /**
        Returns the User Identifier
        \return string with the user identifier
    */
    inline string& getUserID() {
        return _userID;
    }

    /*
        Returns wether authentication should be used
        \return boolean response
    */
    inline bool getAuthEnabled() {
        return _authenticate;
    }

    /**
        Returns the IPv6 address of the default Charging Manager
        \return Pointer to a in6_addr* containing the address
    */
    inline in6_addr* getDefaultChargingManager() {
        return (_chargingManagerAddress_set ? &_chargingManagerAddress : NULL);
    }

    /**
        Sets the address of the default Charging Manager
        \param addr Address of the Charging Manager
    */
    inline void setDefaultChargingManager(in6_addr& addr) {
        _chargingManagerAddress_set = true;
        memcpy(&_chargingManagerAddress, &addr, sizeof(in6_addr));
        return ;
    }

    /**
        Returns wether it should be used cryptography (SIGN+Verify) in data packets
        \return boolean value. True if crypto must be used
    */
    inline bool	getUseCryptoData() {
        return _useCryptoData;
    };

    /**
        Returns wether it should be used cryptography (SIGN+Verify) in control packets
        \return boolean value. True if crypto must be used
    */
    inline bool	getUseCryptoControl() {
        return _useCryptoControl;
    };


    inline string& getUserSecret() {
        return _userSecret;
    }

    inline string& getOperatorRSAKeyFile() {
        return _opRSAKeyFile;
    }
    inline string& getOperatorECKeyFile() {
        return _opECKeyFile;
    }

    inline string& getHostKeyFile() {
        return _hostKeyFile;
    }

    inline in6_addr* getMyAddress() {
        return &_nodeAddress;
    }

    inline in6_addr* getNetworkAdhocAddress() {
        return &_networkAdhocAddress;
    }

    inline in6_addr* getNetworkAdhocAddressMask() {
        return &_networkAdhocAddressMask;
    }

    inline string&	getNetworkSecret() {
        return _networkSecret;
    }

    inline uint16_t	getSignallingPort() {
        return _signallingPort;
    }

    inline bool getFilterMarkStatus() {
        return _useFilterMark;
    }

    inline bool	getConfFileStatus() {
        return _confFileLoaded;
    }

    inline string&	getAdhocDev() {
        return _adhocDevName;
    }

    inline string&	getCoreDev() {
        return _coreDevName;
    }

    //Start and termination commands
    inline string&	getStartupCommand() {
        return _startupCommand;
    }

    inline string&  getTerminateCommand() {
        return _terminateCommand;
    }

    //Database
    inline string&	getDBHostname() {
        return _dbHostname;
    }
    inline string&	getDBDatabase() {
        return _dbDatabase;
    }
    inline string&	getDBUsername() {
        return _dbUsername;
    }
    inline string&	getDBPassword() {
        return _dbPassword;
    }

    //Routing
    inline uint32_t	getRoutingProto() {
        return _routingProto;
    }

  protected:
    int _logLevel;
    bool	_confFileLoaded;
    bool _confFileNeeded;

    bool _quiet;
    bool	_authenticate;

    string	_opRSAKeyFile;
    string  _opECKeyFile;
    string	_hostKeyFile;
    bool		_useCryptoData;
    bool		_useCryptoControl;

    string	_userID;
    string _userSecret;
    string _networkSecret;
    string	_adhocDevName;
    string	_coreDevName;
    in6_addr _chargingManagerAddress;
    bool	_chargingManagerAddress_set;
    uint32_t	_signallingPort;
    uint32_t	_chargingManagerSignallingPort;

    char	_configFile[1024];

    //Database
    string		_dbHostname;
    string		_dbDatabase;
    string		_dbUsername;
    string		_dbPassword;

    in6_addr	_nodeAddress;
    in6_addr	_networkAdhocAddress;
    in6_addr	_networkAdhocAddressMask;
    in6_addr	_networkCoreAddress;
    in6_addr	_networkCoreAddressMask;
    bool	_useFilterMark;

    string	_startupCommand;
    string  _terminateCommand;

    uint32_t _routingProto;

};

#endif
