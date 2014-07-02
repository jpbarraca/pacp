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


#ifndef _LOG_H_
#define _LOG_H_

#include <iostream>
#include <string>
#include <pthread.h>

#define LOG_NONE			0
#define LOG_FATAL			1
#define LOG_ERROR			2
#define LOG_INFO			3
#define LOG_WARNING 	4
#define LOG_DEBUG			5

using namespace std;

class LOG_L {

  public:
    LOG_L(int a = 0) {
        level = a;
    }
    ~LOG_L() {}
    int level;
};

class Log {
  public:

    Log(int l = -1) {
        pthread_mutex_init(&_mutLog, NULL);
        _logMaxLevel = l;
        _logLevel = 0;
    };

    ~Log() {};

    inline void setLevel(int l = -1) {
        if( l < LOG_NONE) {
            l = LOG_NONE;
        }

        if(l > LOG_DEBUG) {
            l = LOG_DEBUG;
        }

        _logMaxLevel = l;
    };

    inline Log& operator<< (LOG_L x ) {
        if(_logMaxLevel <= 0) {	//Quiet
            return *this;
        }

        pthread_mutex_lock(&_mutLog);
        _logLevel = x.level;

        if(_logLevel <= _logMaxLevel)
            switch(_logLevel) {
                case LOG_FATAL: {
                    cout << "FATAL: ";
                    break;
                }

                case LOG_ERROR: {
                    cout << "ERROR: ";
                    break;
                }

                case LOG_WARNING: {
                    cout << "WARNING: ";
                    break;
                }

                case LOG_INFO: {
                    cout << "INFO: ";
                    break;
                }

                case LOG_DEBUG: {
                    cout << "DEBUG: ";
                    break;
                }

                default:
                    break;
            }

        //cout.flush();
        pthread_mutex_unlock(&_mutLog);
        return *this;
    };

    /*		friend inline Log& operator<<(Log& l, ostream& (*)(ostream&)){
    			if(_logLevel <= _logMaxLevel)
    				cout <<endl;
    			return l;
    		};*/

    template  <class T> Log& operator<<(T x) {
        if(_logMaxLevel <= 0 ) {
            return *this;
        }

        pthread_mutex_lock(&_mutLog);

        if(_logLevel <= _logMaxLevel) {
            cout << x;
            cout.flush();
        }

        pthread_mutex_unlock(&_mutLog);
        return *this;
    };

    inline void parseCLine(int argc, char* const* argv, char* cquiet, char* clevel) {
        int i;
        int l = -2;

        for(i = 1; i < argc; i++) {
            if(l == -1) {
                sscanf(argv[i], "%u", &l );
                setLevel(l);
                return;
            }

            if(!strcmp(argv[i], cquiet)) {
                setLevel(LOG_NONE);
                return;
            }

            if(!strcmp(argv[i], clevel)) {
                l = -1;
            }
        }
    }
    //	private:
    pthread_mutex_t	_mutLog;
    int _logMaxLevel;
    int _logLevel;
};


#endif
