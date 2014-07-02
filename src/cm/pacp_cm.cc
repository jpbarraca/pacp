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

//System Includes
#include <unistd.h>
#include <getopt.h>
#include <csignal>
//Specific Includes
#include <iostream>
#include <config.h>
#include <configuration.h>
#include <log.h>
#include <debug.h>
#include <exception.h>
#include "chargingManager.h"

using namespace std;

Configuration* conf;
Log logger(LOG_NONE);
ChargingManager*	cm;

char* cname;
char cwd[1000];

static int quitting = 0;


void catchSignal(int sig) {
    if(sig == SIGSEGV) {
        logger.setLevel(LOG_NONE);
        printBackTrace(cwd, cname, 3);
        exit(-1);
    }

    if(quitting == 1) {
        logger << LOG_L(LOG_FATAL) << "Already exiting... Press again to force\n";
        quitting = 2;
        return;

    } else if(quitting == 2) {
        logger << LOG_L(LOG_FATAL) << "Forced quit! Bye!\n";
        exit(0);
    }

    quitting = 1;
    logger << LOG_L(LOG_FATAL) << "Got a signal. Cleaning up...\n";

    if (conf) {
        delete conf;
        conf = NULL;
    }

    logger << LOG_L(LOG_FATAL) << "Have a nice day!\n";
    exit(0);
}

int main(int argc, char* const argv[]) {
    cm = NULL;
    conf = NULL;
    getcwd(cwd, 200);
    cname = argv[0];
    std::signal(SIGINT, catchSignal);
    std::signal(SIGSEGV, catchSignal);

    try {
        logger.parseCLine(argc, argv, "-q", "-l");
        //Load Configurations
        conf = new Configuration();
        //Start Logging
        logger << LOG_L(LOG_INFO) << "PACP - Polynomial assisted Ad-hoc Charging Protocol v" << VERSION << "   Build date: " << __DATE__ << ", " << __TIME__ << "\n";
        logger << LOG_L(LOG_INFO) << "       by João Paulo Barraca <jpbaraca@av.it.pt> \n";
        logger << LOG_L(LOG_INFO) << "        Instituto de Telecomunicações - Aveiro \n\n";

        if (conf->readCLine(argc, argv) ) {
            delete conf;
            return -1;
        };

        if(!conf->confFileLoaded()) {
            logger << LOG_L(LOG_WARNING) << "Conf file not specified. Loading from /etc/pacp/cm.conf\n";
            conf->readFile("/etc/pacp/cm.conf");
        }

        //Start Logging
        cm = new ChargingManager();
        cm->run ();
        logger << LOG_L(LOG_INFO) << "Exiting\n";

        if (cm) {
            delete cm;
            cm = NULL;
        }

        if (conf) {
            delete conf;
            conf = NULL;
        }

    } catch (Exception e) {
        e.print();
    }

    return 0;
}
