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
#include <config.h>
#include <unistd.h>
#include <getopt.h>
#include <csignal>

//Specific Includes
#include "configuration.h"
#include "chargingAgent.h"
#include "log.h"
#include "exception.h"
#include "debug.h"

using namespace std;

Configuration* conf;
ChargingAgent* agent;
Log logger;

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

    }	else if(quitting == 2) {
        logger << LOG_L(LOG_FATAL) << "Forced quit! Bye!\n";
        exit(0);
    }

    quitting = 1;
    logger << LOG_L(LOG_FATAL) << "Got a signal. Cleaning up...\n";

    if (agent) {
        delete agent;
    }

    agent = NULL;

    if (conf && conf->getTerminateCommand().length() != 0) {
        logger << LOG_L(LOG_INFO) << "Executing Terminate Command\n";
        system(conf->getTerminateCommand().c_str());
        logger << "Done\n";
    }

    delete conf;
    conf = NULL;
    logger << LOG_L(LOG_DEBUG) << "Clearing IP6Tables\n";
    system("ip6tables -t mangle --flush");
    logger << LOG_L(LOG_FATAL) << "Have a nice day!\n";
    exit(0);
}

int main(int argc, char* const argv[]) {
    int	error = 0;
    agent = NULL;

    if(getuid() != 0) {
        cerr << "Must run as root!" << endl;
        exit(-1);
    }

    getcwd(cwd, 200);
    cname = argv[0];
    std::signal(SIGINT, catchSignal);
    std::signal(SIGSEGV, catchSignal);
    conf = new Configuration();

    if (conf->readCLine(argc, argv) ) {
        delete conf;
        return -1;
    };

    //Load Configurations
    logger.setLevel(conf->getLogLevel());

    //Start Logging
    logger << LOG_L(LOG_INFO) << "PACP - Polynomial assisted Ad-hoc Charging Protocol v" << VERSION << "   Build date: " << __DATE__ << ", " << __TIME__ << "\n";

    logger << LOG_L(LOG_INFO) << "       by João Paulo Barraca <jpbaraca@av.it.pt> \n";

    logger << LOG_L(LOG_INFO) << "        Instituto de Telecomunicações - Aveiro \n\n";

    if(!conf->confFileLoaded()) {
        logger << LOG_L(LOG_WARNING) << "Conf file not specified. Loading from /etc/pacp/node.conf\n";
        conf->readFile("/etc/pacp/node.conf");
    }

    if (conf->getStartupCommand().length() != 0) {
        logger << LOG_L(LOG_INFO) << "Executing Startup Command ";
        system(conf->getStartupCommand().c_str());
        logger << "Done\n";
    }

    try {
        agent = new ChargingAgent();
        error = agent->run();

    } catch (Exception e) {
        e.print();
    }

    if (!error) {
        logger << LOG_L(LOG_INFO) << "Exiting with no errors\n";

    } else {
        logger << LOG_L(LOG_DEBUG) << "Exiting with some error\n";
    }

    if (agent) {
        delete agent;
    }

    agent = NULL;

    if (conf && conf->getTerminateCommand().length() != 0) {
        logger << LOG_L(LOG_INFO) << "Executing Terminate Command ";
        system(conf->getTerminateCommand().c_str());
        logger << "Done\n";
    }

    delete conf;
    conf = NULL;
    logger << LOG_L(LOG_DEBUG) << "Clearing IP6Tables\n";
    system("ip6tables -t mangle --flush");
    return 0;
}
