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


#ifndef _GWINFO_CLIENT_H
#define _GWINFO_CLIENT_H

#include <map>
#include <vector>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <pthread.h>
#include "log.h"
#include "configuration.h"
#include "threadFunc.h"

using namespace std;
extern Log logger;
extern Configuration* conf;

class GWInfoClient : public ThreadFunc {

  public:
    GWInfoClient();
    virtual ~GWInfoClient();

  protected:
    void*	run(void*);

  private:
    bool _run;
    pthread_t	_gwInfoThread;
    pthread_mutex_t	_gwInfoMutex;
    pthread_cond_t	_gwInfoCond;
};

#endif
