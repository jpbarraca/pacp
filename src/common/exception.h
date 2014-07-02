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


#ifndef _EXCEPTION_H_
#define _EXCEPTION_H_
#include <stdio.h>

#define MYTHROW()	throw Exception(__FILE__,__LINE__,__FUNCTION__,"","")
#define MYTHROW1(m1) throw Exception(__FILE__,__LINE__,__FUNCTION__, m1,"")
#define MYTHROW2(m1,m2)	throw Exception(__FILE__,__LINE__,__FUNCTION__, m1,m2)

class Exception {

  public:
    Exception(char* file, unsigned int line, const char* f, const char* m1 = NULL, char* m2 = NULL) {
        snprintf(_msg, 1024, "%s (%s:%u) - %s - %s", f, file, line, m1, m2);
    }

    ~Exception() {}

    inline void print() {
        fprintf(stderr, "\nEXCEPTION: %s\n\n", _msg);
    }
    inline char* getMsg() {
        return _msg;
    }

  private:
    char _msg[1024];
};

#endif
