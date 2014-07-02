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


#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>

using namespace std;

void printBackTrace(char* cwd, char* name, int skip) {
    char cmd[200];
    int c, i;
    void* addresses[40];
    char** strings;
    c = backtrace(addresses, 40);
    strings = backtrace_symbols(addresses, c);
    fprintf(stderr, "\n\n***** Printing Backtrace: %d\n", c - skip);

    for(i = skip; i < c; i++) {
        sprintf(cmd, "echo -n %2d : %s :; for i in `addr2line -sfC -e %s/%s %x`;do echo -n \"$i \";done\n", i - skip, name, cwd, name, (int)addresses[i]);
        system(cmd);
        fprintf(stdout, "\n");
    }

    fprintf(stderr, "\n***** END *****\n");
}

void printBuf(const char* message, unsigned char* buf, int buflen) {
    fprintf(stderr, "%s(%d)", message, buflen);
    int i;

    for(i = 0; i < buflen; i++) {
        fprintf(stderr, "%2.2X", buf[i]);

        if(i != buflen - 1) {
            fprintf(stderr, ":");
        }
    }

    fprintf(stderr, "\n");
}
