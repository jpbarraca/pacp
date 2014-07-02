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


#include <keyManager.h>
#include <exception.h>
#include <log.h>

Log logger;

int main(int argc, char* argv[]) {
    if(argc != 5) {
        cout << "Usage: " << argv[0] << " <RSAPublicKeyFile> <RSAPrivateKeyFile> <ECPublicKeyFile> <ECPrivateKeyFile>" << endl;
        return 0;
    }

    unlink(argv[1]);
    unlink(argv[2]);
    unlink(argv[3]);
    unlink(argv[4]);

    try {
        kmKey_t* key = KeyManager::generateRSA(1024);
        KeyManager::generateEC(key);
        cout << "  * Dumping RSA Public Key to: " << argv[1] << endl;
        KeyManager::dumpRSAname(key, argv[1], false);
        cout << "  * Dumping RSA Public/Private Key to: " << argv[2] << endl;
        KeyManager::dumpRSAname(key, argv[2], true);
        RSA_print_fp(stdout, key->rsa, 0);
        cout << "  * Dumping EC Public Key to: " << argv[3] << endl;
        KeyManager::dumpECname(key, (uint8_t*) argv[3], false);
        cout << "  * Dumping EC Public/Private Key to: " << argv[4] << endl;
        KeyManager::dumpECname(key, (uint8_t*) argv[4], true);

    } catch (Exception e) {
        e.print();
    }

    return 0;
}
