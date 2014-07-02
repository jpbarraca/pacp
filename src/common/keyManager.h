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



#ifndef _KEY_MANAGER_H_
#define _KEY_MANAGER_H_

#include <map>
#include <netinet/ip6.h>
#include "configuration.h"
#include "log.h"

extern "C" {
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ec_lcl.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/rc4.h>
}

using namespace std;

#define KEYMANAGER_OK 					0
#define KEYMANAGER_PARAM_ERROR 	1
#define KEYMANAGER_ERROR				2

extern Log logger;
extern Configuration* conf;

typedef struct kmKey_t {
    //SIMETRIC KEYS
    uint8_t*	sim;
    uint32_t	simlen;

    RC4_KEY*		rc4;
    //EC Keys
    EC_KEY*	ec;
    BN_CTX*	ec_ctx;
    BIGNUM*	ec_kinv;
    BIGNUM*	ec_rp;

    //RSA KEYS
    RSA*			rsa;
};

class KeyManager {


    typedef struct less {
        bool operator()(const in6_addr& a, const in6_addr& b) {
            return memcmp((void*) &a, (void*) &b, sizeof(in6_addr)) < 0;
        }
    };

  public:
    KeyManager();
    ~KeyManager();

    /**
        Generate a key to be used with Simmetric algorithms. Presently it generates a RC4 key.
        \param size The size of the key to generate
        \param key Optional kmKey_t* to add (or replace) new key
        \return A newly allocated kmKey_t or the previous one if provided
    */
    static kmKey_t*  generateSim(unsigned int size, uint8_t* sim = NULL, kmKey_t* key = NULL );

    /**
        Generate a key to be used with Elliptic curve algorithms.
        \param key Optional kmKey_t* to add (or replace) new key
        \return A newly allocated kmKey_t or the previous one if provided
    */
    static kmKey_t* generateEC(kmKey_t* a = NULL);

    /**
        Generate a key to be used with the RSA algorithm.
        \param key Optional kmKey_t* to add (or replace) new key
        \return A newly allocated kmKey_t or the previous one if provided
    */
    static kmKey_t* generateRSA(unsigned int, kmKey_t* a = NULL);

    /*
        Load a DER encoded RSA Public key from a file
        \param filename File with Key
        \return New allocated Key with a RSA key or NULL if failled
    */
    static kmKey_t* loadRSAFile(char* filename)	;

    /**
        Frees a kmKey_t object
        \param key The key to free
    */
    static void freeKey(kmKey_t* key);

    /**
        Adds a key to the database and relates it with an IPv6 address
        \param address The address related to the key
        \param key The Key to add
    */
    void	setKey(in6_addr* address, kmKey_t* key);

    /**
        Returns the key associated with a given address (if Found)
        \param address The address to search
        \return The key or NULL if not found
    */
    kmKey_t* findKey(in6_addr* address);

    static kmKey_t* loadRSAname(char*);
    static kmKey_t* loadRSAfd(FILE*);
    static int32_t dumpRSAfd(kmKey_t*, FILE* s = stdout, bool priv = false);
    static int32_t dumpRSAname(kmKey_t*, char* filename = NULL, bool priv = false);

    static kmKey_t*	loadECbuf(uint8_t*, kmKey_t* t = NULL);
    static kmKey_t*	loadECname(char*, kmKey_t* key = NULL);

    static int32_t	dumpECbuf(kmKey_t*, uint8_t*);
    static int32_t	dumpECname(kmKey_t*, uint8_t* filename = NULL, bool priv = false);

    static int32_t cipher(kmKey_t*, uint8_t*, uint16_t*, uint8_t*, short unsigned int);
    static int32_t decipher(kmKey_t*, uint8_t*, uint16_t*, uint8_t*, short unsigned int);
    static int32_t sign(kmKey_t*, uint8_t*, uint32_t*, uint8_t*, unsigned int);

    static int32_t cipherRSAPublic(kmKey_t*, uint8_t*, uint16_t*, uint8_t*, short unsigned int);
    static int32_t decipherRSAPrivate(kmKey_t*, uint8_t*, uint16_t*, uint8_t*, short unsigned int);
    static int32_t verifyRSA(kmKey_t*, uint8_t*, short unsigned int, uint8_t*, short unsigned int);
    static 	int32_t signRSA(kmKey_t*, uint8_t*, uint16_t*, uint8_t*, short unsigned int);

    static int32_t verifyECDSA(kmKey_t*, uint8_t*, short unsigned int, uint8_t*, short unsigned int);
    static int32_t signECDSA(kmKey_t*, uint8_t*, uint16_t*, uint8_t*, short unsigned int);


    kmKey_t*	_hostKey;
    kmKey_t*	_opKey;

  private:
    map<in6_addr, kmKey_t*, less>	_keyDB;
    BIO* _bio_err;
};
#endif
