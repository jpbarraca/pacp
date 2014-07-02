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


#include <map>
#include <sys/time.h>
#include <iostream>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include "exception.h"
#include "keyManager.h"
#include "debug.h"

extern "C"
{
#include <openssl/ec.h>
#include <openssl/md5.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>
#include <openssl/rc4.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
}

using namespace std;

static BIO* bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

KeyManager::KeyManager() {
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    _bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    uint32_t	seed;
    timeval	tv;
    gettimeofday(&tv, NULL);
    seed = tv.tv_sec + tv.tv_usec;
    srand(seed);
    RAND_load_file("/dev/urandom", 64);
    _hostKey = new kmKey_t;
    _opKey = new kmKey_t;
    memset(_hostKey, 0, sizeof(kmKey_t));
    memset(_opKey, 0, sizeof(kmKey_t));
};



KeyManager::~KeyManager() {
    if(_hostKey) {
        freeKey(_hostKey);
    }

    if(_opKey) {
        freeKey(_opKey);
    }

    CRYPTO_cleanup_all_ex_data();
    CRYPTO_mem_leaks(_bio_err);
    BIO_free(_bio_err);
};



kmKey_t* KeyManager::generateSim(unsigned int s, uint8_t* sim, kmKey_t* okey) {
    uint32_t i = 0;
    unsigned char*	cipherKey = new (unsigned char)[s];

    //Generate session key
    if(!sim) {
        for (i = 0; i < s; i++) {
            cipherKey[i] = rand();
        }

    } else {
        memcpy(cipherKey, sim, s);
    }

    kmKey_t*	key;

    if(okey) {
        key = okey;

        if(key->rc4) {
            delete key->rc4;
        }

        if(key->sim) {
            delete [] key->sim;
        }

    } else {
        key = new kmKey_t;
        memset(key, 0, sizeof(kmKey_t));
    }

    key->rc4 = new RC4_KEY;
    RC4_set_key(key->rc4, s, cipherKey);
    key->sim = cipherKey;
    key->simlen = s;
    return key;
}



kmKey_t* KeyManager::generateEC(kmKey_t* okey) {
    //Generate EC Key
    EC_KEY* key = EC_KEY_new();

    if (key == NULL) {
        MYTHROW1("Error Allocating new EC Key");
    }

    key->group = EC_GROUP_new_by_curve_name(NID_secp160r1);

    if (!key->group) {
        MYTHROW1("Error Creating EC Key Group");
    }

    if (!EC_KEY_generate_key(key)) {
        MYTHROW1("Error Generating EC Key");
    }

    kmKey_t* e;

    if(okey) {
        e = okey;

        if(e->ec) {
            EC_KEY_free(e->ec);
        }

        if(e->ec_kinv) {
            delete e->ec_kinv;
        }

        if(e->ec_rp) {
            delete e->ec_rp;
        }

        if(e->ec_ctx) {
            BN_CTX_free( e->ec_ctx);
        }

    } else {
        e = new kmKey_t;
        memset(e, 0, sizeof(kmKey_t));
    }

    e->ec = key;
    e->ec_ctx = BN_CTX_new();
    ECDSA_sign_setup(e->ec, e->ec_ctx, &e->ec_kinv, &e->ec_rp);
//	EC_KEY_print(bio_err,e->ec,0);
    return e;
}



kmKey_t* KeyManager::generateRSA(uint32_t	size, kmKey_t* okey) {
    if (!size) {
        return 0;
    }

    RSA*	r = RSA_generate_key(size, 3, NULL, NULL);
    kmKey_t* key;

    if(okey) {
        key = okey;

        if(key->rsa) {
            RSA_free(key->rsa);
        }

    } else {
        key = new kmKey_t;
        memset(key, 0, sizeof(kmKey_t));
    }

    key->rsa = r;
    return key;
}


void KeyManager::freeKey(kmKey_t* kp) {
    if(!kp) {
        return;
    }

    if(kp->sim) {
        delete [] kp->sim;
    }

    if(kp->rc4) {
        delete kp->rc4;
    }

    if(kp->ec) {
        EC_KEY_free(kp->ec);
    }

    if(kp->ec_kinv) {
        BN_free(kp->ec_kinv);
    }

    if(kp->ec_rp) {
        BN_free(kp->ec_rp);
    }

    if(kp->ec_ctx) {
        BN_CTX_free(kp->ec_ctx);
    }

    if(kp->rsa) {
        RSA_free(kp->rsa);
    }

    delete kp;
}




void	KeyManager::setKey(in6_addr* addr, kmKey_t* key) {
    in6_addr* a = new in6_addr;
    memcpy(a, addr, sizeof(in6_addr));
    /*
        fprintf(stderr, "SET: %x:%x:%x:%x:%x:%x:%x:%x\n",
          (int)ntohs(a->s6_addr16[0]), (int)ntohs(a->s6_addr16[1]),
          (int)ntohs(a->s6_addr16[2]), (int)ntohs(a->s6_addr16[3]),
          (int)ntohs(a->s6_addr16[4]), (int)ntohs(a->s6_addr16[5]),
          (int)ntohs(a->s6_addr16[6]), (int)ntohs(a->s6_addr16[7]));
    */
    _keyDB[*a] = key;
};


kmKey_t* KeyManager::findKey(in6_addr* a) {
    map<in6_addr, kmKey_t*, less>::iterator it = _keyDB.find(*a);
//	map<in6_addr,kmKey_t*,less>::iterator it;

    /*
    	fprintf(stderr, "FIND: %x:%x:%x:%x:%x:%x:%x:%x\n",
             (int)ntohs(a->s6_addr16[0]), (int)ntohs(a->s6_addr16[1]),
             (int)ntohs(a->s6_addr16[2]), (int)ntohs(a->s6_addr16[3]),
             (int)ntohs(a->s6_addr16[4]), (int)ntohs(a->s6_addr16[5]),
             (int)ntohs(a->s6_addr16[6]), (int)ntohs(a->s6_addr16[7]));
    */
    /*
        if(it != _keyDB.end()){
    	fprintf(stderr,"FOUND!\n");
    	return (*it).second;
        }
    */
    for(it = _keyDB.begin(); it != _keyDB.end(); it++) {
        /*
        	const in6_addr * b= &(*it).first;
        			fprintf(stderr, "Search: %x:%x:%x:%x:%x:%x:%x:%x\n",
              (int)ntohs(b->s6_addr16[0]), (int)ntohs(b->s6_addr16[1]),
              (int)ntohs(b->s6_addr16[2]), (int)ntohs(b->s6_addr16[3]),
              (int)ntohs(b->s6_addr16[4]), (int)ntohs(b->s6_addr16[5]),
              (int)ntohs(b->s6_addr16[6]), (int)ntohs(b->s6_addr16[7]));
        */
        if ( !memcmp(&(*it).first, a, sizeof(in6_addr))) {
//			fprintf(stderr,"FOUND - 2\n");
            return (*it).second;
        }
    }

    return NULL;
}



kmKey_t* KeyManager::loadRSAname(char* filename) {
    if(!filename) {
        MYTHROW1("Error in parameters");
    }

    FILE* fd = fopen(filename, "r");

    if(!fd) {
        MYTHROW1("Error opening file with RSA key");
    }

    return loadRSAfd(fd);
}


kmKey_t* KeyManager::loadRSAfd(FILE* fd) {
    if (!fd) {
        MYTHROW1("Error in parameters");
    }

    RSA* rsa = PEM_read_RSAPublicKey(fd, NULL, NULL, NULL);

    if(rsa) {
        PEM_read_RSAPrivateKey(fd, &rsa, NULL, NULL);

    } else {
        rsa = PEM_read_RSAPrivateKey(fd, NULL, NULL, NULL);
    }

    if(!rsa) {
        MYTHROW1("Could load ANY key from file");
    }

    if(conf->getLogLevel() >= LOG_DEBUG) {
        RSA_print_fp(stderr, rsa, 0);
    }

    kmKey_t* key = new kmKey_t;
    memset(key, 0, sizeof(kmKey_t));
    key->rsa = rsa;
    return key;
}


kmKey_t* KeyManager::loadECname(char* name, kmKey_t* okey) {
    if(!name) {
        MYTHROW1("Error in parameters");
    }

    kmKey_t* key;

    if(okey) {
        key = okey;

        if(key->ec) {
            EC_KEY_free(key->ec);
        }

        if(key->ec_kinv) {
            delete key->ec_kinv;
        }

        if(key->ec_rp) {
            delete key->ec_rp;
        }

        if(key->ec_ctx) {
            BN_CTX_free( key->ec_ctx);
        }

        key->ec = NULL;
        key->ec_kinv = NULL;
        key->ec_rp = NULL;

    } else	{
        key =  new kmKey_t;
        memset(key, 0, sizeof(kmKey_t));
    }

    FILE*	fd = fopen((const char*) name, "r");

    if(!fd) {
        MYTHROW1("Error opening file");
    }

    unsigned char*	buf = new (unsigned char)[8192];
    memset(buf, 0, 8192);
    long	tlen = 0;
    long	len = tlen;

    if((tlen = fread(buf, 1, 8192, fd)) == 0) {
        delete [] buf;
        fclose(fd);
        MYTHROW1("Error reading file");
    }

    memcpy(&len, buf, sizeof(uint16_t));
    unsigned char* buffi = buf;
    key->ec = EC_KEY_new();
    buffi += sizeof(uint16_t);

    if(!d2i_ECParameters(&key->ec, (const unsigned char**) &buffi, len)) {
//		ERR_print_errors(_bio_err);
        delete [] buf;
        MYTHROW1("Error decoding EC key parameters");
    }

    len = *((uint16_t*) buffi);
    buffi += sizeof(uint16_t);

    if(!o2i_ECPublicKey(&key->ec, (const unsigned char**) &buffi, len)) {
        delete [] buf;
        MYTHROW1("Error decoding EC Public key");
    }

    //We could also have a private key
    if(buffi - buf < tlen) {
        len = *((uint16_t*) buffi);
        buffi += sizeof(uint16_t);

        if(!d2i_ECPrivateKey(&key->ec, (const unsigned char**)&buffi, len)) {
            delete [] buf;
            ERR_print_errors(bio_err);
            MYTHROW1("Error decoding EC Private key");
        }
    }

    delete [] buf;
    fclose(fd);
    return key;
}



int32_t KeyManager::dumpECname(kmKey_t* key, uint8_t* name, bool priv) {
    if(!key || !key->ec || !name) {
        MYTHROW1("Error in parameters");
    }

    EC_KEY* ec = key->ec;
    FILE*	fd = fopen((const char*) name, "w+");

    if(!fd) {
        MYTHROW1("Eror creating file");
    }

    unsigned char* buff = new (unsigned char)[8192];
    unsigned char* b1 = buff;
    unsigned char* b2 = b1 + sizeof(uint16_t);
    uint32_t	len = 0;
    len += sizeof(int16_t);
    int16_t ret = i2d_ECParameters(ec , &b2);

    if(ret <= 0) {
        delete [] buff;
        MYTHROW1("Error Encoding ECPKParameters");
    }

    memcpy(b1, &ret, sizeof(uint16_t));
    len += ret;
    b1 = b2;
    b2 += sizeof(int16_t);
    len += sizeof(int16_t);
    ret = i2o_ECPublicKey(ec, &b2);

    if(ret <= 0) {
        delete [] buff;
        MYTHROW1("Error Encoding EC Public Key");
    }

    memcpy(b1, &ret, sizeof(uint16_t));
    len += ret;

    if(priv) {
        b1 = b2;
        b2 += sizeof(int16_t);
        len += sizeof(int16_t);
        ret = i2d_ECPrivateKey(ec, &b2);

        if(ret <= 0) {
            delete [] buff;
            MYTHROW1("Error Encoding EC Public Key");
        }

        memcpy(b1, &ret, sizeof(uint16_t));
        len += ret;
    }

    if(fwrite(buff, len, 1, fd) != 1) {
        delete [] buff;
        fclose(fd);
    };

    delete [] buff;

    return 1;
}



kmKey_t* KeyManager::loadECbuf(uint8_t* buf, kmKey_t* k) {
    if(!buf) {
        MYTHROW1("Error in parameters");
    }

    kmKey_t* key = NULL;

    if(k) {
        key = k;

        if(key->ec) {
            EC_KEY_free(key->ec);
            key->ec = NULL;
        }

        if(key->ec_kinv) {
            BN_free(key->ec_kinv);
            key->ec_kinv = NULL;
        }

        if(key->ec_rp) {
            BN_free(key->ec_rp);
            key->ec_rp = NULL;
        }

    } else {
        key = new kmKey_t;
        memset(key, 0, sizeof(kmKey_t));
    }

    long	len = *((uint16_t*) buf);
    unsigned char* buffi = buf + sizeof(uint16_t);
//	fprintf(stderr,"Param Length: %u\n",len);
    key->ec = EC_KEY_new();

    if(!d2i_ECParameters(&key->ec, (const unsigned char**) &buffi, len)) {
//		ERR_print_errors(_bio_err);
        MYTHROW1("Error decoding EC key parameters");
    }

    len = *((uint16_t*) buffi);
//	fprintf(stderr,"Puk Length: %u\n",len);
    buffi += sizeof(uint16_t);

    if(!o2i_ECPublicKey(&key->ec, (const unsigned char**) &buffi, len)) {
        MYTHROW1("Error decoding EC Public key");
    }

//	EC_KEY_print(bio_err,key->ec,0);
    return key;
}


int32_t KeyManager::dumpECbuf(kmKey_t* key, uint8_t* buf) {
    if(!key || !key->ec || !buf) {
        MYTHROW1("Error in parameters");
    }

//	EC_KEY_print(bio_err,key->ec,0);
    EC_KEY* ec = key->ec;
    unsigned char* b1 = buf;
    unsigned char* b2 = b1 + sizeof(uint16_t);
    int16_t ret = i2d_ECParameters(ec , &b2);

    if(ret <= 0) {
        MYTHROW1("Error Encoding ECPKParameters");
    }

//	fprintf(stderr,"Param Length: %u\n",ret);
    memcpy(b1, &ret, sizeof(uint16_t));
    b1 = b2;
    b2 += sizeof(int16_t);
    ret = i2o_ECPublicKey(ec, &b2);

    if(ret <= 0) {
        MYTHROW1("Error Encoding EC Public Key");
    }

//	fprintf(stderr,"Puk Length: %u\n",ret);
    memcpy(b1, &ret, sizeof(uint16_t));
    return b2 - buf;
}

int32_t	KeyManager::dumpRSAname( kmKey_t* key, char* filename, bool priv) {
    if(!key) {
        MYTHROW1("Error in parameters");
    }

    if(filename) {
        FILE* fp = fopen(filename, "a+");

        if(!fp) {
            MYTHROW1("Error opening file for RSA output");
        }

        dumpRSAfd(key, fp, priv);

    } else {
        dumpRSAfd(key, stdout, priv);
    }

    return true;
}



int32_t	KeyManager::dumpRSAfd(kmKey_t* key, FILE* fp, bool priv) {
    if (!fp || !key || !key->rsa) {
        MYTHROW1("Error in parameters");
    }

    if(fp == stdout) {
        RSA_print_fp(fp, key->rsa, 0);

    } else {
        if(key->rsa->e) {
            PEM_write_RSAPublicKey(fp, key->rsa);
        }

        if(key->rsa->d && priv) {
            PEM_write_RSAPrivateKey(fp, key->rsa, NULL, NULL, 0, NULL, NULL);
        }
    }

    return true;
}



int32_t	KeyManager::cipher(kmKey_t* key, uint8_t* cipher, uint16_t* clen, uint8_t* data, uint16_t datalen) {
    if (!key || !key->rc4 || !cipher || !clen || ! data || !datalen) {
        MYTHROW1("Error in parameters");
    }

    RC4(key->rc4, datalen, data, cipher);
    *clen = datalen;
    return datalen;
};


int32_t	KeyManager::decipher(kmKey_t* key, uint8_t* cipher, uint16_t* clen, uint8_t* data, uint16_t datalen) {
    if (!key || !key->rc4 || !cipher || !clen || ! data || !datalen) {
        MYTHROW1("Error in parameters");
    }

    RC4(key->rc4, datalen, data, cipher);
    *clen = datalen;
    return datalen;
};


int32_t KeyManager::cipherRSAPublic(kmKey_t* kmkey, uint8_t* dataout, uint16_t* dolen, uint8_t* data, uint16_t dlen) {
    if (!kmkey || !kmkey->rsa || !dolen || !dataout || !data || !dlen) {
        MYTHROW1("Error in parameters");
    }

    RSA* key = kmkey->rsa;

    if (*dolen < RSA_size(key)) {
        MYTHROW1("Error in parameters");
    }

    uint16_t cBytes = 0;
    int rsaSize = RSA_size(key);
    int bSize = rsaSize - 11;
    int i = 0;
    int ec = 0;

    for (i = 0 ; i < dlen; i += bSize) {
        if(dlen - i < bSize) {
            ec = RSA_public_encrypt(dlen - i, data + i, dataout + cBytes, key, RSA_PKCS1_PADDING);

        }	else {
            ec = RSA_public_encrypt(bSize, data + i, dataout + cBytes, key, RSA_PKCS1_PADDING);
        }

        if (ec < 0) {
            MYTHROW1("Error ciphering data with RSA");
        }

        cBytes += ec;
    }

    *dolen = cBytes;
    return cBytes;
}



int32_t KeyManager::decipherRSAPrivate(kmKey_t* kmkey, uint8_t* dataout, uint16_t* dolen, uint8_t* data, uint16_t dlen) {
    if (!kmkey || !kmkey->rsa || !dolen || !dataout || !data || !dlen) {
        MYTHROW1("Error in parameters");
    }

    RSA* key = kmkey->rsa;

    if (*dolen < RSA_size(key)) {
        MYTHROW1("Output buffer must be larger than key size");
    }

    uint16_t cBytes = 0;
    int rsaSize = RSA_size(key);
    int bSize = rsaSize;

    if(dlen % rsaSize != 0) {
        logger << LOG_L(LOG_DEBUG) << "KeyManager: decipherRSAPRivate: Input data is not multiple of RSA_SIZE\n";
    }

    int i = 0;

    for (i = 0; i < dlen; i += bSize) {
//		fprintf(stderr,"BS: %u, i: %u, cBytes: %u dlen: %u\n", bSize,i,cBytes,dlen);
        int ret = RSA_private_decrypt(bSize, data + i, dataout + cBytes, key, RSA_PKCS1_PADDING);

        if(ret < 0) {
            ERR_print_errors(bio_err);
            MYTHROW1("Error deciphering data with RSA");
        }

        cBytes += ret;
    }

    *dolen = cBytes;
    return cBytes;
}



int32_t KeyManager::verifyRSA(kmKey_t* kmkey, uint8_t* sign, uint16_t slen, uint8_t* data, uint16_t dlen) {
    if (!kmkey || !kmkey->rsa || !sign || !slen || !data || !dlen) {
        MYTHROW1("Error in parameters");
    }

    RSA* key = kmkey->rsa;

    if (slen != RSA_size(key)) {
        MYTHROW1("Signature length is incorrect");
    }

    unsigned char md[16];
    MD5(data, dlen, md);
    return RSA_verify(NID_md5, md, 16, sign, slen, key);
}



int32_t	KeyManager::signRSA(kmKey_t*	kmkey, uint8_t* sign, uint16_t* slen, uint8_t* data, uint16_t dlen) {
    if (!kmkey || !kmkey->rsa || !sign || !slen || !data || !dlen) {
        MYTHROW1("Error in parameters");
    }

    RSA* key = kmkey->rsa;

    if (*slen < RSA_size(key)) {
        MYTHROW1("Signature length is incorrect");
    }

    unsigned int len = *slen;
    unsigned char	md[16];
    MD5(data, dlen, md);
    int ret = RSA_sign(NID_md5, md, 16, sign, &len, key);

    if(ret != 1) {
//		ERR_print_errors(_bio_err);
        MYTHROW1("Error generating RSA signature");
    }

    *slen = len;
    return ret;
}



int32_t	KeyManager::signECDSA(kmKey_t* kmkey, uint8_t* sign, uint16_t* slen, uint8_t* data, uint16_t dlen) {
    if (!kmkey || !kmkey->ec || !sign || !slen || !data || !dlen) {
        fprintf(stderr, "kmkey: %x, ec: %x, sign: %x, slen: %x, data: %x, dlen: %x\n", kmkey, kmkey->ec, sign, slen, data, dlen);
        MYTHROW1("Error in parameters");
    }

    EC_KEY* key = kmkey->ec;

    if(*slen < ECDSA_size(key)) {
        MYTHROW1("Signature buffer too small");
    }

    unsigned char	md[16];
    MD5(data, dlen, md);
    unsigned int siglen = *slen;

    if(!kmkey->ec_kinv || !kmkey->ec_rp || !kmkey->ec_ctx) {
        logger << LOG_L(LOG_DEBUG) << "KeyManager::signECDSA: Sign Setup REQUIRED\n";
        ECDSA_sign_setup(kmkey->ec, kmkey->ec_ctx, &kmkey->ec_kinv, &kmkey->ec_rp);
    }

    int ret = ECDSA_sign_ex(0, md, 16, sign, &siglen, (const BIGNUM*) kmkey->ec_kinv, (const BIGNUM*) kmkey->ec_rp, key);

    /*
    	printBuf("ECDSA Sign",sign,siglen);
    	printBuf("ECDSA Sign MD",md,16);
    */
    if(ret != 1) {
//		ERR_print_errors(_bio_err);
        MYTHROW1("Error generating ECDSA signature");
    }

    *slen = siglen;
    return ret;
}


int32_t KeyManager::verifyECDSA(kmKey_t* kmkey, uint8_t* sign, uint16_t slen, uint8_t* data, uint16_t dlen) {
    if (!kmkey || !kmkey->ec || !sign || !slen || !data || !dlen) {
        MYTHROW1("Error in parameters");
    }

    EC_KEY* key = kmkey->ec;
    unsigned char	md[16];
    MD5(data, dlen, md);
    /*
    	printBuf("ECDSA Verify",sign,slen);
    	printBuf("ECDSA Verify MD",md,16);
    */
    int ret = ECDSA_verify(0, md, 16, sign, slen, key);

    if(ret < 0) {
        MYTHROW1("Error Verifying ECDSA key\n");
    }

    return ret;
}
