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


#ifndef _PACKET_H
#define _PACKET_H

#include <stdint.h>
#include <stdlib.h>
#include <netinet/ip6.h>

extern "C"
{
#include <libipq.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

}

#include "log.h"
#include "configuration.h"
#include "keyManager.h"

//Internal Defines

#define PACKET_DEFAULT_PAYLOAD_SIZE 1500

#define PACKET_RTX_DELAY	10000000 //us
#define PACKET_RTX_COUNT	5

//Internal Packet status
#define PACKET_VERDICT_UNKNOWN 			0
#define PACKET_VERDICT_ACCEPT  			1
#define PACKET_VERDICT_ACCEPT_WHITE 2
#define PACKET_VERDICT_DROP    			3
#define PACKET_VERDICT_QUEUE				4

//Packet types
#define PACKET_TYPE_UNKNOWN		 		0
#define PACKET_TYPE_WHITE			 	1
#define PACKET_TYPE_DATA				2
#define PACKET_TYPE_DATA_TCP				4
#define PACKET_TYPE_DATA_UDP				8
#define PACKET_TYPE_DATA_SHDR	 			16
#define PACKET_TYPE_DATA_FHDR				32
#define PACKET_TYPE_SIG					64
#define PACKET_TYPE_SIG_HDR				128
#define PACKET_TYPE_SIG_REP				256
#define PACKET_TYPE_SIG_REP_RESP			512
#define PACKET_TYPE_SIG_SINIT				1024
#define PACKET_TYPE_SIG_SINIT_RESP			2048
#define PACKET_TYPE_SIG_FAUTH				4096
#define PACKET_TYPE_SIG_FAUTH_RESP			8192
#define PACKET_TYPE_CRYPTO				16536

//Signalling packets
#define PACKET_SIG_REPORT										0x00
#define PACKET_SIG_REPORT_RESP							0x01
#define PACKET_SIG_SESSION_INIT				 			0x02
#define PACKET_SIG_SESSION_INIT_CRYPTO			0x12
#define PACKET_SIG_SESSION_INIT_RESP				0x03
#define PACKET_SIG_SESSION_INIT_RESP_CRYPTO	0x13
#define PACKET_SIG_FLOW_AUTH								0x04
#define PACKET_SIG_FLOW_AUTH_RESP						0x05

//Netfilter MARKS
#define NF_MARK_INPUT		5
#define NF_MARK_OUTPUT 	4
#define NF_MARK_FORWARD 6

//Packet direction
#define PACKET_DIRECTION_UNKNOWN	0
#define PACKET_DIRECTION_IN				1
#define PACKET_DIRECTION_OUT			2
#define PACKET_DIRECTION_FWR			3

//General Defines
#define CRYPTO_HASH_SIZE						16

//Header types
#define HEADER_CODE_FULL			1
#define HEADER_CODE_SMALL 			2
#define HEADER_CODE_EXT				4

#define HEADER_TYPE_FULL 		1
#define HEADER_TYPE_SMALL 		2

//Possible actions to be preformed to a packet
#define PACKET_DATA_ORIGINAL 	0
#define PACKET_DATA_CHANGED		1
#define PACKET_DATA_REPACK		2
#define PACKET_DATA_PACK			3
#define PACKET_DATA_RAW				4
#define PACKET_DATA_PACKED		5

//Proof report
#define REPORT_PROOF_NONE			0
#define REPORT_PROOF_INDEX		1
#define REPORT_PROOF_SEQUENCE	2
#define REPORT_MAX_SIZE 1380
#define REPORT_PROOF_SIZE 1+2+2+sizeof(in6_addr)+16
#define REPORT_PROOF_SIZE_SMALL 2+2+sizeof(in6_addr)
#define REPORT_ROUTE_SIZE 2

//Charging Header stuff.
#define HEADER_ROUTEID_SIZE					sizeof(in6_addr)
#define HEADER_ROUTEHASH_SIZE 			sizeof(uint32_t)
#define HEADER_SEQUENCE_SIZE				sizeof(uint16_t)
#define HEADER_CHARGING_HASH_SIZE		8
#define HEADER_REWARDING_HASH_SIZE 	8
#define HEADER_HASHCHAIN_SIZE  			HEADER_CHARGING_HASH_SIZE + HEADER_REWARDING_HASH_SIZE
#define HEADER_MAC_SIZE							1

#define HEADER_PROOF_SMALL_SIZE 512			//MAC SIZE ADDED
#define HEADER_PROOF_FULL_SIZE 	512			//MAC SIZE ADDED

#define HEADER_SMALL_CODE_OFFSET 				4
#define HEADER_SMALL_SEQUENCE_OFFSET 		HEADER_SMALL_CODE_OFFSET+sizeof(uint8_t)
#define HEADER_SMALL_HASHCHAIN_OFFSET 	HEADER_SMALL_SEQUENCE_OFFSET+sizeof(uint16_t)
#define HEADER_SMALL_MAC_OFFSET					HEADER_SMALL_HASHCHAIN_OFFSET + HEADER_HASHCHAIN_SIZE
#define HEADER_SMALL_PADDING_OFFSET   	HEADER_SMALL_MAC_OFFSET+1
#define HEADER_SMALL_SIZE								1 + 2 + HEADER_HASHCHAIN_SIZE + 1 + 4

#define HEADER_FULL_CODE_OFFSET 				4
#define HEADER_FULL_INDEX_OFFSET 				HEADER_FULL_CODE_OFFSET	+	sizeof(uint8_t)
#define HEADER_FULL_SEQUENCE_OFFSET 		HEADER_FULL_INDEX_OFFSET	+	sizeof(uint8_t)
#define HEADER_FULL_ROUTEHASH_OFFSET 		HEADER_FULL_SEQUENCE_OFFSET	 	+	HEADER_SEQUENCE_SIZE
#define HEADER_FULL_ROUTEID_OFFSET 			HEADER_FULL_ROUTEHASH_OFFSET 	+	HEADER_ROUTEHASH_SIZE
#define HEADER_FULL_HASHCHAIN_OFFSET 		HEADER_FULL_ROUTEID_OFFSET		+	HEADER_ROUTEID_SIZE
#define HEADER_FULL_MAC_OFFSET					HEADER_FULL_HASHCHAIN_OFFSET 	+	 HEADER_HASHCHAIN_SIZE
#define HEADER_FULL_PADDING_OFFSET   		HEADER_FULL_MAC_OFFSET + 1;


typedef struct session_t;

typedef struct pRoute_t;

typedef struct fec_parms;

extern Configuration* conf;
extern Log logger;

#define PKTCMN_ALLOC_BUFFER			1
#define PKTCMN_ALLOC_IPQ				2
#define PKTCMN_ALLOC_IP					4
#define PKTCMN_ALLOC_TCP				8
#define PKTCMN_ALLOC_UDP				16
#define PKTCMN_ALLOC_SIG				32
#define PKTCMN_ALLOC_DATA				64
#define PKTCMN_ALLOC_FHDR				128
#define PKTCMN_ALLOC_SHDR				256
#define PKTCMN_ALLOC_SINIT			512
#define PKTCMN_ALLOC_SINIT_RESP	1024
#define PKTCMN_ALLOC_REP				2048
#define PKTCMN_ALLOC_REP_RESP		4096
#define PKTCMN_ALLOC_FAUTH			8192
#define PKTCMN_ALLOC_FAUTH_RESP	16384

typedef struct pktCmn_t {
    //Common pkt header
    uint8_t*							buffer;
    uint16_t							psize;
    uint32_t							ptype;
    uint64_t							timestamp;
    uint32_t							verdict;
    uint32_t							status;
    uint64_t							alloc;
    session_t*						session;
    ipq_packet_msg_t*			ipqhdr;

    ip6_hdr*							ipv6hdr;
    sockaddr_in6*					ipv6sock;
    struct tcphdr*				tcphdr;
    struct udphdr*				udphdr;


    uint8_t*							sighdr;
    uint16_t							sigLength;

    uint8_t*							data;
    uint16_t							dataLength;
};

typedef struct pProof_t {
    uint8_t		index;
    uint16_t	packetLength;
    uint16_t	sequence;
    uint8_t		routeID[sizeof(in6_addr)];
    uint8_t		hashChain[16];
};


#define PKTFHDR_ALLOC_BUFFER 1
typedef struct chargingHeader_t {
    uint8_t*	buffer;
    uint32_t	alloc;
    uint8_t	packed;
    uint8_t*	nextHeader;
    uint8_t*	headerLength;
    uint8_t*	type;
    uint8_t*	dataLength;
    uint8_t*	code;
    uint8_t*	index;
    uint16_t*	sequence;
    uint8_t*	routeHash;
    uint8_t*	routeID;
    uint8_t*	hashChain;
    uint8_t*		macLength;
    uint8_t*		mac;
};

#define PKTSHDR_ALLOC_BUFFER 1

typedef struct chargingHeaderSmall_t {
    uint8_t*		buffer;
    uint32_t	alloc;
    uint8_t		packed;
    uint8_t*		nextHeader;
    uint8_t*		headerLength;
    uint8_t*		type;
    uint8_t*		dataLength;
    uint8_t*		code;
    uint16_t*	sequence;
    uint8_t*		hashChain;
    uint8_t*		macLength;
    uint8_t*		mac;
};

/*
 	Poof reports

*/
#define PKTREPORT_ALLOC_BUFFER 1
#define PKTREPORT_SIZE 1+8+16+16+1+1

typedef struct pktReport_t {
    uint8_t* 	buffer;
    uint16_t	dataLength;
    uint8_t* 	pointer;
    uint8_t		packed;
    uint32_t	alloc;

    uint8_t*		type;
    uint64_t*	reportID;
    in6_addr*	sessionSrc;
    in6_addr*	sessionDst;
    uint8_t*		nroutes;
    uint8_t*	lastRoute;
    uint8_t*	endPointer;
    uint8_t*	macLength;
    uint8_t* mac;
};

typedef struct reportRoute_t {
    uint8_t nproofs;
};

typedef struct reportProof_t {
    uint8_t	type;
    uint16_t	size;
    uint16_t	sequence;
    uint8_t	index;
    in6_addr	routeID;
    uint8_t	hashChain;
};

typedef struct reportProofSmall_t {
    uint8_t	 type;
    uint16_t size;
    uint16_t sequence;
    uint8_t	 hashChain;
};


/*
    Report Response packets


*/
#define PKTREPORTRESPONSE_ALLOC_BUFFER	1
#define PKTREPORTRESPONSE_ALLOC_SECRET	2

typedef struct pktReportResponse_t {
    uint8_t*	buffer;
    uint16_t	dataLength;
    uint32_t	alloc;

    uint8_t*	type;
    uint8_t*	result;
    uint64_t*	reportID;
    uint8_t*   macLength;
    uint8_t*   mac;
};



#define PKTSINIT_ALLOC_BUFFER	 1
#define PKTSINIT_ALLOC_ADDRESS 2
#define PKTSINIT_ALLOC_SECRET	4
#define PKTSINIT_ALLOC_UID		8
#define PKTSINIT_ALLOC_PUK		16
#define PKTSINIT_ALLOC_MAC		32

typedef struct pktSessionInit_t {
    uint8_t*	buffer;
    uint16_t	dataLength;
    uint32_t	alloc;

    //Ciphered packet
    uint16_t*	cipherLength;
    uint8_t*	cipher;
    uint16_t*	rsaLength;
    uint8_t*	rsa;

    //clear packet
    in6_addr*	address;
    uint8_t* code;
    uint8_t* uidLength;
    uint8_t* uid;
    uint8_t* secretLength;
    uint8_t* secret;
    uint16_t* pukLength;
    uint8_t* puk;

    uint8_t* macLength;
    uint8_t* mac;

    kmKey_t*	key;
};

#define PKTSINITRESP_ALLOC_BUFFER	1
#define PKTSINITRESP_ALLOC_SECRET	2
#define PKTSINITRESP_ALLOC_MAC		4

#define PKTSINITRESP_CODE_ALLOWED	0
#define PKTSINITRESP_CODE_DENIED	1
#define PKTSINITRESP_CODE_ERROR		2

typedef struct pktSessionInitResponse_t {
    uint8_t*	buffer;
    uint16_t	dataLength;
    uint32_t	alloc;
    uint8_t*	cryptoLength;
    uint8_t*  crypto;
    uint8_t* 	code;
    uint8_t* 	sharedSecret;
    uint8_t* 	sharedSecretLength;

    uint8_t* 	macLength;
    uint8_t* 	mac;
};


#define PKTFLOWAUTH_SIZE	1+8+16+16+1+1+2+2+1+1
#define PKTFLOWAUTH_ALLOC_BUFFER 1

typedef struct pktFlowAuth_t {
    uint8_t*	buffer;
    uint16_t	dataLength;
    uint32_t	alloc;
    uint8_t*   code;

    uint8_t*		request;
    uint64_t*		sid;
    in6_addr*	 	src;
    in6_addr*	 	dst;
    uint8_t*	 	tc;
    uint8_t*			proto;
    uint16_t*		sport;
    uint16_t*		dport;

    uint8_t* 	macLength;
    uint8_t*  mac;
};

#define PKTFLOWAUTHRESP_SIZE	1+8+4+4+4+4+1+1
#define PKTFLOWAUTHRESP_ALLOC_BUFFER 1

typedef struct pktFlowAuthResponse_t {
    uint8_t*	buffer;
    uint16_t	dataLength;
    uint32_t	alloc;
    uint8_t*   code;

    uint32_t*	result;
    uint64_t*	sessionID;
    uint32_t*	issueTime;
    uint32_t*	startTime;
    uint32_t*	expireTime;
    uint8_t*		keyLength;
    uint8_t*		key;
    uint8_t*	 macLength;
    uint8_t*		mac;
};


class Packet {

  public:
    ~Packet();

    static pktCmn_t*  	decode(uint8_t*, int32_t, sockaddr_in6*);
    static pktCmn_t*	decode(uint8_t* buffer, ipq_packet_msg_t* packet);
    static void 			encode(pktCmn_t*);

    static void				free(pktCmn_t*);
    static pktCmn_t*	alloc(uint32_t	bl = 0);

    //Misc
//		static bool				sameNet(in6_addr*, in6_addr*, in6_addr*);
    static bool				sameNet(in6_addr*, in6_addr*, uint8_t mask = 64);
    static bool 			inWhiteUDPList(pktCmn_t*);



    static uint16_t		getPacketLength(pktCmn_t* p) {
        return p->psize;
    };
    static void				setType(pktCmn_t*, uint8_t);
    static void shiftData(pktCmn_t*, uint8_t*, int);

    static uint8_t	getDirection(pktCmn_t*);
  protected:
    static void setupWhite(pktCmn_t*);
    static void setupControl(pktCmn_t*, uint8_t*);

    static void encodeData(pktCmn_t*);
    static void encodeControl(pktCmn_t*);
};

class IPV6Packet : public Packet {
  public:
    static void setup(pktCmn_t*, uint8_t*);
    static uint16_t	getPayloadLength(pktCmn_t*);
    static void pack(pktCmn_t*);
    static void unpack(pktCmn_t*);


    static in6_addr*	getDst(pktCmn_t* p);
    static in6_addr*	getSrc(pktCmn_t* p);
    static uint8_t*		getNextHdr(pktCmn_t* p);
    static void				setNextHdr(pktCmn_t* p, uint8_t);
    static uint16_t		getPLength(pktCmn_t* p);
    static void			setPLength(pktCmn_t* p, uint16_t pl);
};

class UDPPacket		:	public IPV6Packet {
  public:
    static void setup(pktCmn_t*, uint8_t*);
    static void pack(pktCmn_t*);
    static void unpack(pktCmn_t*);
    static uint8_t inWhiteList(pktCmn_t*, uint16_t*, uint16_t);

    static inline uint16_t	getDstPort(pktCmn_t* p) {
        if(p && p->udphdr) {
            return ntohs(p->udphdr->dest);

        } else {
            return 0;
        }
    }
    static inline uint16_t	getSrcPort(pktCmn_t* p) {
        if(p && p->udphdr) {
            return ntohs(p->udphdr->source);

        } else {
            return 0;
        }
    }
};

class TCPPacket		:	public IPV6Packet {
  public:
    static void pack(pktCmn_t*);
    static void unpack(pktCmn_t*);
    static void setup(pktCmn_t*, uint8_t*);

    static void updateMSS(pktCmn_t* packet);
    static uint16_t getDstPort(pktCmn_t* p)  {
        if(p && p->tcphdr && p->ptype & PACKET_TYPE_DATA_TCP) {
            return ntohs(p->tcphdr->dest);

        } else {
            return 0;
        }
    }
    static uint16_t	getSrcPort(pktCmn_t* p ) {
        if(p && p->tcphdr && p->ptype & PACKET_TYPE_DATA_TCP) {
            return ntohs(p->tcphdr->source);

        } else {
            return 0;
        }
    }
};

class DataPacket		:	public IPV6Packet {


};


class PACPHeaderSmall	: public DataPacket {
  public:
    static void pack(pktCmn_t*);
    static void unpack(pktCmn_t*);
    static void setup(pktCmn_t*, uint8_t*);

    static void	free(pktCmn_t*);
    static void	setNxt(pktCmn_t*, uint8_t);

    static void	addHeader(pktCmn_t*, uint8_t, uint16_t);
    static void	removeHeader(pktCmn_t*);

    static uint8_t getCode(pktCmn_t*);
    static void	initHashChain(pktCmn_t*, uint8_t*, uint16_t);
    static void updateHashChain(pktCmn_t*, uint8_t*, uint16_t);
    static uint8_t* getHashChain(pktCmn_t*);

    static uint16_t	getSequence(pktCmn_t*);
    static void			setSequence(pktCmn_t*, uint16_t);

    static void	updateRID(pktCmn_t*, char*, uint16_t, fec_parms*);
    static void	updateRHash(pktCmn_t*, char*);

    static uint16_t	getFullLength(pktCmn_t*);
    static uint16_t	getLength(pktCmn_t*);
    static uint16_t	getPadding(pktCmn_t* p) {
        int a = getLength(p) % 8;

        if(a) {
            return 8 - a;
        }

        return 0;
    }


    /**
        Signs the packet with the supplied Private Key.
        \param packet The packet to be signed
        \param key The Private Key to be used
    */
    static void sign(pktCmn_t* packet, kmKey_t* key);

    /**
        Verifies the signature using the suplied Public Key
        \param packet The packet with signature to be verified
        \param key The Public key to be used
        \return boolean with true if verification was ok
    */
    static bool verifySig(pktCmn_t* packet, kmKey_t* key);
};


class PACPHeaderFull	: public DataPacket {
  public:
    static void pack(pktCmn_t*);
    static void unpack(pktCmn_t*);
    static void setup(pktCmn_t*, uint8_t*);

    static void	free(pktCmn_t*);
    static void	setNxt(pktCmn_t*, uint8_t);

    static void	addHeader(pktCmn_t*, uint8_t, uint16_t);
    static uint8_t getCode(pktCmn_t*);
    static uint8_t getIndex(pktCmn_t*);

    static void updateTCPMSS(pktCmn_t*);

    static void	initHashChain(pktCmn_t*, uint8_t*, uint16_t);

    static void	updateRID(pktCmn_t*, uint8_t*, uint16_t, fec_parms*);
    static uint8_t*	getRID(pktCmn_t*);

    static void	updateRHash(pktCmn_t*, uint8_t*, uint16_t);
    static uint8_t* getRHash(pktCmn_t*);

    static void	updateHashChain(pktCmn_t*, uint8_t*, uint16_t);
    static uint8_t* getHashChain(pktCmn_t*);

    static void	removeHeader(pktCmn_t*);

    static uint16_t	getSequence(pktCmn_t* p) {
        if(p && p->sighdr && p->ptype | PACKET_TYPE_DATA_FHDR) {
            return ntohs(*((chargingHeader_t*) p->sighdr)->sequence);

        } else {
            return 0;
        }
    }
    static uint16_t	getFullLength(pktCmn_t*);
    static uint16_t	getLength(pktCmn_t*);
    static uint16_t	getPadding(pktCmn_t* p) {
        int a = getLength(p) % 8;

        if(a) {
            return 8 - a;
        }

        return 0;
    }

    /**
        Signs the packet with the supplied Private Key.
        \param packet The packet to be signed
        \param key The Private Key to be used
    */
    static void sign(pktCmn_t* packet, kmKey_t* key);

    /**
        Verifies the signature using the suplied Public Key
        \param packet The packet with signature to be verified
        \param key The Public key to be used
        \return boolean with true if verification was ok
    */
    static bool verifySig(pktCmn_t* packet, kmKey_t* key);
};


class PACPSessionInit	: public UDPPacket {
  public:
    ~PACPSessionInit();
    static void pack(pktCmn_t*);
    static void unpack(pktCmn_t*);
    static void setup(pktCmn_t*, uint8_t*);

    static pktCmn_t* alloc();
    static void free(pktCmn_t*);
    static uint8_t*	getBuffer(pktCmn_t*, uint16_t*);

    static in6_addr* getAddress(pktCmn_t*);
    static void  	 	setAddress(pktCmn_t*, in6_addr*);

    static uint8_t* getSecret(pktCmn_t*, uint8_t*);
    static void  	 	setSecret(pktCmn_t*, uint8_t*, uint8_t);


    static uint8_t*	getUID(pktCmn_t*, uint8_t*);
    static void			setUID(pktCmn_t*, uint8_t*, uint8_t);

    static kmKey_t*	getPUK(pktCmn_t*, kmKey_t* t = NULL);
    static void			setPUK(pktCmn_t*, kmKey_t*);

    static kmKey_t*	getKey(pktCmn_t*);

    /**
        Ciphers the packet payload with a Simetric key, adds the key to the end and Ciphers the Sim Key with a RSA Public key
        \param packet The packet to cipher
        \param sim The Simmetric key to used
        \param rsa The RSA Public Key to use
    */
    static void cipherSimRSA(pktCmn_t* packet, kmKey_t* sim, kmKey_t* rsa);

    /**
     	Deciphers the Simmetric Key in the packet using the RSA Private Key and then deciphers the payload using the Simmetric key.
        \param packet The paket to decipher
        \param rsa The RSA Private Key to use
    */
    static void decipherSimRSA(pktCmn_t* packet, kmKey_t* rsa);

    /**
        Signs the packet with the supplied Private Key.
        \param packet The packet to be signed
        \param key The Private Key to be used
    */
    static void sign(pktCmn_t* packet, kmKey_t* key);

    /**
        Verifies the signature using the suplied Public Key
        \param packet The packet with signature to be verified
        \param key The Public key to be used
        \return boolean with true if verification was ok
    */
    static bool verifySig(pktCmn_t* packet, kmKey_t* key);

  private:
};


class PACPSessionInitResponse	: public UDPPacket {
  public:
    ~PACPSessionInitResponse();

    static void pack(pktCmn_t*);
    static void unpack(pktCmn_t*);
    static void setup(pktCmn_t*, uint8_t*);

    static pktCmn_t*	alloc();
    static void	free(pktCmn_t*);
    static uint8_t*	getBuffer(pktCmn_t*, uint16_t*);

    static void	encrypt(pktCmn_t*);
    static void decrypt(pktCmn_t*);
    static void verify(pktCmn_t*);
    static void sign(pktCmn_t*);

    static void			setCode(pktCmn_t*, uint8_t c);
    static uint8_t	getCode(pktCmn_t*);
    static void			setSharedSecret(pktCmn_t*, uint8_t*, uint16_t);
    static uint8_t*	getSharedSecret(pktCmn_t*, uint16_t*);

    /**
        Ciphers the packet payload with a Simetric key
        \param packet The packet to cipher
        \param sim The Simmetric key to used
    */
    static void cipher(pktCmn_t* packet, kmKey_t* sim);

    /**
     	Deciphers the packet using the provided simmetric key
        \param packet The paket to decipher
        \param sim The simmetric key to decipher the packet
    */
    static void decipher(pktCmn_t* packet, kmKey_t* sim);
    /**
        Signs the packet with the supplied Private Key.
        \param packet The packet to be signed
        \param key The Private Key to be used
    */
    static void sign(pktCmn_t* packet, kmKey_t* key);

    /**
        Verifies the signature using the suplied Public Key
        \param packet The packet with signature to be verified
        \param key The Public key to be used
        \return boolean with true if verification was ok
    */
    static bool verifySig(pktCmn_t* packet, kmKey_t* key);
};

class PACPReport	: public UDPPacket {
  public:
    static void pack(pktCmn_t*);
    static void unpack(pktCmn_t*);
    static void setup(pktCmn_t*, uint8_t*);

    static void free(pktCmn_t*);
    static pktCmn_t* alloc();

    static uint8_t* getBuffer(pktCmn_t*, uint16_t*);

    static int16_t	addRoute(pktCmn_t*, uint32_t);
    static int16_t	addProof(pktCmn_t*, uint8_t, uint8_t, uint16_t, uint16_t, uint8_t*, uint8_t*);

    static uint64_t getReportID(pktCmn_t*);
    static void setReportID(pktCmn_t*, uint64_t);

    static void setSessionSrc(pktCmn_t*, in6_addr*);
    static in6_addr* getSessionSrc(pktCmn_t*);
    static void setSessionDst(pktCmn_t*, in6_addr*);
    static in6_addr* getSessionDst(pktCmn_t*);

    static in6_addr* setSessionSrc(pktCmn_t*);
    static in6_addr* setSessionDst(pktCmn_t*);

    static uint8_t getNumberRoutes(pktCmn_t*);

    static uint8_t* getDataStart(pktCmn_t*);

    /**
        Signs the packet with the supplied Private Key.
        \param packet The packet to be signed
        \param key The Private Key to be used
    */
    static void sign(pktCmn_t* packet, kmKey_t* key);

    /**
        Verifies the signature using the suplied Public Key
        \param packet The packet with signature to be verified
        \param key The Public key to be used
        \return boolean with true if verification was ok
    */
    static bool verifySig(pktCmn_t* packet, kmKey_t* key);
};

class PACPReportResponse	: public UDPPacket {
  public:
    static void pack(pktCmn_t*);
    static void unpack(pktCmn_t*);
    static void setup(pktCmn_t*, uint8_t*);

    static void free(pktCmn_t*);
    static pktCmn_t* alloc();

    static uint64_t	getReportID(pktCmn_t*);
    static void	setReportID(pktCmn_t*, uint64_t);

    static uint8_t* getBuffer(pktCmn_t*, uint16_t*);

    /**
        Signs the packet with the supplied Private Key.
        \param packet The packet to be signed
        \param key The Private Key to be used
    */
    static void sign(pktCmn_t* packet, kmKey_t* key);

    /**
        Verifies the signature using the suplied Public Key
        \param packet The packet with signature to be verified
        \param key The Public key to be used
        \return boolean with true if verification was ok
    */
    static bool verifySig(pktCmn_t* packet, kmKey_t* key);
};

class PACPFlowAuth	: public UDPPacket {
  public:
    static void pack(pktCmn_t*);
    static void unpack(pktCmn_t*);
    static void setup(pktCmn_t*, uint8_t*);

    static void free(pktCmn_t*);
    static pktCmn_t* alloc();

    static uint8_t*	getBuffer(pktCmn_t*, uint16_t*);

    static void setRequestKey(pktCmn_t*, uint8_t value = true);
    static uint8_t getRequestKey(pktCmn_t*);

    static void setSessionID(pktCmn_t*, uint64_t);
    static uint64_t getSessionID(pktCmn_t*);

    static void setSessionDst(pktCmn_t*, in6_addr*);
    static in6_addr*	getSessionDst(pktCmn_t*);
    static void setSessionSrc(pktCmn_t*, in6_addr*);
    static in6_addr*	getSessionSrc(pktCmn_t*);

    static void				setProto(pktCmn_t*, uint8_t);
    static uint8_t		getProto(pktCmn_t*);
    static void				setQOS(pktCmn_t*, uint16_t);
    static uint16_t		getQOS(pktCmn_t*);

    static void 			setSPort(pktCmn_t*, uint16_t);
    static uint16_t		getSPort(pktCmn_t*);
    static void 			setDPort(pktCmn_t*, uint16_t);
    static uint16_t		getDPort(pktCmn_t*);

    /**
        Signs the packet with the supplied Private Key.
        \param packet The packet to be signed
        \param key The Private Key to be used
    */
    static void sign(pktCmn_t* packet, kmKey_t* key);

    /**
        Verifies the signature using the suplied Public Key
        \param packet The packet with signature to be verified
        \param key The Public key to be used
        \return boolean with true if verification was ok
    */
    static bool verifySig(pktCmn_t* packet, kmKey_t* key);

};

class PACPFlowAuthResponse : public UDPPacket {
  public:
    static void pack(pktCmn_t*);
    static void unpack(pktCmn_t*);
    static void setup(pktCmn_t*, uint8_t*);

    static uint8_t* getBuffer(pktCmn_t*, uint16_t*);

    static void free(pktCmn_t*);
    static pktCmn_t* alloc();


    static void setSessionID(pktCmn_t*, uint64_t);
    static uint64_t getSessionID(pktCmn_t*);
    static void setCode(pktCmn_t*, uint32_t);
    static uint32_t	getCode(pktCmn_t*);

    static void setStartTime(pktCmn_t*, uint32_t);
    static uint32_t	getStartTime(pktCmn_t*);

    static void setExpireTime(pktCmn_t*, uint32_t);
    static uint32_t	getExpireTime(pktCmn_t*);

    static void setIssueTime(pktCmn_t*, uint32_t);
    static uint32_t	getIssueTime(pktCmn_t*);

    static void setKey(pktCmn_t*, kmKey_t*);
    static kmKey_t* getKey(pktCmn_t*);
    /**
        Signs the packet with the supplied Private Key.
        \param packet The packet to be signed
        \param key The Private Key to be used
    */
    static void sign(pktCmn_t* packet, kmKey_t* key);

    /**
        Verifies the signature using the suplied Public Key
        \param packet The packet with signature to be verified
        \param key The Public key to be used
        \return boolean with true if verification was ok
    */
    static bool verifySig(pktCmn_t* packet, kmKey_t* key);
};

#endif
