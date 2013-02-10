#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>

// COMMITMENT EXTENSION OID DEFINITION ////////////////////////////////////////
#define UNISA_PEN "11312" // http://www.iana.org/assignments/enterprise-numbers
#define COMMITMENT_OID "1.3.6.1.4.1." UNISA_PEN ".42"	// don't panic!
#define COMMITMENT_OID_C COMMITMENT_OID ".1"
#define COMMITMENT_OID_SNAME "CommC"
#define COMMITMENT_OID_LNAME "Commitment C value"
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
DSA* dsaKeyFromCertFile(char *filename);
void writeCommitmentCSR(BIGNUM *commitment_c, char *privkey_filename, char *req_filename, char *creq_filename);
BIGNUM *getCommitmentValueFromCert(char *filename);
BIGNUM *getCommitmentValueFromCSR(char *filename);
///////////////////////////////////////////////////////////////////////////////
void commit(BIGNUM *p, BIGNUM *q, BIGNUM *g, BIGNUM *h, // in: p, q, g, h - parameters given by Receiver
		BIGNUM *m, 				// in: m - "secret" value/message
		BIGNUM *r, BIGNUM *c);			// out: r, c - selected random and committed value

int decommit(BIGNUM *c, 				//in: stored committed value
		BIGNUM *p, BIGNUM *g, BIGNUM *h,	//in: p, g, h - phase 1 parameters
		BIGNUM *r, BIGNUM *m,			//in: r, m - selected random and original value/message
		BIGNUM *cbis);				//out: c', if needed outside -  ignored if NULL
///////////////////////////////////////////////////////////////////////////////
void writeBNtoFile(const BIGNUM *bn, const char *filename);
void readBNfromFile(BIGNUM *bn, const char *filename) ;
void myBN_print(const char *id, const BIGNUM *bn);
///////////////////////////////////////////////////////////////////////////////
void critical_error(const char *msg);

