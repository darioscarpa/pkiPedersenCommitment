#include "commitment_common.h"

/****** PRNG ***************************************************************/
#define SEEDSIZE 16

static int _seed_prng() {
	static int _prng_seeded = 0;
	if (_prng_seeded) return 0;
	if (RAND_load_file("/dev/random", SEEDSIZE)) {
		_prng_seeded = 1;
		return 0;
	}
	return 1;
}
/***************************************************************************/

/****** ERR_HANDLING *******************************************************/
void critical_error(const char *msg) {
	fprintf(stderr, "** %s\n", msg);
	ERR_print_errors_fp(stderr);
	exit(-1);
}
/***************************************************************************/

/****** BIGNUM/BUFFER/FILE UTILS ********************************************/
static int _fileToBuf(const char *filename, unsigned char **buf, int *bufLen) {
	FILE *f = fopen(filename, "rb");
	if (!f) return 1;
	fseek(f, 0, SEEK_END);
	*bufLen = ftell(f);
	*buf = (unsigned char*) malloc(*bufLen);
	if (!*buf) return 1;
	fseek(f, 0, SEEK_SET);
	if (fread(*buf, 1, *bufLen, f) != *bufLen) return 1;
	fclose(f);
	return 0;
}

static int _bufToFile(const char *filename, unsigned char *buf, int bufLen) {
	FILE *f = fopen(filename, "wb");
	if (!f) return 1;
	if (fwrite(buf, 1, bufLen, f)!=bufLen) return 1;
	fclose(f);
	return 0;
}

void writeBNtoFile(const BIGNUM *bn, const char *filename) {
	int bufLen = BN_num_bytes(bn);
	unsigned char *buf = (unsigned char *) malloc(bufLen);

	bufLen = BN_bn2bin(bn, buf);
	if (_bufToFile(filename, buf, bufLen)) {
		printf("%s - ",filename);
		critical_error("can't write to file!");
	}
	free(buf);
}

void readBNfromFile(BIGNUM *bn, const char *filename) {
	unsigned char *buf;
	int bufLen;

	if (_fileToBuf(filename, &buf, &bufLen)) {
		printf("%s - ",filename);
		critical_error("Can't read from file!");
	}
	BN_bin2bn(buf, bufLen, bn);

	free(buf);
}

void myBN_print(const char *id, const BIGNUM *bn) {
	char *s = BN_bn2dec(bn);
	printf("%s=%s\n\n",id,s);
	OPENSSL_free(s);
}
/***************************************************************************/

/****** COMMITMENT *********************************************************/
static void _commitment_calculate_c(BIGNUM*p, BIGNUM *g, BIGNUM *r, BIGNUM *h, BIGNUM *m, BIGNUM *c) {
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *gr = BN_new();
	BN_mod_exp(gr, g, r, p, ctx);	// gr = g^r (mod p)

	BIGNUM *hm = BN_new();
	BN_mod_exp(hm, h, m, p, ctx);	// hm = h^m (mod p)

	BN_mod_mul(c, gr, hm, p, ctx);	// c = g^r * h^m (mod p)

	// cleanup
	BN_free(gr);
	BN_free(hm);
	BN_CTX_free(ctx);
}

void commit(BIGNUM *p, BIGNUM *q, BIGNUM *g, BIGNUM *h, // in: p, q, g, h - parameters given by Receiver
	BIGNUM *m,		// in: m - secret value/message
	BIGNUM *r, BIGNUM *c) {	// out: r, c - Receiver will store c, sender will store r for decomittment

	_seed_prng();

	/*BIGNUM *q = BN_new();
	BIGNUM *one = BN_new();
	BN_one(one);
	BN_sub(q, p, one);		// q = p-1
	BN_free(one);*/

	BN_rand_range(r, q);		// r = random[0,q[

	//BN_free(q);

	_commitment_calculate_c(p, g, r, h, m,c);	// c = g^r * h^m (mod p)
}

/* returns 1 if c==c', 0 otherwise */
int decommit(BIGNUM *c,		 	//in: stored committed value
	BIGNUM *p, BIGNUM *g, BIGNUM *h,//in: p, g, h - phase 1 parameters
	BIGNUM *r, BIGNUM *m,		//in: r, m - r and original value
	BIGNUM *cbis) {			//out: c', if needed outside -  ignored if NULL
	
	BIGNUM *c2 = BN_new();
	_commitment_calculate_c(p, g, r, h, m, c2);	// c2 = g^r * h^m (mod p)

	int checkPassed = BN_cmp(c,c2)==0;	// c == c' ?

	// if c2 value needed outside
	if (cbis!=NULL) BN_copy(cbis, c2);

	// cleanup
	BN_free(c2);

	return checkPassed;
}
/***************************************************************************/

/****** X509 UTILS *********************************************************/
DSA* dsaKeyFromCertFile(char *filename) {
	X509 *cacert;
	FILE *fp;

	if (!(fp = fopen(filename, "r")))
		critical_error("Error reading certificate file");
	if (!(cacert = PEM_read_X509(fp, NULL, NULL, NULL)))
		critical_error("Error reading  certificate in file");
	fclose(fp);

	EVP_PKEY *ca_pkey = X509_get_pubkey(cacert);
	DSA* ca_dsa = EVP_PKEY_get1_DSA(ca_pkey);

	free(ca_pkey);
	X509_free(cacert);

	if (ca_dsa == NULL)
		critical_error("Can't read DSA key from certificate");

	return ca_dsa;
}
/***************************************************************************/

/****** COMMITMENT X509 EXTENSION ******************************************/
// enables handling of the extension as a string using an appropriate OID
static int _commitmentExt_start() {
	int nid = OBJ_create(COMMITMENT_OID_C, COMMITMENT_OID_SNAME, COMMITMENT_OID_LNAME);
	X509V3_EXT_add_alias(nid, NID_netscape_comment);
	return nid;
}
// when not needed anymore
static void _commitmentExt_end() {
	OBJ_cleanup();
}

// must be called between _commitmentExt_start and _commitmentExt_end
static BIGNUM* _commitmentExt2BN(X509_EXTENSION *ext) {

	// get the extension data as a string
	ASN1_IA5STRING *ia5 = (ASN1_IA5STRING *) X509V3_EXT_d2i(ext);
	char *str = ASN1_STRING_data(ia5);

	// convert the string into a BIGNUM
	BIGNUM *toret = BN_new();
	BN_hex2bn(&toret, str);
	free(str);

	return toret;
}

////////////////////////////////////////////////////////////////////////////

// reads the request req_filename and creates a modified creq_filename with the commitment extension added
void writeCommitmentCSR(BIGNUM *commitment_c, char *privkey_filename, char *req_filename, char *creq_filename) {
	FILE *fp;

	/* read in the request */
	X509_REQ *req;
	if (!(fp = fopen(req_filename, "r")))
		critical_error("Error reading request file");
	if (!(req = PEM_read_X509_REQ(fp, NULL, NULL, NULL)))
		critical_error("Error reading request in file");
	fclose(fp);

	/*  read in the private key */
	EVP_PKEY *pkey;
	if (!(fp = fopen(privkey_filename, "r")))
		critical_error("Error reading private key file");
	if (!(pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)))
		critical_error("Error reading private key in file");
	fclose(fp);

	/* create the new request */
	X509_REQ *creq;
	if (!(creq = X509_REQ_new()))
		critical_error("Failed to create X509_REQ object");

	X509_REQ_set_pubkey(creq, pkey);

	// gets subj from initial requests and adds it to new one
	X509_NAME *subj = X509_REQ_get_subject_name(req);
	if (X509_REQ_set_subject_name(creq, subj) != 1)
			critical_error("Error adding subject to request");

	// enable the commitment extension handling (retrieve/print as string)
	int nid = _commitmentExt_start();

	// get extensions stack of original request
	STACK_OF(X509_EXTENSION) *extlist = X509_REQ_get_extensions(req);

	// if no extensions, create new stack
	if (extlist==NULL) {
		extlist = sk_X509_EXTENSION_new_null();
	} else { // else check that the extension isn't already there (error!)
		X509_EXTENSION *tmp = (X509_EXTENSION*) X509V3_get_d2i(extlist, nid, NULL, NULL);
		if (tmp!=NULL)
			critical_error("Aborting process: CSR already contains commitment extension!\n");		
	}

	// create commitment extension storing C value as a hex string
	X509_EXTENSION *exCommitment = (X509_EXTENSION*) X509V3_EXT_conf_nid(NULL, NULL, nid, BN_bn2hex(commitment_c));
	if (!exCommitment)
		critical_error("error creating commitment extension");

	// push commitment extension into stack
	sk_X509_EXTENSION_push(extlist, exCommitment);

	// assign extensions to the new request
	if (!X509_REQ_add_extensions(creq, extlist))
		critical_error("Error adding extensions to the request");

	sk_X509_EXTENSION_pop_free(extlist, X509_EXTENSION_free);
	/////////////////////////////////////////////////////////////////////

	/* pick the correct digest and sign the new request */
	EVP_MD *digest;
	if (EVP_PKEY_type(pkey->type) == EVP_PKEY_DSA)
		digest = (EVP_MD*) EVP_dss1();
	else if (EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA)
		digest = (EVP_MD*) EVP_sha1();
	else
		critical_error("Error checking public key for a valid digest");

	if (!(X509_REQ_sign(creq, pkey, digest)))
		critical_error("Error signing request");

	/* write the modified request */
	if (!(fp = fopen(creq_filename, "w")))
		critical_error("Error writing to request file");
	if (PEM_write_X509_REQ(fp, creq) != 1)
		critical_error("Error while writing request");
	fclose(fp);

	// cleanup
	_commitmentExt_end();
	EVP_PKEY_free(pkey);
	X509_REQ_free(req);
	X509_REQ_free(creq);
}

// returns NULL if cert doesn't contain the extension, the commitment C value otherwise
BIGNUM *getCommitmentValueFromCert(char *cert_filename) {
	X509 *cert;
	FILE *fp;
	if (!(fp = fopen(cert_filename, "r")))
		critical_error("Error reading client certificate file");
	if (!(cert = PEM_read_X509(fp, NULL, NULL, NULL)))
		critical_error("Error reading client certificate in file");
	fclose(fp);
	BIGNUM *toret = NULL;

	// enable the extension handling (retrieve/print as string)
	int nid = _commitmentExt_start();

	// try to locate extension
	int extpos = X509_get_ext_by_NID(cert, nid, -1);

	if (extpos!=-1) { // extension found
		X509_EXTENSION *ext = X509_get_ext(cert, extpos);
		toret = _commitmentExt2BN(ext);		
	}
	X509_free(cert);
	_commitmentExt_end();
	return toret;
}

// returns NULL if CSR doesn't contain the extension, the commitment C value otherwise
BIGNUM *getCommitmentValueFromCSR(char *req_filename) {
	
	/* read in the request */
	X509_REQ *req;
	FILE *fp;
	if (!(fp = fopen(req_filename, "r")))
		critical_error("Error reading request file");
	if (!(req = PEM_read_X509_REQ(fp, NULL, NULL, NULL)))
		critical_error("Error reading request in file");
	fclose(fp);

	BIGNUM *toret = NULL;

	// enable the extension handling (retrieve/print as string)
	int nid = _commitmentExt_start();

	// get extensions stack of request
	STACK_OF(X509_EXTENSION) *extlist = X509_REQ_get_extensions(req);
			
	if (extlist!=NULL) {	// if there are extensions
		int extpos = X509v3_get_ext_by_NID(extlist, nid, -1); 	// try to locate extension
		if (extpos!=-1) { // if found	
			X509_EXTENSION *ext = X509v3_get_ext(extlist, extpos);
			toret = _commitmentExt2BN(ext);
		}
	} 
	X509_REQ_free(req);
	_commitmentExt_end();
	return toret;
}

/***************************************************************************/

