#include "commitment_common.h"

int main(int argc, char *argv[]) {

	// parse params
	char *ca_cert_filename = NULL;
	char *cert_filename = NULL;
	char *req_filename = NULL;
	char *m_filename = NULL;
	char *r_filename = NULL;
	int verbose = 0;

	int cmdLine_err = 0;
	int c_opt;

	while (!cmdLine_err) {
               	int option_index = 0;
               	static struct option long_options[] = {
                   {"CAcert"	, 1, NULL, 'c'},
                   {"cert"	, 1, NULL, 'l'},
		   {"req"	, 1, NULL, 'q'},
                   {"in"	, 1, NULL, 'i'},
                   {"inR"	, 1, NULL, 'r'},
                   {"v"	    , 0, NULL, 'v'},
                   {0		, 0, 0, 0}
               	};

		c_opt = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c_opt==-1) break;

		switch (c_opt) {
			case 'c':
				ca_cert_filename = optarg;
				break;
			case 'l':
				cert_filename = optarg;
				break;
			case 'q':
				req_filename = optarg;
				break;	
			case 'i':
				m_filename = optarg;
				break;
			case 'r':
				r_filename = optarg;
				break;
			case 'v':
				verbose = 1;
				break;
			case '?':
				cmdLine_err = 1;
				break;
		}
	}

	// check parameters and show usage if neeeded
	if (! ( !cmdLine_err && ca_cert_filename && 
		(cert_filename || req_filename) && (!(cert_filename && req_filename)) &&
		 m_filename && r_filename ) ) {
		printf(
		"Sample usage:\n"
		"\t%s -cert userCert.pem -CAcert caCert.pem -in test.txt -inR test.txt.R\n"
		"\t%s -req  userReq.pem  -CAcert caCert.pem -in text.txt -inR test.txt.R\n"
		"warning: -cert and -req are mutually exclusive!\n"
		" -cert   : certificate containing commitment C value\n"		
		" -req    : certificate signing request containing commitment C value\n"
		" -CAcert : CA certificate (DSA) - (DSA key public values used as commitment parameters)\n"
		" -in     : input file (taken as commitment M value)\n"
		" -inR    : input file (taken as commitment R value)\n"
		" -v      : verbose - print status and values (in decimal form)\n"
		"\n", argv[0], argv[0]);
		return 1;
	}
	
	// init openssl error strings
	ERR_load_crypto_strings();

	// get m
	if (verbose) printf("Reading input file %s (M) as BIGNUM...\n", m_filename);
	BIGNUM *m = BN_new();
	readBNfromFile(m, m_filename);
	if (verbose) myBN_print("m",m);
	
	// get r
	if (verbose) printf("Reading input file %s (R) as BIGNUM...\n", r_filename);
	BIGNUM *r = BN_new();
	readBNfromFile(r, r_filename);
	if (verbose) myBN_print("r",r);

	// get parameters
	if (verbose) printf("Getting parameters from CA certificate...\n");
	DSA* ca_dsa = dsaKeyFromCertFile(ca_cert_filename);
	BIGNUM *p = ca_dsa->p;
	BIGNUM *g = ca_dsa->g;
	BIGNUM *h = ca_dsa->pub_key;
	if (verbose) {
			myBN_print("p",p);
			myBN_print("g",g);
			myBN_print("h",h);
	}

	// get committed value (from certificate or from CSR)
	BIGNUM *c;
	if (cert_filename) {
		if (verbose) printf("Getting committed value C from certificate %s...\n", cert_filename);
		c = getCommitmentValueFromCert(cert_filename);
		if (c==NULL)
			critical_error("Cannot find committment extension in this certificate!\n");
	} else { // if (req_filename) 
		if (verbose) printf("Getting committed value C from CSR %s...\n", req_filename);
		c = getCommitmentValueFromCSR(req_filename);
		if (c==NULL)
			critical_error("Cannot find commitment extension in this CSR!\n");
	}
	if (verbose) myBN_print("c",c);

	BIGNUM *c2 = NULL;
	if (verbose) c2 = BN_new();

	// decomittment
	if (decommit(c, p, g, h, r, m, c2))
		printf("Decommitment check OK\n");
	else
		printf("Decommitment check failed\n");

	if (verbose) {
		myBN_print("c'",c2);
		BN_free(c2);
	}

	// cleanup
	BN_free(c);
	BN_free(p);
	BN_free(g);
	BN_free(h);
	BN_free(r);
	BN_free(m);

	return 0;
}
