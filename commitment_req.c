#include "commitment_common.h"

int main(int argc, char *argv[]) {

	// parse params
	char *ca_cert_filename = NULL;
	char *pkey_filename = NULL;
	char *in_m_filename = NULL;
	char *in_req_filename = NULL;
	char *out_req_filename = NULL;
	char *out_r_filename = NULL;
	int verbose = 0;

	int cmdLine_err = 0;
	int c_opt;

	while (!cmdLine_err) {
               	int option_index = 0;
               	static struct option long_options[] = {
                   {"CAcert"	, 1, NULL, 'c'},
                   {"key"	, 1, NULL, 'k'},
                   {"in"	, 1, NULL, 'i'},
                   {"inreq"	, 1, NULL, 'u'},
                   {"outreq", 1, NULL, 'o'},
                   {"outR"	, 1, NULL, 'r'},
                   {"v"	    , 0, NULL, 'v'},
                   {0		, 0, 0, 0}
               	};

		c_opt = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c_opt==-1) break;

		switch (c_opt) {
			case 'c':
				ca_cert_filename = optarg;
				break;
			case 'k':
				pkey_filename = optarg;
				break;
			case 'i':
				in_m_filename = optarg;
				break;
			case 'u':
				in_req_filename = optarg;
				break;
			case 'o':
				out_req_filename = optarg;
				break;
			case 'r':
				out_r_filename = optarg;
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
	if (! ( !cmdLine_err && ca_cert_filename && pkey_filename && in_m_filename && in_req_filename && out_req_filename && out_r_filename) ) {
		printf(
		"Sample usage:\n\t%s -CAcert caCert.pem -key keyFile.pem -in test.txt -inreq req.pem -outreq creq.pem -outR test.txt.R\n"
		" -CAcert : CA certificate (DSA) - (DSA key public values used as commitment parameters)\n"
		" -key    : private key file (DSA or RSA) in PEM format (to sign CSR)\n"
		" -in     : input filename (taken as commitment M value)\n"
		" -inreq  : input CSR filename (create it with openssl req)\n"
		" -outreq : output filename (CSR containing committment C value) - overwritten if existant\n"
		" -outR   : output filename (containing commitment R value)      - overwritten if existant\n"
		" -v      : verbose - print status and values (in decimal form)\n"
		"\n",argv[0]);
		return 1;
	}

	// params ok, proceed

	// init openssl error strings
	ERR_load_crypto_strings();

	// get parameters from CA certificate
	if (verbose) printf("Getting parameters from CA certificate...\n");
	DSA* ca_dsa = dsaKeyFromCertFile(ca_cert_filename);
	if (verbose) {
		myBN_print("p",ca_dsa->p);
		myBN_print("q",ca_dsa->q);
		myBN_print("g",ca_dsa->g);
		myBN_print("h",ca_dsa->pub_key);
	}

	// get m
	if (verbose) printf("Reading input file %s as BIGNUM...\n", in_m_filename);
	BIGNUM *m = BN_new();
	readBNfromFile(m, in_m_filename);
	if (verbose) myBN_print("m",m);

	// allocate commitment output BIGNUMs
	BIGNUM *r = BN_new();
	BIGNUM *c = BN_new();

	// do commitment: output c,r
	if (verbose) printf("Calculating commitment values...\n");
	commit(ca_dsa->p, ca_dsa->q, ca_dsa->g, ca_dsa->pub_key, m, r, c);
	if (verbose) {
		myBN_print("r",r);
		myBN_print("c",c);
	}

	// write output files
	if (verbose) printf("Writing new CSR: %s\n", out_req_filename);
	writeCommitmentCSR(c, pkey_filename, in_req_filename, out_req_filename);

	if (verbose) printf("Writing R file: %s\n", out_r_filename);
	writeBNtoFile(r, out_r_filename);

	// done!
	printf("Commitment OK\n");

	//cleanup
	DSA_free(ca_dsa);
	BN_free(m);
	BN_free(r);
	BN_free(c);
	ERR_free_strings();

	return 0;
}
