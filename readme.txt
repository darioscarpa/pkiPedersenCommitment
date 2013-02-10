=== PKI Pedersen Commitment =============================================
Pedersen Commitment scheme implementation based on X509 custom extensions
-------------------------------------------------------------------------
Developed as exam assignment for the
"Cryptography Tools for Information Security"
course taught at the University of Salerno 
_________________________________________________________________________
Dario Scarpa, 2009 - http://www.duskzone.it


This code should be an useful example in using OpenSSL to manipulate
X509 certificates and CSRs using custom extensions.

The included tools, commitment_req and commitment_chk, implement the
Pedersen commitment scheme in this way:

- commitment_req calculates and inserts into a CSR the "commitment" value
- commitment_chk verifies the commitment value inserted into a CSR or a 
  signed certificate, when the CA accepts the CSR and releases it
  
The entire process, including the CA setup, can be tested with the 
included bash script testing.sh.

You obviously need OpenSSL libs and openssl utility installed on your
system to compile the sources and run the script.

Refer to the source code or try the tools to have some usage info.
