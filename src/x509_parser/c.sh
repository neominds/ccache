#gcc x509_read.c -o x509 -lssl -lcrypto
gcc -g3 x509_read.c asn.c logging.c -o x509
