gcc -O0 -g3 -Wall -fmessage-length=0 -DWC_NO_HARDEN -DLINUX -I. -I./wolfssl -I./cyassl -fprofile-arcs -ftest-coverage mc_cache_flash.c mc_cache_osutil.c mc_cache.c asn.c mcreg.c -o mcreg -L. -lcrypto -lssl -lpthread -lgcov --coverage