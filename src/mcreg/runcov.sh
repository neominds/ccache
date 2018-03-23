rm *.gcno
rm *.gcda
rm *.info
rm -rf test1
#gcc -O0 -g3 -Wall -fmessage-length=0 -I. -fprofile-arcs -ftest-coverage mc_cache_flash.c mc_cache_osutil.c mc_cache.c mcreg.c -o mcreg -L. -lcrypto -lssl -lpthread -lgcov --coverage
gcc -O0 -g3 -Wall -fmessage-length=0 -DWC_NO_HARDEN -DLINUX -I. -I./wolfssl -I./cyassl -fprofile-arcs -ftest-coverage mc_cache_flash.c mc_cache_osutil.c mc_cache.c asn.c mcreg.c -o mcreg -L. -lcrypto -lssl -lpthread -lgcov --coverage
./mcreg mcreg_test1.txt
lcov -t "test1" -o test1.info -c -d .
genhtml -o test1 test1.info
