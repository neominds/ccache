#!/bin/sh

declare -a cmdfiles=("cert_test.txt" "cert_test.txt" "cert_test.txt")

for i in "${cmdfiles[@]}"
do
   # or do whatever with individual element of the array
   echo Running "$i"..
   if ./mcreg "$i" |grep FAIL
   then
     echo "FAIL"
     exit
   else
     echo "PASS"
   fi
done

