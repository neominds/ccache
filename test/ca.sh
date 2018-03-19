openssl ecparam -name prime256v1 -genkey -out myrootca.key
openssl req -new -x509 -days 3650 -key myrootca.key -out myroot.crt -config ./openssl.cnf
mv myroot.crt CondorRootCA/signing-ca-1.crt
mv myrootca.key CondorRootCA/signing-ca-1.key
