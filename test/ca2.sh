openssl req -newkey ec:<(openssl ecparam -name prime256v1) -keyout zmiller.key -config ./openssl.cnf -out zmiller.req
openssl ca -config ./openssl.cnf -out zmiller.crt -infiles zmiller.req

