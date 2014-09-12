#!/bin/bash

COUNTRY="GB"
STATE="London"
LOCATION="London"
ORG="Global Security"
COMMONNAME="example.com"

PASSWORD="123456"

echo "Use $PASSWORD for all passwords"
echo Press enter to go!
read 

# identity cert
openssl genrsa -out identity.key 1024
openssl req -new -key identity.key -nodes -out identity.csr -subj "/C=$GB/ST=$STATE/L=$LOCATION/O=$ORG/OU=TorIdentityCert/CN=$COMMONNAME"
openssl x509 -req -days 365 -in identity.csr -signkey identity.key -out identity.crt
rm identity.csr

# link cert, sign by identity
openssl req -new -newkey rsa:1024 -nodes -keyout link.key -out link.csr -days 365 -subj "/C=$GB/ST=$STATE/L=$LOCATION/O=$ORG/OU=TorIdentityCert/CN=$COMMONNAME"
openssl x509 -req -days 365 -in link.csr -CA identity.crt -CAkey identity.key -CAcreateserial -out link.crt
rm link.csr

openssl req -new -newkey rsa:1024 -nodes -keyout auth.key -out auth.csr -days 365 -subj "/C=$GB/ST=$STATE/L=$LOCATION/O=$ORG/OU=TorAuthCert/CN=$COMMONNAME"
openssl x509 -req -days 365 -in auth.csr -CA identity.crt -CAkey identity.key -CAcreateserial -out auth.crt
rm auth.csr

# produce a PKCS12 file incorporating pub and private link key
openssl pkcs12 -export -inkey link.key -in link.crt -name link -out link.p12 -password pass:$PASSWORD

keytool -importkeystore -destkeystore keystore.jks -deststorepass $PASSWORD -srckeystore link.p12 -srcstorepass $PASSWORD -srcstoretype PKCS12 -alias link

echo DONE! All keys generated.  Java keystore is keystore.jks.

