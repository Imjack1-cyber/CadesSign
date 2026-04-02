#!/bin/bash

# Simple Certificate Chain Generation
# Creates: Root CA -> Intermediate CA -> End-Entity Certificate

set -e

mkdir -p certs/
mkdir -p keys/
mkdir -p crls/
mkdir -p keystore/

echo "Generating certificate chain..."

# 1. Root CA - private key and certificate
openssl genrsa -out keys/root.key 2048
openssl req -x509 -new -nodes -key keys/root.key -days 3650 -out certs/root.crt \
    -subj "/C=DE/ST=Berlin/L=Berlin/O=Test/CN=Root CA"

# 2. Intermediate CA - private key and CSR
openssl genrsa -out keys/intermediate.key 2048
openssl req -new -key keys/intermediate.key -out certs/intermediate.csr \
    -subj "/C=DE/ST=Berlin/L=Berlin/O=Test/CN=Intermediate CA"

# 3. Sign Intermediate with Root
openssl x509 -req -in certs/intermediate.csr -CA certs/root.crt -CAkey keys/root.key \
    -CAcreateserial -out certs/intermediate.crt -days 1825
    rm -rf certs/intermediate.csr

# 4. End-Entity - private key and CSR
openssl genrsa -out keys/server.key 2048
openssl req -new -key keys/server.key -out certs/server.csr \
    -subj "/C=DE/ST=Berlin/L=Berlin/O=Test/CN=example.com"

# 5. Sign End-Entity with Intermediate
openssl x509 -req -in certs/server.csr -CA certs/intermediate.crt -CAkey keys/intermediate.key \
    -CAcreateserial -out certs/server.crt -days 365
    rm -rf certs/server.csr

echo ""
echo "Done creating certificates and keys!"

# 6. Create PKCS#12 keystore with the certificate chain
cat certs/intermediate.crt certs/root.crt > /tmp/chain.pem
openssl pkcs12 -export \
    -in certs/server.crt \
    -inkey keys/server.key \
    -certfile /tmp/chain.pem \
    -out keystore/keystore.p12 \
    -passout pass:"1234" \
    -name "server"
rm -f /tmp/chain.pem

echo "✓ PKCS#12 keystore created: keystore/keystore.p12 (password: 1234)"
echo ""
./generate_crls.sh
echo ""
./update_trustlist.sh
echo ""
