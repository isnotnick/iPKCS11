#!/bin/bash
set -e

echo "GENERATE A PRIVATE KEY"
set -x verbose
openssl genrsa -des3 -out server.key 2048
set +x verbose

echo
echo "CERTIFICATE SIGNING REQUEST"
set -x verbose
openssl req -new -key server.key -out server.csr
set +x verbose

echo
echo "REMOVE PASSPHRASE FROM KEY"
set -x verbose
cp server.key server.key.org
openssl rsa -in server.key.org -out server.key
set +x verbose

echo
echo "GENERATING A SELF-SIGNED CERTIFICATE"
set -x verbose
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
set +x verbose

echo DONE
