#! /bin/bash
mkdir certs
cd certs

# Create CA key
echo "Creating CA key. you need to fill FQDN!"
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

# Create client and server certificates
echo "Creating server Keys, please fill in relevant information"
openssl req -newkey rsa:2048 -nodes -days 365 -keyout client-key.pem -out client-req.pem
openssl x509 -req -days 365 -set_serial 01 -in client-req.pem -out client-cert.pem -CA cert.pem -CAkey key.pem

echo "Creating server Keys, please fill in relevant information"
openssl req -newkey rsa:2048 -nodes -days 365 -keyout server-key.pem -out server-req.pem
openssl x509 -req -days 365 -set_serial 02 -in server-req.pem -out server-cert.pem -CA cert.pem -CAkey key.pem

# Create public keys from them
openssl x509 -pubkey -noout -in cert.pem  > pubkey.pem
openssl x509 -pubkey -noout -in client-cert.pem  > client-pubkey.pem
openssl x509 -pubkey -noout -in server-cert.pem  > server-pubkey.pem

