#!/bin/bash

# generate 2048 bit RSA keypair; output private key
openssl genrsa -out timeserver-private.pem 2048

# export public key
openssl rsa -in timeserver-private.pem -outform PEM -pubout -out timeserver-public.pem
