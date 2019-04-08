#!/bin/bash

# generate 2048 bit RSA keypair; output private key
openssl genrsa -out private.pem 2048

# export public key
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
