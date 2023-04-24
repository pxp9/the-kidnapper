#!/bin/bash

OPENSSL=$(which openssl)

$OPENSSL genpkey -out key.pem -algorithm RSA -pkeyopt rsa_keygen_bits:4096

$OPENSSL rsa -in key.pem -pubout -out public_key.pem