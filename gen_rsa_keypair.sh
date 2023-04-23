OPENSSL=$(which openssl)

$OPENSSL genrsa -out key.pem 4096

$OPENSSL rsa -in key.pem -pubout -out public_key.pem