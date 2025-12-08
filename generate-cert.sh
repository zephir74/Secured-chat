#!/bin/sh

for i in client server; do
#	openssl genrsa -out ${i}-key.pem 2048
#	openssl rsa -in ${i}-key.pem -pubout -out ${i}-cert.crt
#	openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ${i}-key.pem -out ${i}-pkcs8.key
	openssl req -x509 -newkey rsa:4096 -keyout ${i}-key.pem -out ${i}-cert.pem -sha256 -days 365 -nodes -subj "/CN=-${i}"
done
