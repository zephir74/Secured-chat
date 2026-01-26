#!/bin/sh

for i in client server; do
	openssl req -x509 -newkey rsa:4096 -keyout ${i}-key.pem -out ${i}-cert.pem -sha256 -days 365 -nodes -subj "/CN=-${i}"
done
