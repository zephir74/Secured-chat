all: server client

server: server.c
	gcc -Wall -Werror -O0 -g server.c -o server -lssl -lcrypto

client: client.c
	gcc -Wall -Werror -O0 -g client.c -o client -lssl -lcrypto

clean:
	rm -f server client
