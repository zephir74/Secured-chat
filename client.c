/*
 * Max username size is
 * 256 characters
 */ 
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // standard libraries
#include <poll.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h> // network libraries
#include <arpa/inet.h>

#include <openssl/ssl.h> // openssl libraries
#include <openssl/err.h>

void usage(const char *name) {
    fprintf(stdout, "%s -s <server_ip> -p port -u <username> [-h]\n", name);
    fprintf(stdout, "    -s <server_ip>  server IPv4 address to connect\n");
    fprintf(stdout, "    -p <port>       server port number\n");
    fprintf(stdout, "    -u <username>   username in the chat\n");
    fprintf(stdout, "    -h              this help message\n");
    fprintf(stdout, "\n");
}

int help_menu() {
    printf("*\n");
    printf("Available commands :\n");
    printf("/help : display this menu\n");
    printf("/users : list all active users\n");
    printf("/dir : list the current directory used by the server\n");
    printf("/ip : get the server's public IP address\n");
    printf("/reboot : reboot the server\n");
    printf("/quit : kill the current connection\n");
    printf("To send a message, enter just the string you want to send\n");
    printf("For private messages, enter @<username> <your_message>\n");
    printf("*\n");
    return 0;
}

void hexdump(const uint8_t *data, unsigned int size)
{
    int i;
    for (i = 0; i < size; i++) {
        if ((i % 16) == 0) {
            fprintf(stderr, "\n0x%04x: ", i);
        }
        fprintf(stderr, "0x%02x ", data[i]);
    }
}

int quit(int *should_stop) {
    *should_stop = 1;
    return 0;
}

int receive_msg(SSL *ssl) {
    char buffer[2048] = { 0 };
    int ret;

    ret = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (ret == -1) {
        perror("Error while receiving");
    } else {
        printf("%s\n", buffer);
    }

    return 0;
}

int read_input(SSL *ssl, char *buffer, int *pos, int buffer_size, int *should_stop) {
    int ret;
    char key;

    ret = read(STDIN_FILENO, &key, sizeof(key));
    if (ret != sizeof(key)) {
        perror("Error while reading key");
        return -1;
    }

    if (key == '\n') {
        if (strcmp(buffer, "/help") == 0) {
            ret = help_menu();
        } else if (strcmp(buffer, "/quit") == 0) {
            ret = quit(should_stop);
        } else {	
            ret = SSL_write(ssl, buffer, strlen(buffer));
            if (ret == -1) {
                perror("Error while sending message");
            }
        }
        
        memset(buffer, 0, buffer_size);
        *pos = 0;

        return ret;
    }

    if (*pos < buffer_size - 1) {
        buffer[*pos] = key;
        *pos += 1;
    }

    return 0;    
}

int main(int argc, char *argv[]) {
    int opt;
    struct pollfd fds[2];
    int ret;
    int pos = 0;
    char buffer[2048] = { 0 };
    int should_stop = 0;
    const char *username;
    const char *server_addr;
    int port;
    SSL_CTX *ctx;
    SSL *ssl;

    username = NULL;
    port = 1234;
    server_addr = NULL;

    while ((opt = getopt(argc, argv, "s:p:u:h")) != -1) {
        switch(opt) {
            case 's':
                server_addr = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'u':
                username = optarg;
                break;
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            default:
                fprintf(stderr, "Unsupported option '%c'\n", opt);
                break;
        }
    }

    if (username == NULL) {
        fprintf(stderr, "Username not specified !\n");
        printf("./client -h for help\n");
        exit(EXIT_FAILURE);
    }

    if (server_addr == NULL) {
        fprintf(stderr, "Server address not specified !\n");
        printf("./client -h for help\n");
        exit(EXIT_FAILURE);
    }

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(SSLv23_method());
    if (ctx == NULL) {
        printf("SSL object creation failed: ");
        ERR_print_errors_fp(stdout);
        exit(EXIT_FAILURE);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in address;
	address.sin_family = AF_INET;		  // struct to define type,
	address.sin_addr.s_addr = inet_addr(server_addr); // address and port to use
	address.sin_port = htons(port);

    if (connect(fd, (struct sockaddr*)&address, sizeof(address)) == -1) {
        perror("An error occured, cannot connect\n");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    ret = SSL_connect(ssl);
    if (ret != 1) {
        perror("An error occured, secure connection could not be established");
        exit(EXIT_FAILURE);
    }

    SSL_write(ssl, username, strlen(username));

    while (!should_stop) {
        memset(fds, 0, sizeof(fds));

        fds[0].fd = fd;
        fds[0].events = POLLIN;

        fds[1].fd = STDIN_FILENO;
        fds[1].events = POLLIN;

        ret = poll(fds, 2, -1);
        if (ret == -1) {
            perror("Error while polling");
            break;
        }

        if (fds[0].revents & POLLIN) {
            // read msg on socket
            receive_msg(ssl);
        }

        if (fds[1].revents & POLLIN) {
            // read keyboard input
            read_input(ssl, buffer, &pos, sizeof(buffer), &should_stop);
        }
    }

    printf("Connection closed\n");

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    
    shutdown(fd, 2);

    return 0;
}
