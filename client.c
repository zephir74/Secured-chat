/*
 * Client script for secured
 * CLI chat application 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h> // standard libraries
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> // network libraries
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/ssl.h> // openssl libraries
#include <openssl/err.h>

void usage(const char *name) {
    fprintf(stdout, "%s -s <server_ip> -p <port> -u <username> [-h]\n", name);
    fprintf(stdout, "    -s <server_ip>  server IPv4 address to connect\n");
    fprintf(stdout, "    -p <port>       server port number (default: 1234)\n");
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
    struct addrinfo hints;
    struct addrinfo *result;
    struct pollfd fds[2];
    int opt;
    int ret;
    int pos = 0;
    int should_stop = 0;
    char buffer[2048] = { 0 };
    const char *username;
    const char *server_addr;
    char *port;
    SSL_CTX *ctx;
    SSL *ssl;

    memset(&hints, 0, sizeof(hints));
    
    username = NULL;
    port = "1234";
    server_addr = NULL;

    while ((opt = getopt(argc, argv, "s:p:u:h")) != -1) {
        switch(opt) {
            case 's':
                server_addr = optarg;
                break;
            case 'p':
                *port = atoi(optarg);
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

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(server_addr, port, &hints, &result);
    if (ret != 0) {
        printf("getaddrinfo() error: %s\n", gai_strerror(ret));
        exit(EXIT_FAILURE);
    }

    if (connect(fd, result->ai_addr, result->ai_addrlen) == -1) {
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

    freeaddrinfo(result);

    shutdown(fd, 2);

    return 0;
}
