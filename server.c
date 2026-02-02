/*
 * Server script for secured
 * CLI chat application 
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h> // standard libraries
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#include <sys/socket.h> 
#include <netinet/in.h>

#include <openssl/err.h> 
#include <openssl/ssl.h>

#define MAX_CLIENT 5
#define CERT "server-cert.pem"
#define KEY "server-key.pem"

struct client {
    int fd;
    char *username;
    SSL *ssl;
};

void usage(const char *name) {
    fprintf(stdout, "%s -p port [-h]\n", name);
    fprintf(stdout, "   -p <port>    port to use (default: 1234)\n");
    fprintf(stdout, "   -h           this help message\n");
    fprintf(stdout, "\n");
}

int client_accept(int server_fd, struct sockaddr_in *address, struct client *id, int max_client, SSL_CTX *ctx) {
    socklen_t addrlen;
    int i;
    int fd;
    int ret;
    char buffer[256];
    SSL *ssl;

    memset(buffer, 0, sizeof(buffer));

    addrlen = sizeof(*address);
    
    ret = accept(server_fd, (struct sockaddr*)address, &addrlen);
    if (ret == -1) {
		perror("Error while accepting");
		return ret;
    }

    fd = ret;

    for (i = 0; i < max_client; i++) {
		if (id[i].fd == -1) {
			ssl = SSL_new(ctx);
			SSL_set_fd(ssl, fd);
			ret = SSL_accept(ssl);
			if (ret != 1) {
				printf("SSL connection could not be established\n");
				SSL_free(ssl);
				close(fd);
				return -EIO;
			}
		
			id[i].fd = fd;

			SSL_read(ssl, buffer, sizeof(buffer) - 1);

			id[i].username = strdup(buffer);

			id[i].ssl = ssl;
			
			printf("New client '%s' connected\n", id[i].username);
			
			snprintf(buffer, sizeof(buffer), "Hello %s, this is MCP.", id[i].username);
			SSL_write(ssl, buffer, strlen(buffer));

			return 0;
		}
    }

    printf("Too many clients, cannot accept\n");
    close(ret);
    return -EBUSY;
}

int client_handle_command_users(char *msg, int msg_size, struct client *id, int max_client) {
    char *ptr;
    int remaining;
    int i;
    int ret = 0;

    ptr = msg;
    remaining = msg_size;

    for (i = 0; i < max_client; i++) {
		if (id[i].fd == -1) {
			continue;
		}

		if (remaining == 0) {
			printf("Cannot write username, not enough space");
			return -ENOMEM;
		}
			
		ret = snprintf(ptr, remaining, "%s ", id[i].username);

		ptr += ret;
		remaining -= ret;
    }
	
	return 0;
}

int client_handle_command_dir(char *msg, int msg_size) {
	int ret = 0;

	if (getcwd(msg, msg_size) == NULL) {
	    strncpy(msg, "Cannot extract directory", msg_size);
	    ret = -errno;
	}

	return ret;
}

int client_handle_command_ip(char *msg, int msg_size) {
	FILE *pipe;
	int ret;

	pipe = popen("curl ifconfig.me -4", "r");
	if (pipe == NULL) {
	    strncpy(msg, "Cannot extract IP address", msg_size);
	    ret = -errno;
	    goto err_popen;
	}

	if (fgets(msg, msg_size, pipe) == NULL) {
	    strncpy(msg, "Cannot read IP address", msg_size);
	    ret = -EIO;
	    goto err_fgets;
	}

	ret = 0;

err_fgets:
	pclose(pipe);

err_popen:
	return ret;
}

int client_handle_command_reboot(char *msg, int msg_size) {
	int ret = 0;

	ret = system("shutdown -r now");
	if (ret == -1) {
	    strncpy(msg, "Cannot reboot target's system", msg_size);
	    ret = -errno;
	}

	return ret;
}

int client_handle_disconnect(struct client *client, struct client *id, int max_client) {
    int i;
    for (i = 0; i < max_client; i++) {
        if (id[i].fd == client->fd) {
            printf("Disconnect client '%s'\n", client->username);

            close(id[i].fd);
            id[i].fd = -1;

			free(id[i].username);
			id[i].username = NULL;
		
			SSL_free(id[i].ssl);
			id[i].ssl = NULL;

			return 0;
        }
    }
    
    return -EINVAL;
}

int client_handle_command(struct client *client, struct client *id, char *buffer, int max_client) {
    int ret;
    char msg_command[2048];
    int msg_command_size = sizeof(msg_command);
	
    if (strcmp(buffer, "/users") == 0) {
		client_handle_command_users(msg_command, msg_command_size, id, max_client);
    } else if (strcmp(buffer, "/dir") == 0) {
		client_handle_command_dir(msg_command, msg_command_size);
    } else if (strcmp(buffer, "/ip") == 0) {
		client_handle_command_ip(msg_command, msg_command_size);
    } else if (strcmp(buffer, "/reboot") == 0) {
		client_handle_command_reboot(msg_command, msg_command_size);
    } else {
		sprintf(msg_command, "Unknown command");
    }
	
    ret = SSL_write(client->ssl, msg_command, strlen(msg_command));
    if (ret == -1) {
        perror("Error while sending");
	ret = -errno;
    }
    
    return ret;
}

int client_handle_private_message(struct client *client, char *buffer, struct client *id, int max_client) {
    char *user;
    char *msg;
    int i;
    char *private = "[Private] "; 
    char *space = ": ";
	char *err_user = "Error: this user does not exist, please retry later";
	char message[2048];

	*message = '\0';
    
    user = buffer + 1;
    msg = memchr(buffer, ' ', strlen(buffer));
    if (!msg) {
		printf("Invalid message\n");
		return -EINVAL;
    }
    msg++;

	strcat(message, private);
	strcat(message, client->username);
	strcat(message, space);
	strcat(message, msg);

    for (i = 0; i < max_client; i++) {
		if (strncmp(id[i].username, user, strlen(id[i].username)) == 0) {
			SSL_write(id[i].ssl, message, strlen(message));
			*message = '\0';
			return 0;
		} else {
			SSL_write(id[i].ssl, err_user, strlen(err_user));
			printf("User %s not found\n", user);
    		return -EINVAL;
		}
    }

	return 0;
}

int client_handle_message(struct client *client, char *buffer, struct client *id, int max_client) {
    int i;
    char *space = ": ";
	char message[2048];

	*message = '\0';
    
    printf("%s", client->username);
    printf(": ");
    printf("%s\n", buffer);
	
	strcat(message, client->username);
	strcat(message, space);
	strcat(message, buffer);
    
    for (i = 0; i < max_client; i++) {
        if ((id[i].fd != -1) && (id[i].fd != client->fd)) {
			SSL_write(id[i].ssl, message, strlen(message));
        }
    }

	*message = '\0';
    
    return 0;
}

int client_handle(struct client *client, struct client *id, int max_client) {
	char buffer[2048];
	int ret;

	memset(buffer, 0, sizeof(buffer));
	
	ret = SSL_read(client->ssl, buffer, sizeof(buffer) - 1);
	if (ret == -1) {
	    perror("Error while receiving");
	    return ret;
	} else if (ret == 0) {
	    ret = client_handle_disconnect(client, id, max_client);
	} else {
	    if (buffer[0] == '/') {
			ret = client_handle_command(client, id, buffer, max_client);
	    } else if (buffer[0] == '@') {
			ret = client_handle_private_message(client, buffer, id, max_client);
	    } else {
			ret = client_handle_message(client, buffer, id, max_client);
	    }
	}
	
	return ret;
}

int main(int argc, char *argv[]) {
	int server_fd;
	int port;
	int opt;
	int i;
	int j;
	struct sockaddr_in address;
	struct client id[MAX_CLIENT];
	struct pollfd fds[1 + MAX_CLIENT];
    SSL_CTX *ctx;
	int fd_num;
	int ret;

	port = 1234; // default port

	while ((opt = getopt(argc, argv, "p:h")) != -1) {
        switch(opt) {
            case 'p':
                port = atoi(optarg);
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

	/* Initialize OpenSSL */
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	ctx = SSL_CTX_new(SSLv23_method());
	if (ctx == NULL) {
	    printf("SSL object creation failed: ");
	    ERR_print_errors_fp(stdout);
	    exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_certificate_file(ctx, CERT, SSL_FILETYPE_PEM) <= 0) {
	    ERR_print_errors_fp(stderr);
	    exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEY, SSL_FILETYPE_PEM) <= 0) {
	    ERR_print_errors_fp(stderr);
	    exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
	    fprintf(stderr,"Private key does not match the certificate public key\n");
	    exit(5);
	}
	
	/* Create server socket */
	ret = socket(AF_INET, SOCK_STREAM, 0); // create TCP socket
	if (ret == -1) {
	    perror("Socket creation failed");
	    exit(EXIT_FAILURE);
	}
	server_fd = ret;

	opt = 1;
	ret = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (ret == -1) {
	  perror("setsockopt(SO_REUSEADDR) failed");
	}
	
	address.sin_family = AF_INET;		  // struct to define type,
	address.sin_addr.s_addr = INADDR_ANY; // address and port to use
	address.sin_port = htons(port);
	
	if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) == -1) {
	    perror("Error while binding");
	    exit(EXIT_FAILURE);
	}
	
	if (listen(server_fd, 10) == -1) {
	    perror("Error while listening");
	    exit(EXIT_FAILURE);
	}

	memset(id, 0, sizeof(id));

	for (i = 0; i < MAX_CLIENT; i++) {
	    id[i].fd = -1;
	}

	while (1) {
	    memset(fds, 0, sizeof(fds));

	    fd_num = 0;
	    fds[fd_num].fd = server_fd;
	    fds[fd_num].events = POLLIN;
	    fd_num++;  
	    
	    for (i = 0; i < MAX_CLIENT; i++) {
			if (id[i].fd != -1) {
				fds[fd_num].fd = id[i].fd;
				fds[fd_num].events = POLLIN;
				fd_num++;
			}
	    }
		
	    ret = poll(fds, fd_num, -1);
	    if (ret == -1) {
			perror("Error while polling");
			break;
	    }

	    for (i = 0; i < fd_num; i++) {
			if (fds[i].revents & POLLIN) {
				if (i == 0) {
				/* The server socket is signaled, process incoming connection */
					client_accept(server_fd, &address, id, MAX_CLIENT, ctx);
				} else {
				/* Client socket, process message */
					struct client *client = NULL;

					for (j = 0; j < MAX_CLIENT; j++) {
						if (fds[i].fd == id[j].fd) {
							client = &id[j];
						}
					}

					client_handle(client, id, MAX_CLIENT);
				}
			}
	    }
	}
	
	SSL_CTX_free(ctx);

	return 0;
}
