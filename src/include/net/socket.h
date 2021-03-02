#ifndef NET_SOCKET_H
#define NET_SOCKET_H

#include <netinet/in.h> 
#include <netdb.h> 

#define SA struct sockaddr

int bind_socket(int sockfd, int port);
int listen_socket(int sockfd);
int accept_socket(int sockfd);
int init_socket();
int connect_socket(int sockfd, in_addr_t ip, int port);
int close_socket(int sockfd);
int check_sock(int sock);

#endif