#ifndef CLIENT_CLIENT_H
#define CLIENT_CLIENT_H

#include <net/socket.h>

typedef struct
{
    in_addr_t ip;
    int port;
} client_p2p;

typedef struct
{
    int sock;
    int is_listen;
    int is_p2p;
    int halt;
    client_p2p clients[50];
    char * buff;
} client_tree;

int start_listen(client_tree * client);
char * recv_file(client_tree * root);
int write_file(char * name, char * base64, int src);
int send_file(char * token, client_tree * root);
char * get_ip(char * ip);
int join_group(int sock, char * token);
int read_safe(int sock, char * dest);
int p2p_info(int sock, char * token);
int p2p_recv(client_tree * client);
void * cli_recv(void * client);
int send_serialized(int sockfd, char * type, char * payload);
int get_param(char * dest, char * src, int index);
int send_tokenized(int socket, char * payload, char * token, char * type);
int send_message(int is_p2p, int socket, int chat, char * message, char * token);
int authenticate_serialize(int socket, char * secret);
int authenticate_get_resp(int socket, char * token);
int authenticate(int socket, char * password, char * glob_token);


#endif