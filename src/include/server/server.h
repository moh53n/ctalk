#ifndef SERVER_SERVER_H
#define SERVER_SERVER_H

typedef struct
{
    int id;
    int users;
    int clients[50];
} group;

typedef struct
{
    int id;
    int sock;
    int is_group;
    group * group_ptr;
    void * root;
    char token[33];   
    char * buff;
} proto_authentication_client;

typedef struct
{
    int serv_sock;
    int cli_index;
    proto_authentication_client * clients;
} server_tree;

char * get_file(proto_authentication_client * cli);
int send_file(proto_authentication_client * dest, char * base64);
int deliver_group(proto_authentication_client * dest, int id, char * msg);
int deliver(proto_authentication_client * dest, int id, char * msg);
int check_pass(proto_authentication_client * cli);
int dispatch(proto_authentication_client * cli);
int join_group(server_tree * root, int cli, int group_id);
group * group_register(server_tree * root);
int client_recv(proto_authentication_client * cli);
void * client_register(void * clinet);
void server_welcome(void * server);
int new_token(char * token);
void server_authenticate(void * clinet);
int send_serialized(int sockfd, char * type, char * payload);
int read_safe(int sock, char * dest);
int get_param(char * dest, char * src, int index);

#endif