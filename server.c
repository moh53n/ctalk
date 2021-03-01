#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/in.h> 

#define SA struct sockaddr

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

group * group_register(server_tree * root);
int get_param(char * dest, char * src, int index);

int check_sock(int sock) {
    int error = 0;
    socklen_t len = sizeof (error);
    int retval = getsockopt (sock, SOL_SOCKET, SO_ERROR, &error, &len);
    if (retval == 0 && error == 0) {
        return 0;
    }
    else return -1;
}

char * get_file(proto_authentication_client * cli){
    char * base64 = malloc(1024 * 1024 * 4 * 1.5);
    printf("IN GET FILE\n");
    bzero(base64, sizeof(base64));
    read(cli->sock, base64, 6291456);
    printf("OUT OF GET FILE\n%s\n", base64);
    return base64;
}

int send_file(proto_authentication_client * dest, char * base64){
    write(dest->sock, base64, strlen(base64));
    printf("OUT OF SEND FILE\n");
    return 0;
}

int deliver_group(proto_authentication_client * dest, int id, char * msg) {
    int i;
    char buff[200];
    char temp[200];
    strcpy(buff, "0|0|0|");
    sprintf(temp, "<GROUP %d> ", dest->id);
    strncat(buff, temp, strlen(temp) + 1);
    get_param(temp, msg, 3);
    strncat(buff, temp, strlen(temp) + 1);
    printf("In deliver group\n");
    group * group_ptr = dest->group_ptr;
    server_tree * root = (server_tree *) dest->root;
    for (i = 0; i < group_ptr->users; i++) {
        deliver(&root->clients[group_ptr->clients[i]], id, buff);
    }
}

int deliver(proto_authentication_client * dest, int id, char * msg) {
    char buff[200];
    char tmp[200];
    if (dest->is_group == 1) {
        return deliver_group(dest, id, msg);
    }
    if (check_sock(dest->sock) != 0) return -1;
    get_param(tmp, msg, 3);
    printf("msg: %s\n", msg);
    bzero(buff, sizeof(buff));
    sprintf(buff, "%d", id);
    strncat(buff, "|", 1);
    strncat(buff, tmp, strlen(tmp) + 1);
    printf("%s\n", buff);
    printf("sock %d\n", dest->sock);
    send_serialized(dest->sock, "MSG_RECV", buff);
}

int check_pass(proto_authentication_client * cli) {
    char temp[32];
    get_param(temp, cli->buff, 1);
    if (strncmp(temp, cli->token, 32) == 0) {
        return 0;
    }
    return -1;
}

int dispatch(proto_authentication_client * cli) {
    char dest[5];
    char buff[200];
    char tmp[200];
    server_tree * root = (server_tree *) cli->root;
    printf("cli4 p %p\n", root);
    printf("got: %s from id %d in socket %d\n", cli->buff, cli->id, cli->sock);
    if (strncmp(cli->buff, "MSG_SEND", 8) == 0) {
        if (check_pass(cli) == -1) {
            printf("PASS ERR: %s\n", cli->buff);
            return -1;
        }
        get_param(dest, cli->buff, 2);
        printf("dest %d\n", root->clients[strtol(dest, (char **)NULL, 10)].id);
        deliver(&root->clients[strtol(dest, (char **)NULL, 10)], cli->id, cli->buff);
    }
    else if (strncmp(cli->buff, "P2P_INFO", 8) == 0) {
        if (check_pass(cli) == -1) {
            printf("PASS ERR: %s\n", cli->buff);
            return -1;
        }
        proto_authentication_client * dest_cli;
        get_param(dest, cli->buff, 2);
        dest_cli = &root->clients[strtol(dest, (char **)NULL, 10)];
        if (check_sock(dest_cli->sock) != 0) return -1;
        get_param(tmp, cli->buff, 3);
        printf("msg: %s\n", cli->buff);
        bzero(buff, sizeof(buff));
        sprintf(buff, "%d", cli->id);
        strncat(buff, "|", 1);
        strncat(buff, tmp, strlen(tmp) + 1);
        strncat(buff, "|", 1);
        get_param(tmp, cli->buff, 4);
        strncat(buff, tmp, strlen(tmp) + 1);
        printf("%s\n", buff);
        printf("sock %d\n", dest_cli->sock);
        send_serialized(dest_cli->sock, "P2P_INFO", buff);
    }
    else if (strncmp(cli->buff, "FILE_INFO", 9) == 0) {
        if (check_pass(cli) == -1) {
            printf("PASS ERR: %s\n", cli->buff);
            return -1;
        }
        char name[50];
        char * base64;
        int i;
        proto_authentication_client * dest_cli;
        get_param(dest, cli->buff, 2);
        get_param(name, cli->buff, 3);
        dest_cli = &root->clients[strtol(dest, (char **)NULL, 10)];
        send_serialized(cli->sock, "FILE_GO", "");
        base64 = get_file(cli);
        printf("%s\n", base64);
        sprintf(buff, "%d|%s", cli->id, name);
        send_serialized(dest_cli->sock, "FILE_INFO", buff);
        sleep(1);
        for (i=0;i<10;i++) {
            sleep(1);
            get_param(tmp, dest_cli->buff, 0);
            if (strncmp(tmp, "FILE_GO", 7) == 0) {
                printf("SENDING FILE!\n");
                send_file(dest_cli, base64);
                break;
            }
        }
        printf("OUT OF FILE\n");
    }
    else if (strncmp(cli->buff, "GRP_REG", 7) == 0) {
        if (check_pass(cli) == -1) {
            printf("PASS ERR: %s\n", cli->buff);
            return -1;
        }
        group * group_ptr = group_register(cli->root);
        group_ptr->users++;
        group_ptr->clients[group_ptr->users - 1] = cli->id;
        strcpy(buff, "0|0|0|Group Registered!");
        deliver(cli, group_ptr->id, buff);
    }
    else if (strncmp(cli->buff, "GRP_JOIN", 8) == 0) {
        printf("Go for join\n");
        if (check_pass(cli) == -1) {
            printf("PASS ERR: %s\n", cli->buff);
            return -1;
        }
        get_param(dest, cli->buff, 2);
        join_group(root, cli->id, strtol(dest, (char **)NULL, 10));
        printf("Go for deliver group\n");
        strcpy(buff, "0|0|0|Client joined the chat!");
        deliver(&root->clients[strtol(dest, (char **)NULL, 10)], cli->id, buff);
    }
    else {
        printf("TYPE ERR: %s\n", cli->buff);
    }
}

int join_group(server_tree * root, int cli, int group_id) {
    printf("In join\n");
    group * group_ptr = root->clients[group_id].group_ptr;
    printf("grp2 p %p\n", group_ptr);
    group_ptr->users++;
    printf("grp3 %d\n", group_ptr->users);
    group_ptr->clients[group_ptr->users - 1] = cli;
    printf("In join EXIT\n");
    return 0;
} 

group * group_register(server_tree * root) {
    group * group_ptr = malloc(sizeof(group));
    int index;
    printf("grp1 p %p\n", group_ptr);
    group_ptr->users = 0;
    root->cli_index++;
    index = root->cli_index - 1;
    root->clients[index].is_group = 1;
    root->clients[index].group_ptr = group_ptr;
    root->clients[index].id = index;
    root->clients[index].root = root;
    group_ptr->id = index;
    return group_ptr;
}

int client_recv(proto_authentication_client * cli) {
    for (;;) {
        if (check_sock(cli->sock) != 0) return -1;
        if (read_safe(cli->sock, cli->buff) == 0){
            printf("cli3 p %p\n", cli->root);
            dispatch(cli);
        }
    }
}

void * client_register(void * clinet) {
    char * buff = malloc(sizeof(char) * 1001);
    strcpy(buff, "");
    proto_authentication_client * cli = (proto_authentication_client*) clinet;
    server_authenticate(cli);
    printf("Hi %d\n", cli->id);
    printf("cli5 p %p\n", cli->root);
    cli->buff = buff;
    cli->is_group = 0;
    printf("buff1 p %p\n", buff);
    printf("buff2 p %p\n", cli->buff);
    sprintf(buff, "0|0|0|Welcome! Your ID is %d.", cli->id);
    printf("buf %s\n", buff);
    sleep(1);
    deliver(cli, cli->id, buff);
    strcpy(buff, "");
    client_recv(clinet);
    return 0;
}

void server_welcome(void * server) {
    server_tree * serv = (server_tree *) server;
    int cli_sock;
    serv->cli_index = 0;
    pthread_t tid;
    int len = sizeof(struct sockaddr_in);
    for (;;) {
        cli_sock = accept_socket(serv->serv_sock);
        serv->clients[serv->cli_index].sock = cli_sock;
        serv->clients[serv->cli_index].id = serv->cli_index;
        serv->clients[serv->cli_index].root = serv;
        printf("cli p %p\n", serv->clients[serv->cli_index].root);
        printf("cli2 p %p\n", serv);
        pthread_create(&tid, NULL, client_register, (void *)&serv->clients[serv->cli_index]);
        serv->cli_index++;
    }
}

int new_token(char * token) {
    int i;
    char pass[33];
    for(i = 0; i < 32; i++) {
        pass[i] = 65 + rand() % 57;
    }
    pass[i] = '\0';
    printf("%s\n",pass);
    strncpy(token, pass, 33);
}

void server_authenticate(void * clinet) {
    char buff[50];
    char secret[33];
    char pass[33];
    char token[33];
    printf("auth\n");
    strcpy(secret, "CasVVSkO7KDOOZBaDQBAC8K3Z5uUdlOa");
    proto_authentication_client * cli = (proto_authentication_client*) clinet;
    bzero(buff, sizeof(buff));
    strcpy(buff, "AUTH_REQ");
    //write(cli->sock, buff, sizeof(buff));
    bzero(buff, sizeof(buff));
    read(cli->sock, buff, sizeof(buff));
    printf("%d\n", cli->sock);
    printf("%s\n", buff);
    get_param(pass, buff, 2);
    printf("%s\n", pass);
    if (strncmp(pass, secret, 33) == 0) {
        new_token(token);
        printf("%s\n", token);
        strncpy(cli->token, token, 33);
        send_serialized(cli->sock, "AUTH_OK", token);
    }
}

int init_socket() { 
	int sockfd; 
	 	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) { 
		printf("socket creation failed...\n"); 
		return -1; 
	} 
	else
		printf("Socket successfully created..\n"); 
	    return sockfd;
} 

int connect_socket(int sockfd, int port) {
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr)); 

	servaddr.sin_family = AF_INET; 
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1"); 
	servaddr.sin_port = htons(port); 

	if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
		printf("connection with the server failed...\n"); 
		return -1; 
	} 
	else
		printf("connected to the server..\n");
        return sockfd;
}

int bind_socket(int sockfd, int port) {
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr)); 
  
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(port); 
  
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed...\n"); 
        return -1; 
    } 
    else
        printf("Socket successfully binded..\n");
        return sockfd;
}

int listen_socket(int sockfd) {
    if ((listen(sockfd, 5)) != 0) { 
        printf("Listen failed...\n"); 
        return -1; 
    } 
    else
        printf("Server listening..\n");
        return sockfd;
}

int accept_socket(int sockfd) {
    int connfd, len;
    struct sockaddr_in cli; 

    len = sizeof(cli);
    connfd = accept(sockfd, (SA*)&cli, &len); 
    if (connfd < 0) { 
        printf("server acccept failed...\n"); 
        return -1;
    } 
    else
        printf("server acccept the client...\n"); 
        return connfd;
}

int close_socket(int sockfd) {

}

int send_serialized(int sockfd, char * type, char * payload) {
    char buff[200];
    stpcpy(buff, type);
    strcat(buff, "|");
    strcat(buff, payload);
    printf("%s\n", buff);
    write(sockfd, buff, sizeof(buff));
    return 0;
}

int read_safe(int sock, char * dest) {
    char buff[200];
    int i = 0;
    bzero(buff, sizeof(buff));
    strcpy(buff, "");
    while (strncmp(buff, "", 200) == 0 || strncmp(buff, "\n", 200) == 0 || strlen(buff) < 2) {
        read(sock, buff, sizeof(buff));
        i++;
        if (i >= 5) {
            return -1;
        }
    }
    printf("READ %s\n", buff);
    strncpy(dest, buff, strlen(buff) + 1);
    return 0;
}

int get_param(char * dest, char * src, int index) {
    char temp[200];
    int n = 0;
    int i = 0;
    int j = 0;
    bzero(temp, sizeof(temp));
    for (i; i<200; i++) {
        if (src[i] == '|') {
            n++;
            continue;
        }
        if (src[i] == '\0' || src[i] == '\n') {
            break;
        }
        if (n == index) {
            temp[j] = src[i];
            j++;
        }
    }
    temp[j] = 0;
    strncpy(dest, temp, strlen(temp) + 1);
    return 0;
}

int main() {
    int socket;
    char buff[1000];
    proto_authentication_client * clients = malloc(sizeof(proto_authentication_client) * 1000);
    server_tree * server = malloc(sizeof(server_tree));
    socket = init_socket();
    bind_socket(socket, 8080);
    listen_socket(socket);
    server->serv_sock = socket;
    server->clients = clients;
    printf("GO for welcome\n");
    server_welcome(server);
    bzero(buff, sizeof(buff));
    printf("%d\n", server->clients[0].sock);
    read_safe(server->clients[0].sock, buff);
    printf("I: %s\n", buff);
}