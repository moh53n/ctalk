#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <pthread.h>
#include <unistd.h>
#include <net/socket.h>
#include <client/client.h>
#include <client/base64.h>

int start_listen(client_tree * client) {
    int socket;
    client->is_listen = 1;
    client->is_p2p = 1;
    socket = init_socket();
    bind_socket(socket, 7070);
    listen_socket(socket);
    printf("Waiting for client...\n");
    client->sock = accept_socket(socket);
    printf("Connected!\n");
}

char * recv_file(client_tree * root) {
    char * base64 = malloc(1024 * 1024 * 4 * 1.5);
    //printf("IN GET FILE\n");
    bzero(base64, sizeof(base64));
    read(root->sock, base64, 6291456);
    //printf("OUT OF GET FILE\n%s\n", base64);
    return base64;
}

int write_file(char * name, char * base64, int src) {
    FILE *file;
    file = fopen(name, "w+");
    char * buffer = malloc(1024 * 1024 * 4);
    size_t output_length = 0;
    size_t len;
    len = strlen(base64);
    //printf("len:%d\n", len);
    buffer = base64_decode(base64, len, &output_length);
    //printf("Buffer: %s\n", buffer);
    fprintf(file, "%s", buffer);
    fclose(file);
    printf("Downloaded '%s' from %d!\n", name, src);
}

int send_file(char * token, client_tree * root) {
    char file_name[100];
    FILE *file;
    int dest;
    size_t fileLen;
    char * buffer;
    size_t output_length = 0;
    int i;
    char * base64 = malloc(1024 * 1024 * 4 * 1.5);
    printf("Please enter the file name: ");
    scanf("%s", file_name);
    printf("Please enter the destination: ");
    scanf("%d", &dest);
    //printf("Going to open file.\n");
    file = fopen(file_name , "rb");
    //printf("File Opened.\n");
    if (!file)
    {
      return -1;
    }
    fseek(file, 0, SEEK_END);
    fileLen=ftell(file);
    fseek(file, 0, SEEK_SET);
    buffer = malloc(fileLen + 1);
    fread(buffer, fileLen, 1, file);
    //printf("File Read.\n");
    base64 = base64_encode(buffer, fileLen, &output_length);
    //printf("Base64 done.\n");
    //printf("%s\n", base64);
    fclose(file);
    sprintf(buffer, "%d|%s", dest, file_name);
    send_tokenized(root->sock, buffer, token, "FILE_INFO");
    for (i=0;i<1000000;i++) {
        //printf("BUF: %s\n", root->buff);
        if (strncmp(root->buff, "FILE_GO", 7) == 0) {
            //printf("Going for send.\n");
            write(root->sock, base64, strlen(base64));
            break;
        }
    }
}

char * get_ip(char * ip) {
    //printf("ip ptr: %p\n", ip);
    char hostbuffer[256];
    struct hostent *host_entry;
    int hostname;
    hostname = gethostname(hostbuffer, sizeof(hostbuffer));
    //printf("hostname: %s\n", hostbuffer);
    host_entry = gethostbyname(hostbuffer); 
    ip = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0]));
    //printf("ip: %p\n", ip);
    return ip;
}

int join_group(int sock, char * token) {
    int grp;
    char grp_str[8];
    printf("Please enter the group ID: ");
    scanf("%d", &grp);
    sprintf(grp_str, "%d", grp);
    send_tokenized(sock, grp_str, token, "GRP_JOIN");
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
    //printf("..%s..", buff);
    strncpy(dest, buff, strlen(buff) + 1);
    return 0;
}

int p2p_info(int sock, char * token) {
    char * ip;
    //printf("\n%p\n", ip);
    char port[10];
    int dest;
    char buff[100];
    sprintf(port, "%d", 7070);
    ip = get_ip(ip);
    //printf("\n%s\n", ip);
    printf("Please enter the destination ID: ");
    scanf("%d", &dest);
    sprintf(buff, "%d", dest);
    strcat(buff, "|");
    strncat(buff, ip, strlen(ip) + 1);
    strcat(buff, "|");
    strncat(buff, port, strlen(port) + 1);
    send_tokenized(sock, buff, token, "P2P_INFO");
}

int p2p_recv(client_tree * client) {
    int option;
    client_tree * cli = (client_tree *) client;
    cli->sock = -1;
    cli->halt = 1;
    printf("\nConnection to server died. Please enter 1 for listen to other clients or 2 for connect to them.\n");
    scanf("%d", &option);
    if (option == 1) {
        start_listen(cli);
    }
    else {
        printf("Please enter the client ID: ");
        scanf("%d", &option);
        int socket = init_socket();
        connect_socket(socket, cli->clients[option].ip, cli->clients[option].port);
        cli->is_p2p = 1;
        cli->sock = socket;
    }
    cli->halt = 0;
}

void * cli_recv(void * client) {
    client_tree * cli = (client_tree *) client;
    //printf("sock: %d\n", cli->sock);
    char buff[200];
    char src[5];
    char temp[50];
    int counter = 0;
    char msg[200];
    char * base64;
    for (;;) {
        if (check_sock(cli->sock) != 0) {
            p2p_recv(cli);
            counter = 0;
        }
        if (counter > 10) {
            p2p_recv(cli);
            counter = 0;
        }
        if (read_safe(cli->sock, buff) == -1) {
            counter++;
            //printf("ERROR RECV: %d\n", counter);
            continue;
        }
        //printf("!!!\n");
        cli->buff = buff;
        get_param(temp, buff, 0);
        if (strncmp("P2P_INFO", temp, 8) == 0) {
            get_param(temp, buff, 1);
            int cli_index = strtol(temp, (char **)NULL, 10);
            get_param(temp, buff, 2);
            //printf("ip::%s\n", temp);
            cli->clients[cli_index].ip = inet_addr(temp);
            get_param(temp, buff, 3);
            cli->clients[cli_index].port = strtol(temp, (char **)NULL, 10);
            printf("Got p2p information of client %d!\n", cli_index);
            continue;
        }
        else if (strncmp(cli->buff, "FILE_INFO", 9) == 0) {
            char name[50];
            get_param(name, cli->buff, 2);
            send_serialized(cli->sock, "FILE_GO", "");
            base64 = recv_file(cli);
            get_param(temp, buff, 1);
            write_file(name, base64, strtol(temp, (char **)NULL, 10));
        }
        else if (strncmp("FILE_GO", temp, 7) == 0) continue;
        if (cli->is_p2p) {
            get_param(msg, buff, 0);
            printf("Message from p2p: %s\n", msg);
        }
        else {
            get_param(src, buff, 1);
            get_param(msg, buff, 2);
            printf("Message from %s: %s\n", src, msg);
        }
    }
}

int send_serialized(int sockfd, char * type, char * payload) {
    char buff[200];
    stpcpy(buff, type);
    strncat(buff, "|", 1);
    strcat(buff, payload);
    write(sockfd, buff, sizeof(buff));
    //printf("3 %s\n", buff);
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
    strncpy(dest, temp, strlen(temp)+1);
    return 0;
}

int send_tokenized(int socket, char * payload, char * token, char * type) {
    char buff[150];
    strncpy(buff, token, 33);
    //printf("1 %s\n", buff);
    strncat(buff, "|", 1);
    strncat(buff, payload, strlen(payload));
    //printf("2 %s\n", buff);
    send_serialized(socket, type, buff);
    return 0;
}

int send_message(int is_p2p, int socket, int chat, char * message, char * token) {
    char buff[110];
    if (strlen(message) >= 100) {
        return -1;
    }
    if (socket < 0) return -1;
    if (is_p2p == 1) {
        send_serialized(socket, message, "");
        return 0;
    }
    sprintf(buff, "%d", chat);
    strncat(buff, "|", 1);
    strncat(buff, message, strlen(message));
    send_tokenized(socket, buff, token, "MSG_SEND");
    return 0;
}


int authenticate_serialize(int socket, char * secret) {
	char payload[33];
	strncpy(payload, "0", 1);
	strncat(payload, "|", 1);
	strncat(payload, secret, 33);
	send_serialized(socket, "AUTH_SECRET", payload);
	//free(payload);
	return 0;
}

int authenticate_get_resp(int socket, char * token) {
	char buff[50]; 
	bzero(buff, sizeof(buff));
	read(socket, buff, sizeof(buff));
	if ((strncmp(buff, "AUTH_OK", 7)) != 0) {
		return -1;
	}
	get_param(token, buff, 1);
	return 0;
}

int authenticate(int socket, char * password, char * glob_token) {
    char token[33];
    authenticate_serialize(socket, password);
	authenticate_get_resp(socket, token);
	strncpy(glob_token, token, 33);
}

int main() {
    char glob_token[33];
    char pass[33];
    char buff[200];
    int dest;
    client_tree * client = malloc(sizeof(client_tree));
    pthread_t tid;
    client->is_p2p = 0;
    client->is_listen = 0;
    client->halt = 0;
    bzero(glob_token, sizeof(glob_token));
    strcpy(pass, "CasVVSkO7KDOOZBaDQBAC8K3Z5uUdlOa");
    client->sock = init_socket();
    connect_socket(client->sock, inet_addr("127.0.0.1"), 8080);
    authenticate(client->sock, pass, glob_token);
    //printf("END %s\n", glob_token);
    pthread_create(&tid, NULL, cli_recv, (void *)client);
    printf("Please set your destination ID: ");
    scanf("%d", &dest);
    for (;;) {
        if (client->halt == 1) continue;
        printf("Sending message to %d: ", dest);
        scanf("%s", buff);
        if (strncmp(buff, "/msg", 4) == 0) {
            printf("Please set your destination ID: ");
            scanf("%d", &dest);
            continue;
        }
        else if (strncmp(buff, "/join", 5) == 0) {
            join_group(client->sock, glob_token);
            continue;
        }
        else if (strncmp(buff, "/reg", 4) == 0) {
            send_tokenized(client->sock, "", glob_token, "GRP_REG");
            continue;
        }
        else if (strncmp(buff, "/send_p2p", 9) == 0) {
            p2p_info(client->sock, glob_token);
            printf("Sent!\n");
            continue;
        }
        else if (strncmp(buff, "/file", 5) == 0) {
            send_file(glob_token, client);
            printf("File Sent!\n");
            continue;
        }
        send_message(client->is_p2p, client->sock, dest, buff, glob_token);
    }
    return 0;
}