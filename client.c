#include <netdb.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <pthread.h>
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <netdb.h> 
#include <unistd.h>
#define SA struct sockaddr

typedef struct
{
    char type;   //auth type
} proto_authentication_req;

typedef struct
{
    char type;   //auth type
    char secret[33];   //128 bit secret
} proto_authentication_resp;

typedef struct
{
    char err_type[2];   //error type
} proto_authentication_err;

typedef struct
{
    char secret[33];   //128 bit token
} proto_authentication_ok;

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

int read_safe(int sock, char * dest);

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    //printf("BASE_CODE: %s\n", data);
    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    //printf("BASE_DECODE: %s\n", decoded_data);
    return decoded_data;
}

void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}

int check_sock(int sock) {
    int error = 0;
    socklen_t len = sizeof (error);
    int retval = getsockopt (sock, SOL_SOCKET, SO_ERROR, &error, &len);
    if (retval == 0 && error == 0) {
        return 0;
    }
    else return -1;
}

char * recv_file(client_tree * root) {
    proto_authentication_client * dest_cli;
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

int connect_socket(int sockfd, in_addr_t ip, int port) {
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr)); 

	servaddr.sin_family = AF_INET; 
	servaddr.sin_addr.s_addr = ip; 
	servaddr.sin_port = htons(port); 
    //printf("Ip: %d, Port: %d\n", ip, port);
	if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
		printf("connection failed...\n"); 
		return -1; 
	} 
	else
		printf("connected...\n");
        return sockfd;
}

int close_socket(int sockfd) {

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


int authenticate_serialize(int socket, proto_authentication_resp * req) {
	char payload[33];
	strncpy(payload, "0", 1);
	strncat(payload, "|", 1);
	strncat(payload, req->secret, 33);
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
    proto_authentication_resp * req = malloc(sizeof(proto_authentication_resp));
    req->type = "0";
    strncpy(req->secret, password, 33);
    authenticate_serialize(socket, req);
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
    connect_socket(client->sock, inet_addr("192.168.1.11"), 8080);
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