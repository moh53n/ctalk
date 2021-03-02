#include <net/socket.h>

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

int check_sock(int sock) {
    int error = 0;
    socklen_t len = sizeof (error);
    int retval = getsockopt (sock, SOL_SOCKET, SO_ERROR, &error, &len);
    if (retval == 0 && error == 0) {
        return 0;
    }
    else return -1;
}