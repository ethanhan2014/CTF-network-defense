#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h>

#define BACKLOG 10 //pending connections queue will hold

volatile sig_atomic_t running = 1;

void error(char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void url_decode(char *input, char* dest, int max)
{
	while(*input)
	{
		if(*input == '%')
		{
			char buffer[3] = { input[1], input[2], 0 };
			*dest++ = strtol(buffer, NULL, 16);
			input += 3;
		}
		else
		{
			*dest++ = *input++;
		}
	}
}

int executeCommand(char *command, char *response)
{
    FILE *fp;
    char path[65535]={0};

    fp = popen(command, "r");
    if (fp == NULL){
        perror("Unable to open process\n");
    }

    while(fgets(path, sizeof(path), fp) != NULL){
        strcat(response, path);
    }

    int status = pclose(fp);
    return status;
}

void sendResponse(int fd, int status, char *response)
{
    char buf[65535] = {0};
    if (status == 200){
        sprintf(buf, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %zu\r\nContent-Type: text/plain;charset=utf-8\r\n\n%s\r\n", 
        strlen(response), response);
    }else if (status == 404) {
        sprintf(buf, "HTTP/1.1 404 Not Found\r\nContent-Encoding: gzip\r\nContent-Length: %zu\r\nContent-Type: text/plain;charset=utf-8\r\n\n%s\r\n", 
        strlen(response), response);
    }

    if (send(fd, buf, sizeof(buf), 0) == -1){
        perror("send");
        exit(1);
    }
}

void sigint_handler(int sig)
{
    printf("received SIGINT\n");
    running = 0;
}

void handle_request(int fd, struct sockaddr_in *clientaddr)
{
    char buffer[65535]= {0};
    char input[65535] = {0};
    char response[65535] = {0};
    int retval;

    pid_t pid = getpid();
    printf("Process Request, fd is %d, pid is %d.\n", fd, pid);
    if (recv(fd , buffer, sizeof buffer, 0) == -1)
    {
        perror("receive");
        exit(1);
    }
    /*handle GET request*/

    //if (sscanf(buffer, "GET /exec/%s HTTP/1.1", input) == 1)
    if (sscanf(buffer, "GET %s HTTP/1.1", input) == 1)
    {
        char url[65535] = {0};
        char command[65535] = {0};
        // char *url = calloc(strlen(input), sizeof(char));
        url_decode(input, url, strlen(input));
        printf("decoded url is %s\n", url);
        // char *command = calloc(strlen(url), sizeof(char));
        if (sscanf(url, "/exec/%[^\n]", command) == 1)
        {
            printf("command is %s\n", command);
            retval = executeCommand(command, response);
            if (retval == -1)
            {
                printf("error when executing commands. code %d. To send 404 response\n", retval);
                sendResponse(fd, 404, "Error when executing commands. Try again.");
            }
            else if (retval != 0)
            {
                sendResponse(fd, 404, "Command Not Found.");
            }
            else
            {
                sendResponse(fd, 200, response);
            }
        } else{
            printf("Illegal url. To send 404 response.\n");
            sendResponse(fd, 404, "Page Not Found.");
        }
        // free(url);
        // free(command);
    } else {
        printf("Illegal url. To send 404 response.\n");
        sendResponse(fd, 404, "Page Not Found.");
    }
}

int main(int argc, char *argv[]){
    int sockfd, newsockfd, rv;
    char *portno;
    int yes = 1;
    struct sockaddr_storage client_addr;
    struct addrinfo hints, *servinfo, *p;
    socklen_t sin_size;
    struct sigaction sa;
    char s[INET6_ADDRSTRLEN];

    /*get port number from commandline argument*/
    if (argc != 2)
    {
        fprintf(stderr, "Usage %s <port>", argv[0]);
        exit(1);
    }

    portno = argv[1];

    /*get server information*/
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if((rv = getaddrinfo(NULL, portno, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }

    /* Loop thru all results and bind to the first IP*/
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }
        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            error("setsockopt");
        }
        if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }
        break;
    }

    freeaddrinfo(servinfo);

    //catch ctrl-c
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    if (p == NULL){
        error("server: failed to bind\n");
    }
    
    if (listen(sockfd, BACKLOG) == -1)
    {
        error("server: listen");
    }

    printf("\n+++++++ Waiting for new connection ++++++++\n\n");

    /*accept loop*/
    while(running)
    {
        sin_size = sizeof client_addr;
        newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size);
        if (newsockfd == -1){
            perror("server: accept");
            continue;
        }

        inet_ntop(client_addr.ss_family,
            get_in_addr((struct sockaddr *)&client_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        // handle_request(newsockfd, (struct sockaddr_in *)&client_addr);
        int pid = fork();
        if (pid == 0){ //child process
            close(sockfd);
            handle_request(newsockfd, (struct sockaddr_in *)&client_addr);
            close(newsockfd);
            exit(0);
        }
        int child_status;
        waitpid(pid, &child_status, 0);
        printf("child result in status %d\n", WEXITSTATUS(child_status));
        close(newsockfd);
    }
    close(sockfd);
    return 0;
}
