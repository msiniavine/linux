#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <unistd.h>

#include "test.h"
#include "my_sockets.h"

int main()
{
	int sockfd, newsockfd, portno;
	char buffer[256];
	socklen_t clilen;
	struct sockaddr_in serv_addr, cli_addr;
	int n;

	enable_save_state();
	sockfd=my_socket(MY_AF_INET, MY_SOCK_STREAM, 0);
	if(sockfd < 0)
	{
		perror("Error opening socket");
		exit(1);
	}

	bzero(&serv_addr, sizeof(serv_addr));
	portno=5001;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	if(my_bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("Error binding a socket");
		exit(1);
	}

	if(my_listen(sockfd, 1) < 0)
	{
		perror("Error listening on a socket");
		exit(1);
	}
	clilen = sizeof(cli_addr);

	newsockfd = accept(sockfd, (struct sockaddr*)&cli_addr, &clilen);
	if(newsockfd < 0)
	{
		perror("Error on accept");
		exit(1);
	}
	while(1)
	{
		bzero(buffer, 256);
		n = my_recv(newsockfd, buffer, 255, 0);
		printf("recv returned %d\n", n);
		if(n < 0)
		{
			perror("Error reading from socket");
			break;
		}
		if(n == 0)
		{
			printf("Client disconnected\n");
			break;
		}

		printf("ECHO: %s\n", buffer);
		n=my_send(newsockfd, buffer, n, 0);
		printf("send returned %d\n", n);
		if(n < 0)
		{
			perror("Error writing");
			break;
		}
		if(n==0)
		{
			printf("Client disconnected");
			break;
		}
	}

	return 0;
}
