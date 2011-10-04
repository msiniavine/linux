#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test.h"

int main()
{
	int sockfd, newfd; // listen on sockfd, new connections on newfd
	struct addrinfo hints, *servinfo;
	int err;
	int yes = 1;

	enable_save_state();

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	
	if((err = getaddrinfo("localhost", "8080", &hints, &servinfo)) != 0)
	{
		fprintf(stderr, "getaddrinfo %s\n", gai_strerror(err));
		return 1;
	}

	if((sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) < 0)
	{
		perror("socket");
		return 1;
	}

	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
	{
		perror("setsockopt");
		return 1;
	}

	if(bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) < 0)
	{
		close(sockfd);
		perror("bind");
		return 1;
	}

	freeaddrinfo(servinfo);

	if(listen(sockfd, 1) < 0)
	{
		close(sockfd);
		perror("listen");
		return 0;
	}

	while(1)
	{
		int read;
		char buff[256];
		newfd = accept(sockfd, NULL, NULL);
		if(newfd < 0)
		{
			perror("accept");
			close(sockfd);
			return 1;
		}

		read = recv(newfd, buff, 255, 0);
		if(read < 0)
		{
			perror("recv");
			close(newfd);
			continue;
		}
		if(read == 0)
		{
			close(newfd);
			continue;
		}

		buff[read] = '\0';
		err = send(newfd, buff, read,0);
		if(err < 0)
		{
			perror("send");
		}
		close(newfd);
	}
}
