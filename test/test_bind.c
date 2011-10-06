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
	int sockfd;
	struct addrinfo hints, *servinfo;
	int err;
	int yes = 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	
	// Want to bind to a specific address rather than any available one
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
		return 1;
	}


	// if bind is not working this would crash during restore
	while(1)
	{
		if(was_state_restored())
			exit(0);
		sleep(1);
	}
	return 1;
}
