#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "test.h"

int main()
{
	struct sockaddr_un address;
	int sockfd, newfd;

	enable_save_state();

	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(sockfd < 0)
	{
		perror("socket");
		return 1;
	}

	unlink("test_listen_socket");

	memset(&address, 0, sizeof(address));

	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, 255, "/home/maxim/linux-2.6/test/test_listen_socket");

	if(bind(sockfd, (struct sockaddr*)&address, sizeof(address)) != 0)
	{
		perror("bind");
		close(sockfd);
		return 1;
	}

	if(listen(sockfd, 1) != 0)
	{
		perror("listen");
		close(sockfd);
		return 1;
	}

	while(1)
	{
		char buff[256];
		int len;
		newfd = accept(sockfd, NULL, NULL);
		if(newfd < 0)
		{
			perror("accept");
			close(sockfd);
			return 1;
		}

		len = recv(newfd, buff, 255, 0);
		if(len <= 0)
		{
			if(len < 0) 
				perror("recv");
			close(newfd);
			continue;
		}

		send(newfd, buff, len, 0);
		close(newfd);
	}

	return 0;
}
