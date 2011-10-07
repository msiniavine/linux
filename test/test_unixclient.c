#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

int main()
{
	struct sockaddr_un address;
	int sockfd, len;
	char buff[256];

	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(sockfd < 0)
	{
		perror("socket");
		return 1;
	}

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, 255, "/home/maxim/linux-2.6/test/test_listen_socket");

	if(connect(sockfd, (struct sockaddr*)&address, sizeof(address)) < 0)
	{
		perror("connect");
		return 1;
	}

	send(sockfd, "hello word\n", 12, 0);
	len = recv(sockfd, buff, 255, 0);
	if(len <= 0)
	{
		if(len < 0)
			perror("recv");
		close(sockfd);
		return 1;
	}
	
	buff[len] = '\0';
	printf("%s", buff);
	return 0;
}
