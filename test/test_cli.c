#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#define USE_LIBC
#include  "test.h"

int main(void)
  {
  	int sockfd;
	int n;
	socklen_t len;
	char msg[100];
	struct sockaddr_in cliaddr;
	enable_save_state();
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0) {
	 printf("error\n");
	}
	printf("fd = %d\n",sockfd);
	bzero(&cliaddr, sizeof(cliaddr));
	cliaddr.sin_family = AF_INET;
	cliaddr.sin_port = htons(3000);
 	if (inet_aton("172.16.177.1", &cliaddr.sin_addr)==0) {
   	  printf("inet_aton() failed\n");
   	return 1;
   	}
	n = 0;

	for ( ; ; ){
          //printf("Sending packet %d\n", n);
	  msg[0] = n;
     	  if (sendto(sockfd, msg, len, 0, (struct sockaddr*)&cliaddr, sizeof(cliaddr))==-1){
		//printf("error sending!");	
		}
	  n++;
	}
return 0;
  }

