#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#include  "test.h"

int main(void)
  {
  	int sockfd;
	int n;
	char msg[256];
	struct sockaddr_in cliaddr;
	enable_save_state();
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	
	bzero(&cliaddr, sizeof(cliaddr));
	cliaddr.sin_family = AF_INET;
	cliaddr.sin_port = htons(3000);
	if (inet_aton("142.150.234.235", &cliaddr.sin_addr)==0) {
		printf("inet_aton() failed\n");
		return 1;
   	}

	n = 0;

	for ( ; ; ){
          //printf("Sending packet %d\n", n);
	  sprintf(msg, "%d",n);
     	  if (sendto(sockfd, msg, sizeof(msg), 0, (struct sockaddr*)&cliaddr, sizeof(cliaddr))==-1){
		  perror("sendto");
		  return 1;
		}
	  n++;
	  }
	return 0;
  }

