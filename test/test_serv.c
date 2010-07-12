#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#define USE_LIBC
#include  "test.h"

int main (int argc, char **argv){
	int sockfd;
	int n;
	socklen_t len;
	char msg[100];
	struct sockaddr_in servaddr, cliaddr;
	enable_save_state();
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0) {
	 printf("error\n");
	}
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(3000);
	bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

	for ( ; ; ){
            printf("here\n");
	    len = sizeof(cliaddr);
	    n = recvfrom(sockfd, msg, 100, 0, (struct sockaddr 
*)&cliaddr, &len);
	    
            int i = 0;
            for( i = 0; i<100; i++){
	    printf("%c", msg[i]);
	    }
            printf("\n");	
	}
return 0;
}
