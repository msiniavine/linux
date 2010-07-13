/*#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#define USE_LIBC
*/
#define NO_LIBC
#include  "test.h"

int socketcall(int call, unsigned long* args);
int socket(void)
{
  unsigned long args[] = {2,2,0};
  int call = 1;

  return socketcall(call, args);
}

struct in_addr
{
  unsigned int s_addr;
};

struct sockaddr_in
{
  unsigned short sin_family;
  unsigned short sin_port;
  struct in_addr sin_addr;

  unsigned char pad[16-sizeof(short int) - sizeof(unsigned short int) - sizeof(struct in_addr)];
};


int sendto(int fd, char* msg, unsigned int size_msg, int i, struct sockaddr_in* addr, unsigned int size_addr)
{
  unsigned long args[] = {fd, msg, size_msg, i, addr, size_addr};
  int call = 11;
  return socketcall(call, args);  
}

//int main(void)
void _start()
  {
  	int sockfd;
	int n;
	//socklen_t len;
	char msg[] = "1337";
	struct sockaddr_in cliaddr;
	enable_save_state();
	//sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	sockfd = socket();
	
	//	bzero(&cliaddr, sizeof(cliaddr));
	//	cliaddr.sin_family = AF_INET;
	//	cliaddr.sin_port = htons(3000);
	//	if (inet_aton("172.16.177.1", &cliaddr.sin_addr)==0) {
   	//  printf("inet_aton() failed\n");
	//	return 1;
   	//}

	cliaddr.sin_family = 2;
	cliaddr.sin_port = 47115;
	cliaddr.sin_addr.s_addr = 28381356;
	//	n = 0;

	for ( ; ; ){
          //printf("Sending packet %d\n", n);
	  // sprintf(msg, "%d",n);
     	  if (sendto(sockfd, msg, sizeof(msg), 0, (struct sockaddr*)&cliaddr, sizeof(cliaddr))==-1){
		//printf("error sending!");	
		}
	  n++;
	  }
	exit(0);
  }

