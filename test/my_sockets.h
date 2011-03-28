#ifndef MY_SOCKETS_H
#define MY_SOCKETS_H

#define MY_AF_INET 2

#define MY_SOCK_STREAM 1


struct my_in_addr
{
  unsigned int s_addr;
};

struct my_sockaddr_in
{
  unsigned short sin_family;
  unsigned short sin_port;
  struct my_in_addr sin_addr;

  unsigned char pad[16-sizeof(short int) - sizeof(unsigned short int) - sizeof(struct my_in_addr)];
};



int my_socket(int domain, int type, int protocol);
int my_bind(int fd, const struct my_sockaddr* my_addr, unsigned long addrlen);

#endif
