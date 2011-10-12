#include "test.h"
#include "my_sockets.h"


int my_socket(int domain, int type, int protocol)
{
	unsigned long args[] = {domain, type, protocol};

	return my_socketcall(1, args);
}

int my_bind(int fd, const struct my_sockaddr_in* my_addr, unsigned long addrlen)
{
	unsigned long args[] = {fd, my_addr, addrlen};

	return my_socketcall(2, args);
}

int my_listen(int fd, int backlog)
{
	unsigned long args[] = {fd, backlog};
	return my_socketcall(4, args);
}

int my_accept(int fd, struct my_sockaddr_in* addr, unsigned long* addrlen)
{
	unsigned long args[] = {fd, addr, addrlen};
	return my_socketcall(5, args);
}

int my_recv(int fd, void* buff, unsigned long len, int flags)
{
	unsigned long args[] = {fd, buff, len, flags};
	return my_socketcall(10, args);
}

int my_send(int fd, const void* buff, unsigned long len, int flags)
{
	unsigned long args[] = {fd, buff, len, flags};
	return my_socketcall(9, args);
}



