#include "test.h"
#include "my_sockets.h"


int my_socket(int domain, int type, int protocol)
{
	unsigned long args[] = {domain, type, protocol};

	return my_socketcall(1, args);
}

int my_bind(int fd, const struct my_sockaddr* my_addr, unsigned long addrlen)
{

}
