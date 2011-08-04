#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>

#include "test.h"


struct random
{
	unsigned int mw;
	unsigned int mz;
};

struct random r = {865048991, 117742254};


unsigned int get_random(struct random* r)
{
	r->mz = 36969 * (r->mz & 65535) + (r->mz >> 16);
	r->mw = 18000 * (r->mw & 65535) + (r->mw >> 16);
	return (r->mz << 16) + r->mw;
}



// Pattern generation meta function
typedef void (*pattern_gen)(void* dst, void* pattern, int len);
typedef int  (*pattern_check)(void* src, void* pattern, int len);

struct pattern_state
{
	void* private;
	pattern_gen gen;
	pattern_check check;
};

void fill_pattern(void* dst, struct pattern_state* state, int len)
{
	state->gen(dst, state->private, len);
}

int check_pattern(void* src, struct pattern_state* state, int len)
{
	return state->check(src, state->private, len);
}


// Random pattern generator function
void random_gen(void* dst, void* state, int len)
{
	unsigned int* buff = dst;
	struct random* r = (struct random*)state;
	int total_numbers = len/sizeof(unsigned int);
	int i;
	for(i=0; i<total_numbers; i++)
	{
		buff[i] = get_random(r);
	}
}

int random_check(void* src, void* state, int len)
{
	unsigned int* buff = src;
	struct random* r = state;
	int total_numbers = len/sizeof(unsigned int);
	int i;

	for(i=0;i<total_numbers; i++)
	{
		if(buff[i] != get_random(r))
			return 0;
	}

	return 1;
}

void init_random_gen(struct pattern_state* state)
{
	state->private = &r;
	state->gen = random_gen;
	state->check = random_check;
}

// TTCP like pattern
struct ttcp_pattern
{
	char pos; // current possition in the pattern;
};

void ttcp_gen(void* dst, void* state, int len)
{
	char* buff = dst;
	struct ttcp_pattern* pat = state;
	char current = pat->pos;
	int i;

	for(i = 0; i<len; i++)
	{
		buff[i] = current;
		current++;
		if(current > 126)
			current = 33;
	}

	pat->pos = current;
}

int ttcp_check(void* src, void* state, int len)
{
	char* buff = src;
	struct ttcp_pattern* pat = state;
	char current = pat->pos;
	int i;
	for(i = 0; i<len; i++)
	{
		if(buff[i] != current)
		{
			printf("content error at %d expected %x got %x\n", i, current, buff[i]);
			return 0;
		}
		current ++;
		if(current > 126)
			current = 33;
	}

	pat->pos = current;
	return 1;
}

struct ttcp_pattern ttcp_p = {33};
void init_ttcp_gen(struct pattern_state* state)
{
	state->private = &ttcp_p;
	state->gen = ttcp_gen;
	state->check = ttcp_check;
}

// get current time in microseconds
unsigned int gettime()
{
	unsigned long long usecs;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	usecs = tv.tv_sec * 1000000000 + tv.tv_usec;
	return usecs /1000;
}

void print_usage()
{
	printf("High load tcp test program\n");
	printf("Usage: test_sockload [options] -h <host> -p <port>\n");
	printf("\t-h - Host to connect to\n");
	printf("\t-p - Port to connect on\n");
	printf("Options:\n");
	printf("\t-r - Switches to receive mode and verifies that received data is correct\n");
	printf("\t-l - Limit the number of packets sent every second\n");
	printf("\t-t - Send an incrementing pattern rathen the default random one\n");
}

int send_all(int fd, void* buffer, size_t len)
{
	char* b = (char*)buffer;
	size_t sent = 0;
	while(sent < len)
	{
		size_t ret = 0;
		ret = send(fd, b+sent, len-sent, 0);
		if(ret < 0)
			return -1;
		else if(ret == 0)
			return 0;
		else
		{
			if(ret != len)
				printf("Partial send %d\n", ret);

			sent+=ret;
		}
	}

	return sent;
}

int read_all(int fd, void* buffer, size_t len)
{
	char* b = (char*)buffer;
	size_t received = 0;
	while(received < len)
	{
		size_t ret = recv(fd, b+received, len-received, 0);
		if(ret <= 0)
			return ret;
		received+=ret;
	}
	return received;
}

void print_addresses(struct addrinfo* res)
{
	struct addrinfo* p;
	char ipstr[INET6_ADDRSTRLEN];
	for(p=res; p!=NULL; p=p->ai_next)
	{
		struct sockaddr_in* addr = p->ai_addr;
		inet_ntop(p->ai_family, &addr->sin_addr, ipstr, sizeof(ipstr));
		printf("%s\n", ipstr);
	}
}

int do_send(const char* hostname, int port, int limit, int ttcp_pattern)
{
	int fd;
	unsigned int* buffer;
	int packets_sent = 0;
	unsigned int start;
	struct pattern_state state;

	struct addrinfo hints;
	struct addrinfo* servinfo;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if((err = getaddrinfo(hostname, "5000", &hints, &servinfo)) != 0)
	{
		printf("getaddrinfo error: %s\n", gai_strerror(err));
		return -1;
	}

	print_addresses(servinfo);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0)
	{
		perror("Error creating socket");
		return -1;
	}
	if(connect(fd, servinfo->ai_addr, servinfo->ai_addrlen) < 0)
	{
		perror("Connecting to host");
		return -1;
	}

	freeaddrinfo(servinfo);


	buffer = (unsigned int*)malloc(1024);
	memset(buffer, 0, 1024);
	start = gettime();
	if(ttcp_pattern)
		init_ttcp_gen(&state);
	else
		init_random_gen(&state);

	while(1)
	{
		int ret;
		if(limit > 0 && packets_sent > limit)
		{
			int sleep_time = (1000 - (gettime()-start))*1000;
			if(sleep_time > 0)
				usleep(sleep_time);
			start = gettime();
			packets_sent = 0;
		}

		fill_pattern(buffer, &state, 1024);
		ret = send_all(fd, buffer, 1024);
		if(ret < 0)
		{
			perror("Error sending");
			return -1;
		}
		else if(ret == 0)
			break;

		packets_sent++;
	}

	free(buffer);
	close(fd);
	return 0;
}

int do_receive(int port, int ttcp_pattern)
{
	int fd, clifd;
	struct sockaddr_in serv_addr, cli_addr;
	socklen_t clilen;
	unsigned int* buffer;
	int err = 0;
	int receive_count, receive_total;
	unsigned int start_time;
	struct pattern_state state;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0)
	{
		perror("Error creating socket");
		return -1;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	
	if(bind(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("Error binding socket");
		err = -1;
		goto close_fd;
	}

	if(listen(fd, 1) < 0)
	{
		perror("Error listening");
		err = -1;
		goto close_fd;
	}
	
	clilen = sizeof(cli_addr);
	if((clifd = accept(fd, (struct sockaddr*)&cli_addr, &clilen)) < 0)
	{
		perror("Error accepting");
		err = -1;
		goto close_fd;
	}

	buffer = (unsigned int*)malloc(1024);
	receive_count = 0;
	receive_total = 0;
	start_time = gettime();
	if(ttcp_pattern)
		init_ttcp_gen(&state);
	else
		init_random_gen(&state);
	while(1)
	{
		int ret;
		int cur_time;
		ret = read_all(clifd, buffer, 1024);
		if(ret == 0)
		{
			printf("Disconnected\n");
			err = 0;
			break;
		}
		if(ret < 0)
		{
			perror("Error during read");
			err = -1;
			break;
		}
		receive_count++;
		receive_total++;

		if(!check_pattern(buffer, &state, 1024))
		{
			printf("Error in buffer %d\n", receive_count);
			err=0;
			goto done;
		}

		
		cur_time = gettime();
		if(cur_time - start_time > 1000000)
		{
			printf("%u KB/s\n", receive_count);
			receive_count = 0;
			start_time = cur_time;
		}
		
	}

done:
	printf("Total received %u KBytes\n", receive_total);
	free(buffer);
	close(clifd);
close_fd:
	close(fd);
	return err;
}

int main(int argc, char** argv)
{
	int c;
	char* hostname= NULL;
	int port=0;
	int receive = 0;
	int limit = -1;
	int ttcp_pattern = 0;
	opterr = 0;
	enable_save_state();
	while((c=getopt(argc, argv, "rh:p:l:t")) != -1)
	{
		switch(c)
		{
		case 'h':
			hostname=optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'r':
			receive = 1;
			break;
		case 'l':
			limit=atoi(optarg);
			break;
		case 't':
			ttcp_pattern = 1;
			break;
		default:
			print_usage();
			return 1;
		}
	}

	if(receive)
	{
		if(port == 0)
		{
			print_usage();
			return 1;
		}

		return do_receive(port, ttcp_pattern);
	}

	if(hostname == NULL || port == 0)
	{
		print_usage();
		return 1;
	}

	return do_send(hostname, port, limit, ttcp_pattern);
	
}
