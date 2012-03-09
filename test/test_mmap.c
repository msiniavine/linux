#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>

#include "test.h"

// 16 Megabytes
#define MMAP_SIZE 16 * 1024 * 1024

void touch_memory(void* addr, size_t size)
{
	int* mem = addr;
	int len = size/sizeof(int);
	int i;
	for(i=0; i < len; i++)
	{
		mem[i] = 0xbadbeef2;
	}

	for(i=0; i<len; i++)
	{
		if(mem[i] != 0xbadbeef2)
		{
			printf("Error accessing memory at %p, start %p size %u\n", &mem[i], addr,size);
			exit(0);
		}
	}
}

void do_sleep()
{
	struct timespec time = {3, 0};
	nanosleep(&time, NULL);

}

void fork_children(int fork_count)
{
	int current_count = fork_count;
	pid_t pid;

	while(current_count > 0)
	{
		pid = fork();
		if(pid < 0)
		{
			perror("Fork failed:");
			exit(0);
		}
		else if(pid == 0) 
		{
			// child, so will continue to fork more children
			current_count -= 1;
		}
		else
		{
			// parent, don't fork any more, just pause for a second
			break;
		}
	}
}

int main(int argc, char** argv)
{
	int fork_count = 0;
	char* endptr;

	enable_save_state();
	if(argc > 1)
	{
		fork_count = strtol(argv[1], &endptr, 0);
		if(endptr == argv[1])  // no numbers
		{
			fork_count = 0;
		}
	}
	void* mem = mmap(NULL, MMAP_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if(mem == MAP_FAILED)
	{
		perror("mmap failed:");
		exit(0);
	}

	touch_memory(mem, MMAP_SIZE);
	fork_children(fork_count);
	touch_memory(mem, MMAP_SIZE);


	while(!was_state_restored())
	{
		do_sleep();
	}

	touch_memory(mem, MMAP_SIZE);
	return 0;
}
