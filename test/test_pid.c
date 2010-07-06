#include <unistd.h>
#include <stdio.h>
#define USE_LIBC
#include "test.h"

int main()
{
	pid_t new_pid;
	pid_t original_pid = getpid();
	printf("Current pid: %d\n", original_pid);
	while(!was_state_restored())
	{
		sleep(1);
	}

	new_pid = getpid();
	if(new_pid == original_pid)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}
