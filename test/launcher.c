#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include "test.h"

int main()
{
	pid_t child;
	enable_save_state();
	child=fork();
	if(child == -1)
	{
		printf("Error calling fork\n");
		return 1;
	}
	else if(child == 0)
	{
		execl("/usr/bin/less", "less", "/home/maxim/linux-2.6/test/test_terminal.c", NULL);
	}
	else
	{
		while(!was_state_restored())
		{
			sleep(10);
		}

		sleep(100);
		printf("launcher exiting\n");
	}

	return 0;
}
