#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include "test.h"

int main(int argc, char* argv[])
{
	pid_t pid;
	if(argc != 2)
	{
		printf("Usage launcher <pid>\n");
		return 1;
	}
	
	pid = atoi(argv[1]);
	enable_save_state_pid(pid);
	
	return 0;
}
