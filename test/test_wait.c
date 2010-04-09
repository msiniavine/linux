#include <sys/types.h>
#include <sys/wait.h>
#include "test.h"

int main()
{
	pid_t child;
	int status;
	enable_save_state();

	child = fork();
	if(child == 0)
	{
		while(!was_state_restored())
		{
			sleep(1);
		}
		exit(0);
	}
	else
	{
		waitpid(-1, &status, 0);
	}

	return status;
}
