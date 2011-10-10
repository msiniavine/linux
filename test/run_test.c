#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>

int main()
{
	pid_t child;
	child = fork();
	if(child == -1)
	{
		printf("Error calling fork\n");
		return 1;
	}
	else if(child == 0)
	{
		execl("set_state", "set_state", NULL);
	}
	else
	{
		pid_t wait_pid;
		int status;
		wait_pid = wait(&status);
		if(wait_pid < 0)
		{
			printf("Error calling wait\n");
			return 1;
		}
		printf("Child pid: %d, wait pid: %d, exited: %s, exit status: %d\n", child, wait_pid, 
		       WIFEXITED(status) ? "yes" : "no", WEXITSTATUS(status));
	}
	return 0;
}
