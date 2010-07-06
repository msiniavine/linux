#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test.h"

char* tests[] = {
	"test_loop",
	"test_altstack",
//	"test_condvar",
	"test_pending_signals",
	"test_pid",
	"test_restore_signal",
	"test_sighandler",
	"test_sighandler_call",
	"test_sigsuspend",
	"test_stack",
	"test_wait",
	NULL
};

void start_test(char* name)
{
	pid_t child;
	char path[256];
	strcpy(path, "./");
	strcat(path, name);
	child = fork();
	if(child < 0)
	{
		printf("Error starting test: %s\n", name);
		exit(1);
	}
	if(child == 0)
	{
		printf("%d: %s\n", getpid(), name);
		if(!execl(path, name, NULL))
		{
			perror("execl");
			exit(1);
		}
	}
}

int main()
{
	int i;
	int status;
	int err;
	enable_save_state();
	for(i = 0; tests[i] != NULL; i++)
	{
		start_test(tests[i]);
	}
	
	sleep(15);
	for(i = 0; tests[i] != NULL; i++)
	{
		err = wait(&status);

		if(err < 0)
		{
			perror("wait");
			return 1;
		}

		printf("%d: Normal exit: %s, code: %d\n", err, WIFEXITED(status) ? "yes" : "no", WEXITSTATUS(status));
	}
	return 0;
}
