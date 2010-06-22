#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test.h"

char* tests[] = {
	"test_loop",
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
		execl(path, name, NULL);
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

	for(i = 0; tests[i] != NULL; i++)
	{
		err = wait(&status);

		if(err < 0)
		{
			perror("wait");
			return 1;
		}

		printf("%d: Normal exits: %s, code: %d\n", err, WIFEXITED(status) ? "yes" : "no", WEXITSTATUS(status));
	}
	return 0;
}
