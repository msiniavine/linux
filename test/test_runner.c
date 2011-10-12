#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "test.h"

char* tests[] = {
	"test_loop",
	"test_altstack",
	"test_bind",
	"test_pending_signals",
	"test_pid",
	"test_restore_signal",
	"test_sighandler",
	"test_sighandler_call",
	"test_sigsuspend",
	"test_stack",
	"test_wait",
	"test_fork",
	"test_tempfile",
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
	int all_errs = 0;

	enable_save_state();
	for(i = 0; tests[i] != NULL; i++)
	{
		start_test(tests[i]);
	}
	
	while(!was_state_restored())
	{
		sleep(1);
	}	
	sleep(3);
	for(i = 0; tests[i] != NULL; i++)
	{
		err = wait(&status);
		if(err < 0)
		{
			fprintf(stderr, "wait on %s failed: %s\n", tests[i], strerror(errno));
			exit(1);
		}
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status)) {
				fprintf(stderr, "test = %s, pid = %d, exited status = %d\n", tests[i], err, WEXITSTATUS(status));
				all_errs = 1;
				// exit(1);
			}
		} else { /* bad exit */
			if (WIFSIGNALED(status)) {
				fprintf(stderr, "test = %s, pid = %d, process signal = %d\n", tests[i], err, WTERMSIG(status));
			} else {
				fprintf(stderr, "test = %s, pid = %d, process crashed\n", tests[i], err);
			}
			all_errs = 1;
			// exit(1);
		}
	}
	if (!all_errs) {
		printf("\nall tests passed\n");
		exit(0);
	}
	exit(1);
}
