#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#define USE_LIBC
#include "test.h"

int called = 0;
void sighandler(int signum)
{
	while(!was_state_restored())
	{

	}
	called = 1;
}

int main()
{
	struct sigaltstack new;
	struct sigaction act;
	int err;
	void* stack = malloc(10*1024*1024);
	new.ss_sp = stack;
	new.ss_size = 10*1024*1024;
	new.ss_flags = 0;
	err = sigaltstack(&new, NULL);
	printf("sigaltstack returned: %d\n", err);

	act.sa_handler = sighandler;
        sigemptyset(&act.sa_mask);
	act.sa_flags = SA_ONSTACK;

	sigaction(SIGUSR1, &act, NULL);

	raise(SIGUSR1);
	while(!called)
	{

	}

	return 0;
}
