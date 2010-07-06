#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#define USE_LIBC
#include "test.h"

int called = 0;
void sighandler(int signum)
{
	called = 1;
}

int main()
{
	struct sigaction act;
	int err;
	sigset_t suspend_set;
	
	act.sa_handler = sighandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	sigaction(SIGUSR1, &act, NULL);
	sigemptyset(&suspend_set);
	
	err=sigsuspend(&suspend_set);
	if(called == 1)
		return 0;
	else
		return 1;
}
