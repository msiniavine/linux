#include <stdlib.h>
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
	struct sigaction act;
	act.sa_handler = sighandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	sigaction(SIGUSR1, &act, NULL);

	raise(SIGUSR1);

	while(!called)
	{
		
	}

	return 0;
}

