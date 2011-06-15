#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#define USE_LIBC
#include "test.h"

int called = 0;

void sig_handler(int signum)
{
	called = 1;
}


int main()
{
	struct sigaction act;
	int err;
	act.sa_handler = sig_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	err = sigaction(SIGUSR1, &act, NULL);
//	printf("sigaction returned: %d\n", err);
	
	while(!was_state_restored())
	{
		sleep(1);
	}
//	printf("Received signal\n");
	raise(SIGUSR1);

	return !called;
}
