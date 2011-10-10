#include <signal.h>
#include <stdio.h>
#define USE_LIBC
#include "test.h"
#include <unistd.h>

int main()
{
	sigset_t to_block, pending;
	
	sigemptyset(&to_block);
	sigemptyset(&pending);
	sigaddset(&to_block, SIGUSR1);

	sigprocmask(SIG_SETMASK, &to_block, NULL);

	sigpending(&pending);

	if(sigismember(&pending, SIGUSR1))
	{
		return 1;
	}
	

	raise(SIGUSR1);

	while(!was_state_restored())
	{
		sleep(1);
	}

	sigpending(&pending);

	if(sigismember(&pending, SIGUSR1))
	{
		return 0;
	}
	else
	{
		return 2;
	}
	return 0;
}
