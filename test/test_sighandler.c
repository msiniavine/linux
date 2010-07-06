//#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#define USE_LIBC
#include "test.h"

void termination_handler(int signum)
{
	//nothing
}

int main()
{
	struct sigaction new_action, old_action;
	new_action.sa_handler = termination_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;

	sigaction(SIGUSR1, &new_action, NULL);
	while(!was_state_restored())
	{
		sleep(1);
	}
	
	sigaction(SIGUSR1, NULL, &old_action);

//	printf("Handler: %p, new handler: %p, old_handler: %p\n", termination_handler, new_action.sa_handler, old_action.sa_handler);
	//return 0;

	if(new_action.sa_handler == old_action.sa_handler && old_action.sa_handler == termination_handler)
	{
		return 0;
	}
	else
	{
		return 1;
	}

}
