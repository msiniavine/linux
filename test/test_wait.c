#define NO_LIBC
#include "test.h"

int _start()
{
	int child;
	
	enable_save_state();

	child = fork();
	if(child >= 0)
	{
		while(!was_state_restored())
		{
			
		}
		exit(0);
	}
	exit(1);
}
