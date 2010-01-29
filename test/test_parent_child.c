#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include "test.h"


int main()
{
	pid_t child;
	enable_save_state();
	child = fork();
	if(child < 0)
	{
		return 1;
	}

	if(child == 0)
	{
		// inside child
//		enable_save_state();
		while(1);
	}
	else
	{
		while(1);
	}
	return 0;
}
