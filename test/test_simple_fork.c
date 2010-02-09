#define NO_LIBC
#include "test.h"

int _start()
{
	int err;
	enable_save_state();
	err = fork();
	if(err < 0)
	{
		exit(1);
	}

	if(err == 0)
	{
		while(1);
	}
	else
	{
		while(1);
	}

	exit(0);
}
