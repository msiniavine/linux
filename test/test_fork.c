#define USE_LIBC
#include "test.h"

#include <stdio.h>
#include <unistd.h>

int main()
{
	int count = 1;
	int forked_again = 0;
	enable_save_state();
	fork();
	while(1)
	{
		sleep(1);
		printf("%d\n", count);
		count++;
		if(was_state_restored() && !forked_again)
		{
			forked_again = 1;
			fork();
		}
	}
	return 0;
}

