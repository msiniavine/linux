#define USE_LIBC
#include "test.h"

#include <stdio.h>
#include <unistd.h>

int main()
{
	int count = 1;
	enable_save_state();
	fork();
	while(1)
	{
		sleep(1);
		printf("%d\n", count);
		count++;
	}
	return 0;
}

