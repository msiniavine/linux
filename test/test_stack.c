#define NO_LIBC
#include "test.h"

int recursive_call(int n)
{
	char bump[1024];
	if(n == 0) return 0;
	
	return recursive_call(n-1);
}

int _start()
{
	recursive_call(100);
	while(!was_state_restored());
	recursive_call(1000);
	exit(0);
}
