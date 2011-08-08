#define USE_LIBC
#include "test.h"
#include <stdio.h>
#include <unistd.h>

int main ( void )
{
	enable_save_state();
	
	int index = 0;
	
	fork();
	
        while(1)
	{
		sleep( 1 );
		
		index++;
		
		printf( "%d\n", index );
	}
	
	return 0;
}

