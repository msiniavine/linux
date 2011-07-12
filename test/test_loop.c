#define USE_LIBC
#include "test.h"
#include <stdio.h>

int main ( void )
{
	enable_save_state();
	
	int index = 0;
	
        while(1)
	{
		sleep( 1 );
		
		index++;
		
		printf( "%d\n", index );
	}
	
	return 0;
}

