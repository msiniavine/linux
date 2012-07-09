#define NO_LIBC
#include "test.h"

int _start()
{
//	enable_save_state();
        while(!was_state_restored())
	{
//		was_state_restored();
		int a = 1;
		int b = 1;
		int j;
		
//			12 ms delay
		for(j=0; j<1825000; j++)
		{
			int c = a+b;
			a=b;
			b=c;
		}

	}
        exit(0);
}

