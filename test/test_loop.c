#define NO_LIBC
#include "test.h"

int _start()
{
	enable_save_state();
	//      while(!was_state_restored());
        while(1)
	{
		was_state_restored();
	}
        return 0;
}

