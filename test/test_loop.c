#define NO_LIBC
#include "test.h"

int _start()
{
//	enable_save_state();
        while(!was_state_restored())
	{
//		was_state_restored();
	}
        exit(0);
}

