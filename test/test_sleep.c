#include <unistd.h>

#define USE_LIBC
#include "test.h"

int main()
{
	enable_save_state();
	while(1)
	{
		sleep(10);
	        was_state_restored();
	}
	sleep(30);

	return 0;
}
