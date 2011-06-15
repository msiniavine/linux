#include <unistd.h>

#define USE_LIBC
#include "test.h"

int main()
{
	enable_save_state();
	while(!was_state_restored())
	{
		sleep(10);
	}
	sleep(30);

	return 0;
}
