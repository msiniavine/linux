#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include "test.h"


int main()
{
	enable_save_state();
        while(1)
	{
		test_syscall();
	}
        return 0;
}
