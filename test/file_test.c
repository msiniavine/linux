//#include <sys/types.h>
//#include <sys/stat.h>
//#include <fcntl.h>
//#include <stdio.h>

#include "test.h"


void _start()
{
	int fd = open("file_test.c", O_RDONLY);
	if(fd < 0)
	{
		print("Error opening test file\n");
		exit(1);
	}

	print("Test file fd:"); print_int(fd); print(" \n");
	enable_save_state();

	while(1)
	{
		if(was_state_restored()) exit(42);
	}

	exit(0);
}
