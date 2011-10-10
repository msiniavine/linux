#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#define USE_LIBC
#include "test.h"

// Test named pipes
int main()
{
	int npfd[2], err, i = 0, fd;
	char buf[30];

	enable_save_state();
	write(STDOUT_FILENO, "Program Starting!\n", sizeof("Program Starting!\n"));

	if (mkfifo("/home/maxim/linux-2.6/test/fifopipe", 777) != 0)
	{
		write(STDOUT_FILENO, "Error creating pipe!\n", sizeof("Error creating pipe!\n"));
		return 1;
	}

	err = fork();

	if (err == 0)
	{
		npfd[1] = open("/home/maxim/linux-2.6/test/fifopipe", O_WRONLY);
			for (i = 0; i < 3; i++)
		write(npfd[1], "Write to pipe\n", sizeof("Write to pipe\n"));
		while(!was_state_restored());
	}
	else
	{
		npfd[0] = open("/home/maxim/linux-2.6/test/fifopipe", O_RDONLY);
		read(npfd[0], buf, 15);
        	while(!was_state_restored());
		fd = open("/home/maxim/linux-2.6/test/output.txt", 2, 777);
		read(npfd[0], buf, 30);
		write(fd, buf, 30);
		close(fd);
	}

	exit(100);
}
