#define NO_LIBC
#include "test.h"


// Test unnamed pipes
int mystrcmp(const char* p1, const char* p2, int numchars)
{
	int dist = 0;
	int i = 0;

//    while (!dist && *p1 && *p2)
	while (!dist && i < numchars)
	{
		dist = (*p2++) - (*p1++);
		i++;
	}

	if (dist > 0)
		return (-1);
	else if (dist < 0)
		return (1);

	return (0);
} 


// Double process code
int _start()
{
	int pfd[2], err, i = 0, fd;
	char buf[30];

	enable_save_state();
	write(STDOUT_FILENO, "Program Starting!\n", sizeof("Program Starting!\n"));

	if (pipe(pfd) == -1)
	{
		write(STDOUT_FILENO, "Error creating pipe!\n", sizeof("Error creating pipe!\n"));
		return 1;
	}

	err = fork();

	if (err < 0)
	{
		write(STDOUT_FILENO, "Error forking!\n", sizeof("Error forking!\n"));
		exit(1);
	}

	if (err == 0)
	{
		// Child process
		while (i < 2)
		{
			write(pfd[1], "Write to pipe\n", sizeof("Write to pipe\n"));
			i++;
		}
		while (!was_state_restored());
		exit(0);
	}
	else
	{
		// Parent process
		while (!was_state_restored());
		fd = open("/home/maxim/linux-2.6/test/output.txt", 2, 777);
		read(pfd[0], buf, 30);
		write(fd, buf, 30);
		close(fd);
		//while(1);

		if (mystrcmp(buf,"Write to pipe\n\0Write to pipe\n\0",30) == 0){
			write(pfd[1], "Quit went all good!\n", sizeof("Quit went all good!\n"));
			exit(100);
		}
		else {
			write(pfd[1], "Quit went bad!\n", sizeof("Quit went bad!\n"));
			exit(200);
		}
	}
}


/*
// Single process code
int _start()
{
	int pfd[2], err, i = 0, fd;
	char buf[30];

	enable_save_state();
	write(STDOUT_FILENO, "Program Starting!\n", sizeof("Program Starting!\n"));

	if (pipe(pfd) == -1)
	{
		write(STDOUT_FILENO, "Error creating pipe!\n", sizeof("Error creating pipe!\n"));
		return 1;
	}

	while (i < 2)
	{
		write(pfd[1], "Write to pipe\n", sizeof("Write to pipe\n"));
		i++;
	}

	while(!was_state_restored());
	fd = open("/home/colin/linux-2.6/test/output.txt", 2, 777);
	read(pfd[0], buf, 30);
	write(STDOUT_FILENO, buf, 30);
	write(fd, buf, 30);
	close(fd);
	write(STDOUT_FILENO, "Program Done!\n", sizeof("Program Done!\n"));

	if (mystrcmp(buf,"Write to pipe\n\0Write to pipe\n\0",30) == 0){
		write(pfd[1], "Quit went all good!\n", sizeof("Quit went all good!\n"));
		exit(100);
	}
	else {
		write(pfd[1], "Quit went bad!\n", sizeof("Quit went bad!\n"));
		exit(200);
	}
}*/

