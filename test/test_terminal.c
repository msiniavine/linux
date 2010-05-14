#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "test.h"

void print_all(const char* text)
{
	int length = strlen(text);
	int read = 0;
	while(read != length)
	{
		int ret = write(0, &text[read], length-read);
		if(ret == -1) // error writing
		{
			exit(1);
		}
		read += ret;
	}
}

int main()
{
	enable_save_state();
	print_all("\x1b[2J"); // clear screen
	print_all("\x1b[20;20H"); // move cursor
	print_all("test\n");

	while(!was_state_restored())
	{
		sleep(10);
	}

	print_all("Everything is working\n");
	return 0;
}
