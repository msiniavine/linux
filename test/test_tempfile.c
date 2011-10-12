#include <stdio.h>
#include <unistd.h>

#include "test.h"

int main()
{
	FILE* f = tmpfile();
	int err;
	if(!f)
	{
		perror("tmpfile");
		return 1;
	}

	fprintf(f, "Test message\n");

	while(!was_state_restored())
		sleep(1);

	err = fprintf(f, "hello wordl\n");
	if(err < 0)
	{
		perror("fprintf\n");
		return 1;
	}

	return 0;
}
