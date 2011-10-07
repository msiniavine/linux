#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "test.h"

int main()
{
	int err;
	FILE* f = tmpfile();
	if(!f)
	{
		perror("tmpfile");
		exit(1);
	}

	while(!was_state_restored()) sleep(1);

	err = fprintf(f, "hello world\n");
	if(err < 0)
	{
		perror("fprintf");
		exit(1);
	}
	fclose(f);

	if(err != 12) return 1;

	return 0;
}
