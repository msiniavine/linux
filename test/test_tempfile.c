#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "test.h"

int main()
{
	int err;
	char name[] = "/home/maxim/tmpXXXXXX";
	int fd = mkstemp(name);
	FILE* f = fdopen(fd, "w");
	unlink(name);
	fprintf(f, "temp print\n");
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
