#include <stdio.h>
#include <string.h>
#include "test.h"

int main()
{
	int err = save_state();
	if(err < 0)
	{
		fprintf(stderr, "%s\n", strerror(-err));
		return 1;
	}
	return 0;
}
