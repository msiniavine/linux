#include "test.h"
#include "my_mutex.h"

int main()
{
	struct my_mutex m;
	init_my_mutex(&m);
	down_mutex(&m);
	down_mutex(&m);
	return 0;
}
