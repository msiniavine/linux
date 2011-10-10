#include "test.h"


int make_demand_paging_call(int n); // generates some numbers

void _start()
{
	enable_save_state();

	while(!was_state_restored());

	exit(make_demand_paging_call(10)); // exit code should be 89
}
