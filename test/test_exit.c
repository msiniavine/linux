#include "test.h"

int main()
{
	enable_save_state();
	while(!was_state_restored());
	return 1;
}
