#include "test.h"

char aux_copy[1024];
void* aux_location = NULL;

void _start()
{
	__asm__("movl %esp, aux_location");
	memory_copy(aux_copy, aux_location, 1024);
	enable_save_state();
	while(1);
	exit(0);
}
