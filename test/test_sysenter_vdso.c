#include "test.h"

int restored = 0;
int _start() {
	enable_save_state();
	while(!restored)
	{
        __asm__(
                "movl $335, %eax    \n"
                "call 0xffffe414    \n" 
                "movl %eax, restored    \n"
                );
	}
        exit(0);
}


