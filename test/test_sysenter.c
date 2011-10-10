#include "test.h"


int pid = 0;
int restored = 0;


int _start()
{
	enable_save_state();
	while(!restored)
	{
		__asm__(
			        "movl $335, %eax    \n"
				"call sysenter_call    \n"  
				"movl %eax, restored    \n"
			);

	}
	
	__asm__(
		"movl $20, %eax \n"
		"call 0xffffe414 \n"  // calls vdso version of sysenter
		"movl %eax, pid \n"
		);

	exit(pid);
}
