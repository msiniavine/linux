	.globl test_syscall
test_syscall:		
	pushl %ebp
	movl  %esp, %ebp
	movl  $335, %eax	
	call  *%gs:0x10
	popl %ebp
	ret