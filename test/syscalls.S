.text
.globl was_state_restored
was_state_restored:	
	pushl %ebp
	movl  %esp, %ebp
	movl  $335, %eax
	int $0x80
	popl %ebp
	ret

.globl exit
exit:	
	pushl %ebp
	movl %esp, %ebp
	push %ebx
	movl $1, %eax
	movl 8(%ebp), %ebx
	int $0x80
	popl %ebx
	popl %ebp
	ret

.globl fork
fork:
	pushl %ebp
	movl %esp, %ebp
	movl $2, %eax
	int $0x80
	pop %ebp
	ret


	