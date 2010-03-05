.text


	
.globl was_state_restored
was_state_restored:	
	pushl %ebp
	movl  %esp, %ebp
	movl  $335, %eax	
	call 0xffffe414
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
.globl get_pid
get_pid:	
	pushl %ebp
	movl %esp, %ebp
	movl $20, %eax
	int $0x80
	pop %ebp
	ret

.globl kernel_syscall_copy
kernel_syscall_copy:
	push %ecx
	push %edx
	push %ebp
syscall_restart:	
	mov %esp, %ebp
	sysenter
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	jmp syscall_restart
	pop %ebp
	pop %edx
	pop %ecx
	ret


	