.text

.globl socketcall
socketcall:
	pushl %ebp
	movl  %esp, %ebp
	pushl %ebx
	pushl %ecx
	movl $102, %eax
	movl 8(%ebp), %ebx
	movl 12(%ebp), %ecx
	int $0x80
	popl %ecx
	popl %ebx
	popl %ebp
	ret
	
.globl write
write:
	pushl %ebp
	movl  %esp, %ebp
	pushl %ebx
	pushl %ecx
	pushl %edx
	movl  $4, %eax
	movl  8(%ebp), %ebx
	movl  12(%ebp), %ecx
	movl  16(%ebp), %edx
	int   $0x80
	popl  %edx
	popl  %ecx
	popl  %ebx
	popl  %ebp
	ret

.globl read
read:
	pushl %ebp
	movl  %esp, %ebp
	pushl %ebx
	pushl %ecx
	pushl %edx
	movl  $3, %eax
	movl  8(%ebp), %ebx
	movl  12(%ebp), %ecx
	movl  16(%ebp), %edx
	int   $0x80
	popl  %edx
	popl  %ecx
	popl  %ebx
	popl  %ebp
	ret

.globl open
open:
	pushl %ebp
	movl  %esp, %ebp
	pushl %ebx
	pushl %ecx
	pushl %edx
	movl  $5, %eax
	movl  8(%ebp), %ebx
	movl  12(%ebp), %ecx
	movl  16(%ebp), %edx
	int   $0x80
	popl  %edx
	popl  %ecx
	popl  %ebx
	popl  %ebp
	ret

.globl close
close:
	pushl %ebp
	movl  %esp, %ebp
	pushl %ebx
	movl  $6, %eax
	movl  8(%ebp), %ebx
	int   $0x80
	popl  %ebx
	popl  %ebp
	ret

.globl pipe
pipe:
	pushl %ebp
	movl  %esp, %ebp
	pushl %ebx
	movl  $42, %eax
	movl  8(%ebp), %ebx
	int   $0x80
	popl  %ebx
	popl  %ebp
	ret

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

.globl enable_save_state_pid
enable_save_state_pid:
	pushl %ebp
	movl  %esp, %ebp
	push %ebx
	movl $334, %eax
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


	
