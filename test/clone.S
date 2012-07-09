.data
message:	
.ascii "Test message\n"
	

.text

.globl	my_clone
my_clone:
	pushl %ebp
	movl  %esp, %ebp
	pushl %ebx
	pushl %ecx
	pushl %edx
	pushl %edi
	movl  $120, %eax
	movl  8(%ebp), %ebx
	movl  12(%ebp), %ecx
	movl  16(%ebp), %edx
	movl  20(%ebp), %edi
	int   $0x80
	
	cmpl $0, %eax
	jne done
	
	mov $4, %eax
	mov $1, %ebx
	mov $message, %ecx
	mov $13, %edx
	int $0x80
done:	
	popl  %edi
	popl  %edx
	popl  %ecx
	popl  %ebx
	popl  %ebp
	ret
