void _start()
{
  __asm__("movl $0x14d, %eax\n"
	  "int $0x80\n"
	  "movl $1, %eax\n"
	  "movl $0, %ebx\n"
	  "int $0x80\n");
}
