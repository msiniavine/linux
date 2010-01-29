int gs = 0;
int main()
{
	__asm__("movl %gs:0x10, %eax \n"
		"movl %eax, gs \n");
	return 0;
}


