#include <sys/syscall.h>
#include <unistd.h>

#define __NR_set_state 333
#define __NR_enable_save_state 334
#define __NR_was_state_restored 335
#define __NR_save_state 336

int test_syscall();
#if defined NO_LIBC
void enable_save_state()
{
	__asm__("movl $334, %eax\n");
	__asm__("int $0x80\n");
}

int was_state_restored();
void exit(int);
int fork();
int get_pid();
#else
void set_state(void)
{
	syscall(__NR_set_state);
}

void enable_save_state(void)
{
	syscall(__NR_enable_save_state);
}

int was_state_restored(void)
{
	return syscall(__NR_was_state_restored);
}

void save_state(void)
{
	syscall(__NR_save_state);
}
#endif
