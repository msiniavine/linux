#include <sys/syscall.h>
#include <unistd.h>

#define __NR_set_state 333
#define __NR_enable_save_state 334
#define __NR_was_state_restored 335
#define __NR_save_state 336
#define __NR_state_present 337

int test_syscall();
#if defined NO_LIBC


void enable_save_state_pid(int pid);
int was_state_restored();
void exit(int);
int fork();
int get_pid();
#else
void set_state(void)
{
	syscall(__NR_set_state);
}

void enable_save_state_pid(pid_t pid)
{
	syscall(__NR_enable_save_state, pid);
}

int was_state_restored(void)
{
	return syscall(__NR_was_state_restored);
}

void save_state(void)
{
	syscall(__NR_save_state);
}

int state_present(void)
{
	return syscall(__NR_state_present);
}
#endif

void enable_save_state(void)
{
	enable_save_state_pid(0);
}

