#include <unistd.h>

#include "test.h"

void enable_save_state_pid(int pid)
{
	syscall(__NR_enable_save_state, pid);
}

void enable_save_state(void)
{
	enable_save_state_pid(0);
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

int my_socketcall(int call, unsigned long* args)
{
	return syscall(102, call, args);
}
