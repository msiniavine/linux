#ifndef TEST_H
#define TEST_H

#define __NR_set_state 333
#define __NR_enable_save_state 334
#define __NR_was_state_restored 335
#define __NR_save_state 336
#define __NR_state_present 337

void enable_save_state_pid(int pid);
void enable_save_state(void);
int was_state_restored(void);
void test_syscall(void);
void save_state(void);
int state_present(void);
int my_socketcall(int call, unsigned long* args);

#ifdef NO_LIBC
// declare some basic things
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

int fork(void);
void exit(int code);
int write(int fd, const void* buf, unsigned long count);
int pipe(int pfd[2]);
int close(int fd);
int read(int fd, void* buf, unsigned long count);
int open(const char* filename, int flags, int mode);

void enable_save_state(void)
{
	enable_save_state_pid(0);
}
#endif

#endif
