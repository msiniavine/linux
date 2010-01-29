#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <asm/ptrace.h>         /* For ORIG_EAX, etc. */
#include <sys/syscall.h>        /* For SYS_write etc */
#include <stdio.h>
#include <string.h>

const int long_size = sizeof(long);

void
getdata(pid_t child, long addr, char *str, int len)
{
        char *laddr;
        int i, j;
        union u {
                long val;
                char chars[long_size];
        } data;
        i = 0;
        j = len / long_size;
        laddr = str;
        while (i < j) {
                data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
                memcpy(laddr, data.chars, long_size);
                ++i;
                laddr += long_size;
        }
        j = len % long_size;
        if (j != 0) {
                data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
                memcpy(laddr, data.chars, j);
        }
        str[len] = '\0';
}

void
putdata(pid_t child, long addr, char *str, int len)
{
        char *laddr;
        int i, j;
        union u {
                long val;
                char chars[long_size];
        } data;
        i = 0;
        j = len / long_size;
        laddr = str;
        while (i < j) {
                memcpy(data.chars, laddr, long_size);
                ptrace(PTRACE_POKEDATA, child, addr + i * 4, data.val);
                ++i;
                laddr += long_size;
        }
        j = len % long_size;
        if (j != 0) {
                memcpy(data.chars, laddr, j);
                ptrace(PTRACE_POKEDATA, child, addr + i * 4, data.val);
        }
}

void
monitor_child(pid_t child)
{
        int status;
        long orig_eax;
        int insyscall = 1;
#if 0
	long eax;
        long params[3];
        char str[1000];
#endif

        while (1) {
                wait(&status);
                if (WIFEXITED(status))
		{
			printf("Exited with status: %d\n", status);
                        break;
		}
		printf("Wait status: %d, WIFEXITED: %d, WIFSIGNALED: %d, WIFSTOPPED: %d\n", 
		       status, WIFEXITED(status), WIFSIGNALED(status), WIFSTOPPED(status));
                orig_eax = ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, NULL);
		if (insyscall == 0) { /* Syscall entry */
			insyscall = 1;
			printf("Going into syscall 0x%lx\n", orig_eax);
		} else {
			insyscall = 0;
			printf("Returning from syscall 0x%lx\n", orig_eax);
		}
#if 0
                if (orig_eax == SYS_write) {
                        if (insyscall == 0) { /* Syscall entry */
                                insyscall = 1;
                                params[0] = ptrace(PTRACE_PEEKUSER, child,
                                                   4 * EBX, NULL);
                                params[1] = ptrace(PTRACE_PEEKUSER, child,
                                                   4 * ECX, NULL);
                                params[2] = ptrace(PTRACE_PEEKUSER, child,
                                                   4 * EDX, NULL);
                                printf("Write called with %ld, 0x%x, %ld\n",
                                       params[0], (unsigned int)params[1],
                                       params[2]);
                                getdata(child, params[1], str, params[2]);
                                printf("Write buf:\n%s", str);
                        } else {        /* Syscall exit */
                                eax = ptrace(PTRACE_PEEKUSER, child, 4 * EAX,
                                             NULL);
                                printf("Write returned with %ld\n", eax);
                                insyscall = 0;
                        }
                }
#endif
                ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        }
}

int set_state();

int
main()
{
        pid_t child;

        child = fork();
        if (child == 0) {
                ptrace(PTRACE_TRACEME, 0, NULL, NULL);
// 		execl("/bin/ls", "ls", NULL);
		set_state();
        } else {
                // parent
                monitor_child(child);
        }
        return 0;
}
