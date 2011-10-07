#define USE_LIBC
#include "test.h"

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/sched.h>
#include <signal.h>

int my_clone(int, int, int, int, int*);

void* thread_func(void* args)
{
	printf("Thread is running\n");
	pthread_exit(NULL);
}

int recursive_call(int n)
{
	char bump[1024];
	if(n == 0) return 0;
	
	return recursive_call(n-1)+1;
}


int main()
{
	int forked_again = 0;

	while(1)
	{
		sleep(1);
		if(was_state_restored() && !forked_again)
		{
			forked_again = 1;
			int ret;

//			fork();

			// syscall(120, CLONE_SIGSTOP|CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, 0, 0, &childtid);
			// clone(0, CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xb7efb6f8)
			// syscall(120, CLONE_STOPPED|CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, 0, 0, &childtid);
//			ret = syscall(120, CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, 0, 0, &childtid);
//			ret = my_clone(CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, 0, 0, &childtid);
			ret = fork();
			if (ret == 0)
			{
				int r = recursive_call(100);
				if(r != 100)
				{
					printf("Recursive call in test_fork failed expected %d got %d\n", 100, r);
					return 1;
				}
//				execl("/bin/ls", "/bin/ls", "/home/maxim", NULL);
			}
			return 0;


		}
	}
	return 0;
}

