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


int main()
{
	int err;
	int count = 1;
	int forked_again = 0;
	pthread_t thread;
	int childtid;
	err = my_clone(CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, 0, 0, &childtid);
	printf("It works\n");
	if(!err)
	{
		exit(0);
	}
	wait(NULL);
//	execl("/bin/ls", "/bin/ls", "/home/maxim", NULL);
//	exit(0);
	enable_save_state();

	while(1)
	{
		sleep(1);
		printf("%d pid %d\n", count, getpid());
		count++;
		if(was_state_restored() && !forked_again)
		{
			forked_again = 1;
			int childtid;
			int ret;
			/* if((err = pthread_create(&thread, NULL, thread_func, NULL)) != 0) */
			/* { */
			/* 	printf("Pthread error %d\n", err); */
			/* } */
//			fork();

			// syscall(120, CLONE_SIGSTOP|CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, 0, 0, &childtid);
			// clone(0, CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xb7efb6f8)
			// syscall(120, CLONE_STOPPED|CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, 0, 0, &childtid);
//			ret = syscall(120, CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, 0, 0, &childtid);
			ret = my_clone(CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, 0, 0, &childtid);
			if (ret == 0)
				while(1); 


		}
	}
	return 0;
}

