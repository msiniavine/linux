#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include "test.h"
#include "my_mutex.h"

struct my_mutex m;

void* thread_func(void* arg)
{
	while(!was_state_restored())
	{
		sleep(1);
	}
//	printf("Thread starting\n");
	sleep(10);
//	printf("Releasing mutex\n");
	up_mutex(&m);
	return NULL;
}

int main()
{
	pthread_attr_t attr;
	pthread_t thread;
	pid_t child;
	enable_save_state();
	child = fork();
	if(child == 0)
	{
		init_my_mutex(&m);
		
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
		pthread_create(&thread, &attr, thread_func, NULL);
		
		down_mutex(&m);
		down_mutex(&m);
//	printf("Acquired mutex again\n");
		pthread_join(thread, NULL);
		if(was_state_restored())
		{
			return 0;
		}
		else
		{
			return 1;
		}
	}
	else
	{
		while(1) sleep(1);
	}
}
