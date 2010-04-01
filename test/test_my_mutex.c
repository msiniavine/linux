#include <stdio.h>
#include <pthread.h>
#include "test.h"
#include "my_mutex.h"

struct my_mutex m;

void* thread_func(void* arg)
{
	printf("Thread starting\n");
	sleep(10);
	printf("Releasing mutex\n");
	up_mutex(&m);
	return NULL;
}

int main()
{
	pthread_attr_t attr;
	pthread_t thread;

	init_my_mutex(&m);
	
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	pthread_create(&thread, &attr, thread_func, NULL);

	down_mutex(&m);
	down_mutex(&m);
	printf("Acquired mutex again\n");
	pthread_join(thread, NULL);
	return 0;
}
