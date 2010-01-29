#include <unistd.h>
#include <pthread.h>
#include "test.h"

void* thread_func(void* data)
{
	while(1);
	return NULL;
}


int main()
{
	pthread_t thread;
	int err;
	pid_t child;
	enable_save_state();
	child = fork();
	if(child == 0)
	{
		err = pthread_create(&thread, NULL, thread_func, NULL);
		if(err)
			return 1;
	}
	while(1);
	return 0;
	
}
