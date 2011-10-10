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
	err = pthread_create(&thread, NULL, thread_func, NULL);
	while(1);
	return 0;
}
