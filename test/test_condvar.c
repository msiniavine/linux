#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "test.h"

#define NUM_THREADS  3
#define TCOUNT 10
#define COUNT_LIMIT 12

int     count = 0;
int     thread_ids[3] = {0,1,2};
pthread_mutex_t count_mutex;
pthread_cond_t count_threshold_cv;


void *watch_count(void *t) 
{


//  printf("Starting watch_count(): thread %ld\n", my_id);

  /*
  Lock mutex and wait for signal.  Note that the pthread_cond_wait 
  routine will automatically and atomically unlock mutex while it waits. 
  Also, note that if COUNT_LIMIT is reached before this routine is run by
  the waiting thread, the loop will be skipped to prevent pthread_cond_wait
  from never returning. 
  */
  pthread_mutex_lock(&count_mutex);
    pthread_cond_wait(&count_threshold_cv, &count_mutex);
//    printf("watch_count(): thread %ld Condition signal received.\n", my_id);

//    printf("watch_count(): thread %ld count now = %d.\n", my_id, count);

  pthread_mutex_unlock(&count_mutex);
  pthread_exit(NULL);
}

int test_main (int argc, char *argv[])
{
  int i, rc;
  long t1=1, t2=2, t3=3;
  pthread_t thread;
  pthread_attr_t attr;

  /* Initialize mutex and condition variable objects */
  pthread_mutex_init(&count_mutex, NULL);
  pthread_cond_init (&count_threshold_cv, NULL);

  /* For portability, explicitly create threads in a joinable state */
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
  pthread_create(&thread, &attr, watch_count, (void *)t1);

  while(!was_state_restored()) sleep(10);
  pthread_mutex_lock(&count_mutex);
  pthread_cond_signal(&count_threshold_cv);
  pthread_mutex_unlock(&count_mutex);


  /* Wait for all threads to complete */
    pthread_join(thread, NULL);

//  printf ("Main(): Waited on %d  threads. Done.\n", NUM_THREADS);



  /* Clean up and exit */
  pthread_attr_destroy(&attr);
  pthread_mutex_destroy(&count_mutex);
  pthread_cond_destroy(&count_threshold_cv);
  pthread_exit(NULL);

  return was_state_restored() && count == 145;
}

int main(int argc, char* argv[])
{
	pid_t child;
	child = fork();
	if(child == 0)
	{
		return test_main(argc, argv);
	}
	else
	{
	        while(1) sleep(1);
	}
	return 0;
	
}


