#ifndef MY_MUTEX_H
#define MY_MUTEX_H

#include <sys/time.h>

#define MY_FUTEX_WAIT 0
#define MY_FUTEX_WAKE 1

int my_futex(int* uaddr, int op, int val, const struct timespec* timeout, int* uaddr2, int val3)
{
	return syscall(240, uaddr, op, val, timeout, uaddr2, val3);
}

struct my_mutex
{
	int val;
};


void init_my_mutex(struct my_mutex* m)
{
	m->val = 1;
}

void up_mutex(struct my_mutex* m)
{
	int err;
	int newval = __sync_add_and_fetch(&m->val, 1);
	if(newval == 1) return;

	m->val = 1;
	err = my_futex(&m->val, MY_FUTEX_WAKE, 1, NULL, NULL, 0);
	if(!err) exit(err);
}

void down_mutex(struct my_mutex* m)
{
	int newval;
	int err;
	do
	{ 
		newval = __sync_sub_and_fetch(&m->val, 1);
		if(newval == 0) return;
		m->val = -1;
		
		err = my_futex(&m->val, MY_FUTEX_WAIT, newval, NULL, NULL, 0); 
		if(err)
		{
			exit(err);
		}
	} while(newval != 0);
}

#endif
