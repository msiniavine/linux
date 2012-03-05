#include <linux/sched.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

#define SET_STATE_ONLY_FUNCTIONS 1
#include <linux/set_state.h>

static struct saved_state* get_saved_state(void)
{
	return (struct saved_state*)get_reserved_region();
}

static struct timespec start_quiesence, end_quiesence, start_checkpoint, start_kernel, end_kernel, start_restore, end_restore;

void time_start_quiesence()
{
	getnstimeofday(&start_quiesence);
}

void time_end_quiesence()
{
	getnstimeofday(&end_quiesence);
}
void time_start_checkpoint()
{
	getnstimeofday(&start_checkpoint);
}
void time_end_checkpoint()
{
	struct saved_state* s = get_saved_state();
	s->start_quiesence = start_quiesence;
	s->end_quiesence = end_quiesence;
	s->start_checkpoint = start_checkpoint;
	getnstimeofday(&get_saved_state()->end_checkpoint);
}

void time_start_kernel_init(void)
{
	getnstimeofday(&start_kernel);
}
void time_end_kernel_init(void)
{
	getnstimeofday(&end_kernel);
}
void time_start_restore(void)
{
	getnstimeofday(&start_restore);
}
void time_end_restore(void)
{
	getnstimeofday(&end_restore);
}

static int timings_read(char* page, char** start, off_t offeset, int count, int* eof, void* data)
{
	int len = 0;
	struct saved_state* s = get_saved_state();
	len += sprintf(page+len, "Size: %lu\n", s->checkpoint_size);
	len += sprintf(page+len, "Squiesence: %ld %ld\n", s->start_quiesence.tv_sec, s->start_quiesence.tv_nsec);
	len += sprintf(page+len, "Equiesence: %ld %ld\n", s->end_quiesence.tv_sec, s->end_quiesence.tv_nsec);
	len += sprintf(page+len, "SCehckpoint: %ld %ld\n", s->start_checkpoint.tv_sec, s->start_checkpoint.tv_nsec);
	len += sprintf(page+len, "ECheckpoint: %ld %ld\n", s->end_checkpoint.tv_sec, s->end_checkpoint.tv_nsec);
	len += sprintf(page+len, "Skernel:  %ld %ld\n", start_kernel.tv_sec, start_kernel.tv_nsec);
	len += sprintf(page+len, "EKernel: %ld %ld\n", end_kernel.tv_sec, end_kernel.tv_nsec);
	len += sprintf(page+len, "SRestore: %ld %ld\n", start_restore.tv_sec, start_restore.tv_nsec);
	len += sprintf(page+len, "ERestore: %ld %ld\n", end_restore.tv_sec, end_restore.tv_nsec);
	*eof=1;
	return len;
}

static int timings_init(void)
{
	struct proc_dir_entry* dentry;

	printk(KERN_EMERG "TIMINGS: module started\n");

	dentry = create_proc_read_entry("timings", 0, NULL, timings_read, NULL);
	if(!dentry)
		printk(KERN_EMERG "Failed to create /proc entry\n");

	return 0;
}

static void timings_exit(void)
{
	remove_proc_entry("timings", NULL);
	printk("TIMINGS: module exited\n");
}

module_init(timings_init);
module_exit(timings_exit);
