#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/smp_lock.h>
#include <linux/swap.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/key.h>
#include <linux/personality.h>
#include <linux/binfmts.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/tsacct_kern.h>
#include <linux/cn_proc.h>
#include <linux/audit.h>
#include <linux/tracehook.h>
#include <linux/hash.h>
#include <linux/kthread.h>

#include <asm/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/tlb.h>

#include <linux/ramfs.h>
#include <linux/set_state.h>



static bool valid_arg_len(struct linux_binprm *bprm, long len)
{
	return len <= MAX_ARG_STRLEN;
}


static struct page *get_arg_page(struct linux_binprm *bprm, unsigned long pos,
		int write)
{
	struct page *page;
	int ret;

#ifdef CONFIG_STACK_GROWSUP
	if (write) {
		ret = expand_stack_downwards(bprm->vma, pos);
		if (ret < 0)
			return NULL;
	}
#endif
	ret = get_user_pages(current, bprm->mm, pos,
			1, write, 1, &page, NULL);
	if (ret <= 0)
		return NULL;

	if (write) {
		unsigned long size = bprm->vma->vm_end - bprm->vma->vm_start;
		struct rlimit *rlim;

		/*
		 * We've historically supported up to 32 pages (ARG_MAX)
		 * of argument strings even with small stacks
		 */
		if (size <= ARG_MAX)
			return page;

		/*
		 * Limit to 1/4-th the stack size for the argv+env strings.
		 * This ensures that:
		 *  - the remaining binfmt code will not run out of stack space,
		 *  - the program will have a reasonable amount of stack left
		 *    to work from.
		 */
		rlim = current->signal->rlim;
		if (size > rlim[RLIMIT_STACK].rlim_cur / 4) {
			put_page(page);
			return NULL;
		}
	}

	return page;
}


static void put_arg_page(struct page *page)
{
	put_page(page);
}


static void flush_arg_page(struct linux_binprm *bprm, unsigned long pos,
		struct page *page)
{
	flush_cache_page(bprm->vma, pos, page_to_pfn(page));
}



/*
 * 'copy_strings_user()' copies argument/environment strings from the old
 * processes's memory to the new process's stack.  The call to get_user_pages()
 * ensures the destination page is created and not swapped out.
 */
static int copy_strings_user(int argc, char __user * __user * argv,
			struct linux_binprm *bprm)
{
	struct page *kmapped_page = NULL;
	char *kaddr = NULL;
	unsigned long kpos = 0;
	int ret;

	while (argc-- > 0) {
		char __user *str;
		int len;
		unsigned long pos;

		if (get_user(str, argv+argc) ||
				!(len = strnlen_user(str, MAX_ARG_STRLEN))) {
			ret = -EFAULT;
			goto out;
		}

		if (!valid_arg_len(bprm, len)) {
			ret = -E2BIG;
			goto out;
		}

		/* We're going to work our way backwords. */
		pos = bprm->p;
		str += len;
		bprm->p -= len;

		while (len > 0) {
			int offset, bytes_to_copy;

			offset = pos % PAGE_SIZE;
			if (offset == 0)
				offset = PAGE_SIZE;

			bytes_to_copy = offset;
			if (bytes_to_copy > len)
				bytes_to_copy = len;

			offset -= bytes_to_copy;
			pos -= bytes_to_copy;
			str -= bytes_to_copy;
			len -= bytes_to_copy;

			if (!kmapped_page || kpos != (pos & PAGE_MASK)) {
				struct page *page;

				page = get_arg_page(bprm, pos, 1);
				if (!page) {
					ret = -E2BIG;
					goto out;
				}

				if (kmapped_page) {
					flush_kernel_dcache_page(kmapped_page);
					kunmap(kmapped_page);
					put_arg_page(kmapped_page);
				}
				kmapped_page = page;
				kaddr = kmap(kmapped_page);
				kpos = pos & PAGE_MASK;
				flush_arg_page(bprm, kpos, kmapped_page);
			}
			if (copy_from_user(kaddr+offset, str, bytes_to_copy)) {
				ret = -EFAULT;
				goto out;
			}
		}
	}
	ret = 0;
out:
	if (kmapped_page) {
		flush_kernel_dcache_page(kmapped_page);
		kunmap(kmapped_page);
		put_arg_page(kmapped_page);
	}
	return ret;
}


/*
 * Like copy_strings, but get argv and its values from kernel memory.
 */
int copy_strings(int argc,char ** argv, struct linux_binprm *bprm)
{
	int r;
	mm_segment_t oldfs = get_fs();
	set_fs(KERNEL_DS);
	r = copy_strings_user(argc, (char __user * __user *)argv, bprm);
	set_fs(oldfs);
	return r;
}

static void print_mm(struct mm_struct* mm)
{
	//possible need to use page_table lock
	struct vm_area_struct* vma;
	for(vma = mm->mmap; vma != NULL; vma=vma->vm_next)
	{
		sprint( "vma: %08lx-%08lx\n", vma->vm_start, vma->vm_end);
	}
}

static void allocate_saved_pages(struct saved_task_struct* state)
{
	struct shared_resource* elem;
	list_for_each_entry(elem, &state->mm->pages->list, list)
	{
		struct saved_page* page = (struct saved_page*)elem->data;
		alloc_specific_page(page->pfn, page->mapcount);
	}

}

static int load_saved_binary(struct linux_binprm* bprm, struct saved_task_struct* state)
{
	int retval;
	retval = flush_old_exec(bprm);
	sprint( "Flushed the old executable\n");
	if(retval)
		return retval;
	arch_pick_mmap_layout(current->mm);
	sprint( "Set mmap layout\n");

	//not sure what these two lines do
	current->mm->free_area_cache = current->mm->mmap_base;
	current->mm->cached_hole_size = 0;

//	print_mm(current->mm);
	//retval = restore_stack_pages(bprm, state->stack);
	//if (retval < 0) {
//		send_sig(SIGKILL, current, 0);
		//	return retval;
		//}
	
		//TODO set bprm->p correctly
	current->mm->start_stack = bprm->p;

#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
	//used to be: retval = arch_setup_additional_pages(bprm, executable_stack);
	retval = arch_setup_additional_pages(bprm, 0);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		return retval;
	}
	sprint( "Setup additional pages\n");
#endif /* ARCH_HAS_SETUP_ADDITIONAL_PAGES */
	
	compute_creds(bprm);

	allocate_saved_pages(state);

	print_mm(current->mm);
	return 0;

}


static int create_stack(struct linux_binprm *bprm, struct saved_vm_area* stack)
{
	int err = -ENOMEM;
	struct vm_area_struct *vma = NULL;
	struct mm_struct *mm = bprm->mm;

	if(stack == NULL)
	{
		sprint("create_stack, stack is null\n");
		return err;
	}
	bprm->vma = vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
	if (!vma)
		goto err;

	sprint("Allocated vma for stack\n");
	down_write(&mm->mmap_sem);
	vma->vm_mm = mm;

	sprint("Stack is: %08lx-%08lx\n", stack->begin, stack->end);
	vma->vm_end = stack->end;
	vma->vm_start = stack->begin;

	vma->vm_flags = stack->vm_flags;
	vma->vm_page_prot = stack->protection_flags;
	err = insert_vm_struct(mm, vma);
	if (err) {
		up_write(&mm->mmap_sem);
		goto err;
	}

	mm->stack_vm = mm->total_vm = (vma->vm_end - vma->vm_start)/PAGE_SIZE;
	up_write(&mm->mmap_sem);

	bprm->p = vma->vm_end - sizeof(void *);

	return 0;

err:
	if (vma) {
		bprm->vma = NULL;
		kmem_cache_free(vm_area_cachep, vma);
	}

	return err;
}

struct used_file
{
	struct list_head list;
	char* filename;
	struct file* filep;
};

struct used_file* init_used_files()
{
	struct used_file* ret = (struct used_file*)kmalloc(sizeof(*ret), GFP_KERNEL);
	if(!ret)
	{
		panic("Could not allocate memory for a used file list");
	}
	INIT_LIST_HEAD(&ret->list);
	return ret;
}

struct file* find_file(struct used_file* head, char* filename)
{
	struct list_head* l;
	list_for_each(l, &head->list)
	{
		struct used_file* cur = list_entry(l, struct used_file, list);
		if(!strcmp(filename, cur->filename))
			return cur->filep;
	}
	return NULL;
}

struct file* add_file(struct used_file* head, char* filename)
{
	struct used_file* entry;
	struct file* filep;
	entry = (struct used_file*)kmalloc(sizeof(*entry), GFP_KERNEL);
	if(!entry) panic("Could not allocated a new file list entry");
	filep = open_exec(filename);
	if(IS_ERR(filep)) panic("Could not open file %s", filename);

	entry->filename = filename;
	entry->filep = filep;
	get_file(entry->filep);

	list_add(&entry->list, &head->list);
	return filep;
}

void free_files(struct used_file* head)
{
	struct list_head* cur, *n;
	list_for_each_safe(cur, n, &head->list)
	{
		struct used_file* entry = list_entry(cur, struct used_file, list);
		list_del(cur);
		fput(entry->filep);
		kfree(entry);
	}
}

struct vm_area_struct *
find_vma_prepare(struct mm_struct *mm, unsigned long addr,
		struct vm_area_struct **pprev, struct rb_node ***rb_link,
		 struct rb_node ** rb_parent);

void vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
			struct vm_area_struct *prev, struct rb_node **rb_link,
	      struct rb_node *rb_parent);


static int create_vmas(struct linux_binprm* bprm, struct saved_task_struct* state, struct used_file* files)
{
	int err;
	struct shared_resource* elem;
	struct vm_area_struct* vma, *prev;
	struct rb_node **rb_link, *parent;

	err = create_stack(bprm, state->stack);
	if(err)
		return err;
	sprint("Created stack\n");


	list_for_each_entry(elem, &state->memory->list, list)
	{ 
		struct saved_vm_area* saved_area = (struct saved_vm_area*)elem->data;
		sprint("Restoring area: %08lx-%08lx\n", saved_area->begin, saved_area->end);
		if(saved_area == state->stack) continue;
		down_write(&bprm->mm->mmap_sem);
		vma = find_vma_prepare(bprm->mm, saved_area->begin, &prev, &rb_link, &parent);
		if(!vma)
		{
			panic("find_vma_prepare failed");
		}
		sprint("Vma prepared: %p\n", vma);
		vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
		if(!vma)
			panic("Failed to allocate vma");
		sprint("Vma allocated: %p\n", vma);
		vma->vm_mm = bprm->mm;
		vma->vm_start = saved_area->begin;
		vma->vm_end =   saved_area->end;
		vma->vm_flags = saved_area->vm_flags;
		vma->vm_page_prot = saved_area->protection_flags;
		vma->vm_pgoff = saved_area->vm_pgoff;
		if(saved_area->filename)
		{
			struct file* filep;
			sprint("filename: %s\n", saved_area->filename);
			filep = find_file(files, saved_area->filename);
			if(!filep)
			{
				filep = add_file(files, saved_area->filename);
			}
 			vma->vm_file = filep;
			vma->vm_ops = &generic_file_vm_ops;
			get_file(vma->vm_file);
		}
		sprint("Linking vma\n");
		vma_link(bprm->mm,vma, prev, rb_link, parent);
		sprint("Vma linked\n");
		bprm->mm->total_vm = (vma->vm_end - vma->vm_start)/PAGE_SIZE;
		up_write(&bprm->mm->mmap_sem);
	}

	return 0;
}


static int bprm_mm_create(struct linux_binprm *bprm, struct saved_task_struct* state, struct used_file* files,
	struct map_entry* head)
{
	int err;
	struct mm_struct *mm = NULL;
	struct mm_struct* old_mm = NULL;
	old_mm = (struct mm_struct*)find_by_first(head, state->mm);
	if(old_mm)
	{
		atomic_inc(&old_mm->mm_users);
		bprm->mm = old_mm;
		sprint("Using existing mm\n");
		return 0;
		
	}
	else
	{
		sprint( "Allocating mm\n");
		bprm->mm = mm = mm_alloc();
		insert_entry(head, state->mm, mm);
	}
	err = -ENOMEM;
	if (!mm)
		goto err;
	mm->nr_ptes = state->mm->nr_ptes;
	sprint( "Setting nr_ptes to: %lu\n", mm->nr_ptes);
	sprint("mm->pgd: %p, state->pgd: %p\n", mm->pgd, state->mm->pgd);
	clone_pgd_range(mm->pgd, state->mm->pgd, SAVED_PGD_SIZE);

	mm->start_brk = state->mm->start_brk;
	mm->brk = state->mm->brk;

	err = init_new_context(current, mm);
	if (err)
		goto err;
	sprint("Created new context\n");
	err = create_vmas(bprm, state, files);
	if (err)
		goto err;
	sprint("Created vmas\n");
	return 0;

err:
	if (mm) {
		bprm->mm = NULL;
		mmdrop(mm);
	}

	return err;
}

void restore_file(unsigned int original_fd, char* filename)
{
	unsigned int fd;
	struct file* file;
	fd = alloc_fd(original_fd, 0); // need real flags
	if(fd != original_fd)
	{
		sprint("Could not get original fd %u, got %u\n", original_fd, fd);
		panic("Could not get original fd");
	}
	file = do_filp_open(-100, filename, 0, -1074763960); //need real flags, yes thats an accurate number
	if(IS_ERR(file))
	{
		sprint("Could not open %s error: %ld\n", filename, PTR_ERR(file));
		panic("Could not restore file");
	}
	fd_install(fd, file);
}

void restore_files(struct saved_task_struct* state)
{
	struct saved_file* f;
	for(f=state->open_files; f!=NULL; f=f->next)
	{
		sprint("Restoring fd: %u - %s\n", f->fd, f->name);
		restore_file(f->fd, f->name);
	}
}

int orig_gs, cur_gs;

void check_unsafe_exec(struct linux_binprm *);

extern int pid_max;
#define BITS_PER_PAGE		(PAGE_SIZE*8)
#define BITS_PER_PAGE_MASK	(BITS_PER_PAGE-1)
extern spinlock_t pidmap_lock;
#define find_next_offset(map, off) find_next_zero_bit((map)->page, \
						      BITS_PER_PAGE, off)
int mk_pid(struct pid_namespace *pid_ns, struct pidmap *map, int off);
#define RESERVED_PIDS		300
extern struct hlist_head *pid_hash;

static int alloc_pidmap_for_orig_pid(pid_t original_pid, struct pid_namespace *pid_ns)
{
	int i, offset, max_scan, pid, last = pid_ns->last_pid;
	struct pidmap *map;

	pid = original_pid;
	if (pid >= pid_max)
	{
		panic("Original pid: %d greater than pid_max: %d\n", pid, pid_max);
//		pid = RESERVED_PIDS;
		
	}
	offset = pid & BITS_PER_PAGE_MASK;
	map = &pid_ns->pidmap[pid/BITS_PER_PAGE];
	max_scan = (pid_max + BITS_PER_PAGE - 1)/BITS_PER_PAGE - !offset;
	for (i = 0; i <= max_scan; ++i) {
		if (unlikely(!map->page)) {
			void *page = kzalloc(PAGE_SIZE, GFP_KERNEL);
			sprint("Allocating new pid map\n");
			/*
			 * Free the page if someone raced with us
			 * installing it:
			 */
			spin_lock_irq(&pidmap_lock);
			if (map->page)
				kfree(page);
			else
				map->page = page;
			spin_unlock_irq(&pidmap_lock);
			if (unlikely(!map->page))
				break;
		}
		if (likely(atomic_read(&map->nr_free))) {
			do {
				if (!test_and_set_bit(offset, map->page)) {
					atomic_dec(&map->nr_free);
					//pid_ns->last_pid = pid;
					sprint("Found original pid in the map\n");
					return pid;
				}
				sprint("Could not find original pid\n");
				sprint("Things will go wrong now\n");
				offset = find_next_offset(map, offset);
				pid = mk_pid(pid_ns, map, offset);
			/*
			 * find_next_offset() found a bit, the pid from it
			 * is in-bounds, and if we fell back to the last
			 * bitmap block and the final block was the same
			 * as the starting point, pid is before last_pid.
			 */
			} while (offset < BITS_PER_PAGE && pid < pid_max &&
					(i != max_scan || pid < last ||
					    !((last+1) & BITS_PER_PAGE_MASK)));
		}
		if (map < &pid_ns->pidmap[(pid_max-1)/BITS_PER_PAGE]) {
			++map;
			offset = 0;
		} else {
			map = &pid_ns->pidmap[0];
			offset = RESERVED_PIDS;
			if (unlikely(last == offset))
				break;
		}
		sprint("Could not find original pid\n");
		sprint("Things will go wrong now\n");
		pid = mk_pid(pid_ns, map, offset);
	}
	return -1;
}

extern int pidhash_shift;
#define pid_hashfn(nr, ns)	\
	hash_long((unsigned long)nr + (unsigned long)ns, pidhash_shift)
void free_pidmap(struct upid *upid);

static struct pid *alloc_orig_pid(pid_t original_pid, struct pid_namespace *ns)
{
	struct pid *pid;
	enum pid_type type;
	int i, nr;
	struct pid_namespace *tmp;
	struct upid *upid;

	sprint("Changing pid from %d to %d/n", task_pid_nr(current), original_pid);
	pid = kmem_cache_alloc(ns->pid_cachep, GFP_KERNEL);
	if (!pid)
		goto out;
	sprint("Allocated pid structure\n");

	sprint("pid_namespace has %d levels\n", ns->level);
	tmp = ns;
	for (i = ns->level; i >= 0; i--) {
		nr = alloc_pidmap_for_orig_pid(original_pid, tmp);
		if (nr < 0)
			goto out_free;

		pid->numbers[i].nr = nr;
		pid->numbers[i].ns = tmp;
		tmp = tmp->parent;
	}

	//get_pid_ns(ns);
	pid->level = ns->level;
	atomic_set(&pid->count, 1);
	for (type = 0; type < PIDTYPE_MAX; ++type)
		INIT_HLIST_HEAD(&pid->tasks[type]);

	spin_lock_irq(&pidmap_lock);
	for (i = ns->level; i >= 0; i--) {
		upid = &pid->numbers[i];
		hlist_add_head_rcu(&upid->pid_chain,
				&pid_hash[pid_hashfn(upid->nr, upid->ns)]);
	}
	spin_unlock_irq(&pidmap_lock);

out:
	return pid;

out_free:
	while (++i <= ns->level)
		free_pidmap(pid->numbers + i);

	kmem_cache_free(ns->pid_cachep, pid);
	pid = NULL;
	goto out;
}

void restore_signals(struct saved_task_struct* state)
{
	int i;
	struct sighand_struct* sighand = current->sighand;

	sprint("Restoring signals\n");
	spin_lock_irq(&sighand->siglock);
	for(i = 0; i<_NSIG; i++)
	{
		sighand->action[i] = state->sighand.action[i];
	}
	
	current->blocked = state->sighand.blocked;
	current->pending.signal = state->sighand.pending;

	current->signal->shared_pending.signal = state->sighand.shared_pending;
	spin_unlock_irq(&sighand->siglock);	

	// 179 is the system call number for the rt_sigsuspend
	if(state->registers.orig_ax == 179)
	{
		sprint("Process was inside sigsuspend\n");
		if(state->sighand.state == TASK_INTERRUPTIBLE)
		{
			sprint("Process was sleeping\n");
			current->state = TASK_INTERRUPTIBLE;
			schedule();
			set_restore_sigmask();
			state->registers.ax = -ERESTARTNOHAND;
		}
		else
		{

			sprint("System call needs to be restarted\n");
			sprint("Eax: %ld, orig_ax: %ld ip: %lx\n",
			       state->registers.ax, state->registers.orig_ax, state->registers.ip);
			state->registers.ax = state->registers.orig_ax;
			state->registers.ip -= 2;

		}


//		sprint("System call almost done\n");
//		set_restore_sigmask();
	}

}

void become_user_process(void)
{
	current->flags = current->flags & ~PF_KTHREAD;
}

void restore_creds(struct saved_task_struct* state)
{
	current->uid = state->uid;
	current->euid = state->euid;
	current->suid = state->suid;
	current->fsuid = state->fsuid;

	current->gid = state->gid;
	current->egid = state->egid;
	current->sgid = state->sgid;
	current->fsgid = state->fsgid;

	current->cap_effective = state->cap_effective;
	current->cap_inheritable = state->cap_inheritable;
	current->cap_permitted = state->cap_permitted;
	current->cap_bset = state->cap_bset;

}

void restore_registers(struct saved_task_struct* state)
{
	struct pt_regs* regs;

	sprint("Restoring registers\n");
	regs = task_pt_regs(current);
	*regs = state->registers;
		
}
struct state_info
{
	struct map_entry* head;
	struct saved_task_struct* state;
	struct task_struct* parent;
};

int do_set_state(struct state_info* state);

void asm_resume_saved_state(void* correct_stack);

void resume_saved_state(void)
{
	sprint("Current thread info: %p\n", current_thread_info());
	sprint("pt_regs: %p, stack: %p\n", task_pt_regs(current), task_stack_page(current));
	sprint("Switching to user space\n");
	asm_resume_saved_state(task_pt_regs(current));
}

int do_restore(void* data)
{
	struct state_info* info = (struct state_info*)data;


	do_set_state(info);
	sprint("state restored need to return to user space\n");
	return 0;
}

static void restore_children(struct saved_task_struct* state, struct map_entry* head)
{
	struct saved_task_struct* child;
	struct task_struct* thread;
	struct state_info* info;
	list_for_each_entry(child, &state->children, sibling)
	{
		sprint("Restoring child %d\n", child->pid);
		info = (struct state_info*)kmalloc(sizeof(*info), GFP_KERNEL);
		info->head = head;
		info->state = child;
		info->parent = current;

		thread = kthread_create(do_restore, info, "child_restore");
		if(IS_ERR(thread))
		{
			panic("Failed to create a thread\n");
		}
		wake_up_process(thread);
	}
}


int set_state(struct pt_regs* regs, struct saved_task_struct* state)
{
	struct task_struct* thread;
	struct state_info* info;
	sprint("Restoring pid parent: %d\n", state->pid);
	info = (struct state_info*)kmalloc(sizeof(*info), GFP_KERNEL);
	info->head = new_map();
	info->state = state;
	info->parent = NULL;
	thread = kthread_create(do_restore, info, "test_thread");
	if(IS_ERR(thread))
	{
		sprint("Failed to create a thread\n");
		return 0;
	}

 	wake_up_process(thread);  
	

	return 0;
}


int do_set_state(struct state_info* info)
{
	struct linux_binprm* bprm;
	struct files_struct* displaced;
	int retval;
	struct file* file;
	struct used_file* used_files;
	struct saved_task_struct* state = info->state;

	sprint("Ptrace flags: %x, thread_info flags: %lx\n", current->ptrace, task_thread_info(current)->flags);
	retval = unshare_files(&displaced); // this seems to copy the open files of the current task (displaced is released later)
	if(retval)
		goto out_ret;
	sprint( "Unsared files\n");

	retval = -ENOMEM;
	bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
	if(!bprm)
		goto out_files;
	sprint( "Allocated bprm\n");


	retval = -ENOMEM;


	file = open_exec(state->exe_file);
	retval = PTR_ERR(file);
	if (IS_ERR(file))
	  goto out_kfree;

	bprm->file = file;
	bprm->filename = state->exe_file;
	bprm->interp = state->exe_file;
	used_files = init_used_files();
	used_files->filename = state->exe_file;
	used_files->filep = file;
	get_file(file);
	sprint( "Opened executable file\n");

	retval = bprm_mm_create(bprm, state, used_files, info->head);
	if(retval)
		goto out_file;
	sprint( "Allocated new mm_struct\n");
	print_mm(bprm->mm);

	sprint( "Allocated security\n");

	//here original exec was changing the value of bprm->p which has something to do with the stack
	//but i am skipping that for now, since I dont know what it does

	retval = prepare_binprm(bprm);
	if(retval < 0)
		goto out;
	sprint( "bprm prepared\n");

	//here execve used to call load_elf_binary
	retval = load_saved_binary(bprm, state);
	if(retval >= 0)
	{
		int cpu;
		struct pid* pid;
		struct pid* current_pid;

		become_user_process();

		current_pid = task_pid(current);
		sprint("Current pid count:%d\n", atomic_read(&current_pid->count));
		
		cpu = get_cpu();
		current->thread.gs = 0x33;
		memcpy(current->thread.tls_array, state->tls_array, GDT_ENTRY_TLS_ENTRIES*sizeof(struct desc_struct));
		load_TLS(&current->thread, cpu);
		put_cpu();
	       
	
		pid = alloc_orig_pid(state->pid, current->nsproxy->pid_ns);
		change_pid(current, PIDTYPE_PID, pid);
		current->pid = pid_nr(pid);
		current->tgid = current->pid;


		tracehook_report_exec(NULL, bprm, &state->registers);

		acct_update_integrals(current);
		free_files(used_files);
		free_bprm(bprm);
		if (displaced)
			put_files_struct(displaced);

		
		restore_files(state);
		sprint("Ptrace flags: %x, thread_info flags: %lx\n", current->ptrace, task_thread_info(current)->flags);
		restore_signals(state);
		restore_creds(state);

		restore_registers(state);

		add_to_restored_list(current);

		restore_children(state, info->head);

		if(info->parent)
		{
			current->real_parent = info->parent;
		}

		sprint("Current %d, parent %d %s\n", current->pid, current->real_parent->pid, current->real_parent->comm);

		kfree(info);
		resume_saved_state();
		return 0;
	}

out:
	if(bprm->mm)
		mmput(bprm->mm);

out_file:
	if (bprm->file) {
		allow_write_access(bprm->file);
		fput(bprm->file);
	}

out_kfree:
	kfree(bprm);  //used to be free_bprm(bprm)
out_files:
	if(displaced)
		reset_files_struct(displaced);
out_ret:
	return retval;
}


