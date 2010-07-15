#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
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
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/pipe_fs_i.h>
#include <linux/tty.h>
#include <linux/kd.h>
#include <linux/console_struct.h>

#include <asm/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/tlb.h>

#include <linux/ramfs.h>
#include <linux/set_state.h>
#include <linux/string.h>



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
	for(elem=state->mm->pages;elem!=NULL;elem=elem->next)
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

static struct used_file* init_used_files(void)
{
	struct used_file* ret = (struct used_file*)kmalloc(sizeof(struct used_file), GFP_KERNEL);
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
	filep = do_filp_open(AT_FDCWD, filename, O_RDONLY|O_LARGEFILE, 0);
	if(IS_ERR(filep)) panic("Could not open file %s err: %ld", filename, PTR_ERR(filep));

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


	for(elem=state->memory; elem!=NULL; elem=elem->next)
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

// Finds the other pipe end from the global table
struct pipe_restore_temp* find_other_pipe_end(struct pipe_restore_temp* pipe_restore_head, struct inode* pipe_id)
{
	struct pipe_restore_temp* p;

	for (p = pipe_restore_head; p != NULL; p = p->next)
	{
		if (p->pipe_id == pipe_id)
			return p;
	}
	return NULL;
}

// Add pipe end to global table
void add_to_pipe_restore(struct pipe_restore_temp* pipe_restore_head, struct inode* pipe_id, pid_t process, unsigned int read_fd, unsigned int write_fd, struct file* read_file, struct file* write_file)
{
	struct pipe_restore_temp* p;

	for (p = pipe_restore_head; p != NULL; p = p->next)
	{
		if (p->next == NULL)
		{
			// Reached end of linked list. Allocate new struct and write to it
			p->next = (struct pipe_restore_temp*)kmalloc(sizeof(struct pipe_restore_temp), GFP_KERNEL);
			p = p->next;
			break;
		}
	}

	p->pipe_id = pipe_id;
	p->processlist = (struct pipe_pidlist*)kmalloc(sizeof(struct pipe_pidlist), GFP_KERNEL);
	p->processlist->next = NULL;
	p->processlist->process = process;
	p->read_fd = read_fd;
	p->write_fd = write_fd;
	p->read_file = read_file;
	p->write_file = write_file;
	p->next = NULL;
}

// Add new process to existing pipe in global table
void add_process_to_pipe_restore(struct pipe_restore_temp* pipe_restore_head, struct inode* pipe_id, pid_t process)
{
	struct pipe_restore_temp* p;
	struct pipe_pidlist* pidlist;

	// We're guaranteed not to have null pipe_restore_temp or pipe_pidlist because these are allocated in add_to_pipe_restore()
	for(p = pipe_restore_head; p != NULL; p = p->next)
	{
		if (p->pipe_id == pipe_id)
		{
			for (pidlist = p->processlist; pidlist != NULL; pidlist = pidlist->next)
			{
				if (pidlist->next == NULL)
				{
					pidlist->next = (struct pipe_pidlist*)kmalloc(sizeof(struct pipe_pidlist), GFP_KERNEL);
					pidlist = pidlist->next;
					pidlist->next = NULL;
					pidlist->process = process;
					break;
				}
			}
			break;
		}
	}
}

// Search pipe_restore_temp struct for a particular process
int search_pipe_for_process(struct pipe_restore_temp* pipe_restore, pid_t pid)
{
	struct pipe_pidlist* pid_pointer;
	int result = 0;

	for(pid_pointer = pipe_restore->processlist; pid_pointer != NULL; pid_pointer = pid_pointer->next)
	{
		if (pid_pointer->process == pid)
		{
			result = 1;
			break;
		}
	}

	return result;
}

// Add pipe end to global table for closing pipes
void add_to_pipe_close(struct pipes_to_close* pipe_close_head, pid_t process, unsigned int fd)
{
	struct pipes_to_close* p;

	for (p = pipe_close_head; p != NULL; p = p->next)
	{
		if (p->next == NULL)
		{
			p->next = (struct pipes_to_close*)kmalloc(sizeof(struct pipes_to_close), GFP_KERNEL);
			p = p->next;
			break;
		}
	}

	p->process = process;
	p->fd = fd;
	p->next = NULL;
}

// Reads existing data from pipe pages and writes to new pipe
void restore_pipe_data(struct saved_pipe* saved_pipe, unsigned int fd)
{
	// Read data from pages
	unsigned int numpages = saved_pipe->nrbufs;
	unsigned int curpage = saved_pipe->curbuf;
	char* tempbuf;

	sprint("Total number of pipe buffer pages to restore: %u\n", numpages);
	tempbuf = kmalloc(4096, GFP_KERNEL);
	while(numpages) {
		struct saved_pipe_buffer *saved_buf = saved_pipe->bufs + curpage;
		void *addr;
		size_t chars = saved_buf->len;
		mm_segment_t old_fs;
		struct file* file;
		loff_t temppos = 0;

		sprint("Reading from buffer page %u with %u bytes.\n", curpage, chars);

		// Read from saved buffer
		addr = kmap(saved_buf->page); // Non-atomic map
		memcpy(tempbuf, addr + saved_buf->offset, chars);
		kunmap(saved_buf->page); // Non-atomic unmap

		numpages--;
		curpage = (curpage + 1) & (PIPE_BUFFERS-1);

		// Write to new buffer
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		file = fget(fd);
		sprint("Writing to fd: %u\n", fd);
		if (file)
		{
			vfs_write(file, tempbuf, chars, &temppos);
			fput(file);
		}
		set_fs(old_fs);
		sprint("Wrote to fd: %u\n", fd);
	}
	kfree(tempbuf);
	sprint("Finished writing all pipe contents\n");
}

// Restore unnamed pipes
void restore_pipe(struct saved_file* f, struct global_state_info* global_state, struct saved_task_struct* state, unsigned int* max_fd)
{
	struct saved_file* sfile;
	struct saved_file* open_files = state->open_files;
	struct pipe_restore_temp* pipe_restore_head = global_state->pipe_restore_head;
	struct pipes_to_close* pipe_close_head = global_state->pipe_close_head;
	struct pipe_restore_temp* other_end = find_other_pipe_end(pipe_restore_head, f->pipe.inode);

	// If pipes have not been created yet, create a pair of pipes even if the process doesn't use both pipes.
	// Extraneous pipes will be closed later
	if (other_end == NULL)
	{
		int pipe_fd[2];
		if (do_pipe(pipe_fd) < 0)
		{
			sprint("Unable to restore pipe at fd: %u\n", f->fd);
			panic("Unable to restore pipe");
		}
		sprint("Created pipe pair with read end at fd %d and write end at fd %d.\n", pipe_fd[0], pipe_fd[1]);

		// Scan saved file struct and dup the read and write ends to corresponding fds
		// If the end does not exist, change the fd to max fd+1
		if (f->type == READ_PIPE_FILE)
		{
			int use_maxfd = 1;

			sprint("Restoring read pipe end\n");
			if (f->fd != pipe_fd[0])
			{
				if (sys_dup2(pipe_fd[0], f->fd) != f->fd)
				{
					sprint("Unable to change fd of read end from %d to %u\n", pipe_fd[0], f->fd);
					panic("Unable to change fd of read end");
				}
				sprint("Duped read pipe from %d to %u\n", pipe_fd[0], f->fd);
				sys_close(pipe_fd[0]);
				pipe_fd[0] = f->fd;
			}
			else
				sprint("Did not need to change fd of read end %d\n", pipe_fd[0]);

			// Scan the saved fd table for other pipe end
			for(sfile = open_files; sfile != NULL; sfile = sfile->next)
			{
				if ((sfile->type == WRITE_PIPE_FILE) && (sfile->pipe.inode = f->pipe.inode))
				{
					if (sfile->fd != pipe_fd[1])
					{
						if (sys_dup2(pipe_fd[1], sfile->fd) != sfile->fd)
						{
							sprint("Unable to change fd of read end from %d to %u\n", pipe_fd[1], sfile->fd);
							panic("Unable to change fd of read end");
						}
						use_maxfd = 0;
						sprint("Duped write pipe from %d to %u\n", pipe_fd[1], sfile->fd);
						sys_close(pipe_fd[1]);
						pipe_fd[1] = sfile->fd;
					}
					else
					{
						sprint("Did not need to change fd of write end %d\n", pipe_fd[1]);
					}
					break;
				}
			}

			if (use_maxfd)
			{
				*max_fd = *max_fd + 1;
				if (sys_dup2(pipe_fd[1], *max_fd) != *max_fd)
				{
					sprint("Unable to change fd of write end from %d to %u\n", pipe_fd[1], *max_fd);
					panic("Unable to change fd of write end");
				}
				add_to_pipe_close(pipe_close_head, state->pid, *max_fd);
			}
		}
		else if (f->type == WRITE_PIPE_FILE)
		{
			int use_maxfd = 1;

			sprint("Restoring write pipe end\n");
			if (f->fd != pipe_fd[1])
			{
				if (sys_dup2(pipe_fd[1], f->fd) != f->fd)
				{
					sprint("Unable to change fd of write end from %d to %u\n", pipe_fd[1], f->fd);
					panic("Unable to change fd of write end");
				}
				sprint("Duped write pipe from %d to %u\n", pipe_fd[1], f->fd);
				sys_close(pipe_fd[1]);
				pipe_fd[1] = f->fd;
			}
			else
				sprint("Did not need to change fd of write end %d\n", pipe_fd[1]);

			// Scan the saved fd table for other pipe end
			for(sfile = open_files; sfile != NULL; sfile = sfile->next)
			{
				if ((sfile->type == READ_PIPE_FILE) && (sfile->pipe.inode = f->pipe.inode))
				{
					if (pipe_fd[0] != sfile->fd)
					{
						if (sys_dup2(pipe_fd[0], sfile->fd) != sfile->fd)
						{
							sprint("Unable to change fd of read end from %d to %u\n", pipe_fd[0], sfile->fd);
							panic("Unable to change fd of read end");
						}
						use_maxfd = 0;
						sprint("Duped read pipe from %d to %u\n", pipe_fd[0], sfile->fd);
						sys_close(pipe_fd[0]);
						pipe_fd[0] = sfile->fd;
					}
					else
					{
						sprint("Did not need to change fd of read end %d\n", pipe_fd[0]);
					}
					break;
				}
			}

			if (use_maxfd)
			{
				*max_fd = *max_fd + 1;
				if (sys_dup2(pipe_fd[0], *max_fd) != *max_fd)
				{
					sprint("Unable to change fd of write end from %u to %u\n", pipe_fd[0], *max_fd);
					panic("Unable to change fd of write end");
				}
				add_to_pipe_close(pipe_close_head, state->pid, *max_fd);
			}
		}

		// Store pipe information into global table
		add_to_pipe_restore(pipe_restore_head, f->pipe.inode, state->pid, pipe_fd[0], pipe_fd[1], fcheck(pipe_fd[0]), fcheck(pipe_fd[1]));

		// Write to pipe
		restore_pipe_data(&(f->pipe), pipe_fd[1]);	
	}
	// If the pipes have already been created in this process, do nothing
	// If they were only created in other processes, copy the pipes to current process
	else if(search_pipe_for_process(other_end, state->pid) == 0)
	{
		int pipe_fd[2];

		pipe_fd[0] = pipe_fd[1] = 0;

		// Scan the saved fd table and restore open pipe ends
		for(sfile = open_files; sfile != NULL; sfile = sfile->next)
		{
			if ((sfile->type == READ_PIPE_FILE)  && (sfile->pipe.inode = f->pipe.inode))
			{
				if (alloc_fd(sfile->fd, 0) != sfile->fd)
				{
					sprint("Unable to allocate fd %u for pipe read end\n", sfile->fd);
					panic("Unable to allocate fd for pipe read end");
				}
				fd_install(sfile->fd, other_end->read_file);
				get_file(other_end->read_file);
				pipe_fd[0] = sfile->fd;
				sprint("Copied read pipe end to fd %d.\n", pipe_fd[0]);
			}

			if ((sfile->type == WRITE_PIPE_FILE)  && (sfile->pipe.inode = f->pipe.inode))
			{
				if (alloc_fd(sfile->fd, 0) != sfile->fd)
				{
					sprint("Unable to allocate fd %u for pipe write end\n", sfile->fd);
					panic("Unable to allocate fd for pipe write end");
				}
				fd_install(sfile->fd, other_end->write_file);
				get_file(other_end->write_file);
				pipe_fd[1] = sfile->fd;
				sprint("Copied write pipe end to fd %d.\n", pipe_fd[1]);
			}
		}
		
		// Add process to linked list of multiple processes holding the same pipes
		add_process_to_pipe_restore(pipe_restore_head, f->pipe.inode, state->pid);
	}
	else
	{
		sprint("This fd does not require any pipe restore.\n");
	}

	sprint("Pipe restore completed\n");
}

// Restore named pipes
void restore_fifo(struct saved_file* f, struct global_state_info* global_state, struct saved_task_struct* state, unsigned int* max_fd)
{
	int fd;
	struct pipe_restore_temp* pipe_restore_head = global_state->pipe_restore_head;

	if (f->type == WRITE_FIFO_FILE)
	{
		unsigned int temp_fd = 0;

		sprint("Restoring named pipe: write end\n");

		// Named pipes do not allow a write end to be created if no read end exists.
		// Create a fake read end if no read end is found.
		if (find_other_pipe_end(pipe_restore_head, f->pipe.inode) == NULL)
		{
			sprint("Creating false read end to allow write end to be created\n");
			fd = sys_open(f->name, O_RDONLY | O_NONBLOCK, 777);
			*max_fd = *max_fd + 1;
			if (sys_dup2(fd, *max_fd) != *max_fd)
			{
				sprint("Unable to change fd of false read end from %d to %u\n", fd, *max_fd);
				panic("Unable to change fd of false read end");
			}
			temp_fd = *max_fd;
		}

		fd = sys_open(f->name, O_WRONLY | O_NONBLOCK, 777);
	
		// If not already done, restore data and add pipe to global table
		if (find_other_pipe_end(pipe_restore_head, f->pipe.inode) == NULL)
		{
			restore_pipe_data(&(f->pipe), fd);
			add_to_pipe_restore(pipe_restore_head, f->pipe.inode, state->pid, 0, 0, NULL, NULL);
		}

		// Close fake read end if created
		if (temp_fd != 0)
			sys_close(temp_fd);
	}
	else
	{
		sprint("Restoring named pipe: read end\n");

		fd = sys_open(f->name, O_RDONLY | O_NONBLOCK, 777);
		
		// If pipe has not been written to yet, create a write end and write to it first
		if (find_other_pipe_end(pipe_restore_head, f->pipe.inode) == NULL)
		{
			int temp_fd;

			sprint("Creating false write end to fill pipe\n");
			temp_fd = sys_open(f->name, O_WRONLY | O_NONBLOCK, 777);
			*max_fd = *max_fd + 1;
			if (sys_dup2(temp_fd, *max_fd) != *max_fd)
			{
				sprint("Unable to change fd of false write end from %d to %u\n", fd, *max_fd);
				panic("Unable to change fd of false write end");
			}
			restore_pipe_data(&(f->pipe), *max_fd);
			sys_close(*max_fd);
		}

		add_to_pipe_restore(pipe_restore_head, f->pipe.inode, state->pid, 0, 0, NULL, NULL);
	}

	// Dup the fd to the right one
	if (fd != f->fd)
	{
		if (sys_dup2(fd, f->fd) != f->fd)
		{
			sprint("Could not dup fd of fifo from %d to %u\n", fd, f->fd);
			panic("Could not dup fd of fifo\n");
		}
		sys_close(fd);
	}
	sprint("Duped fd of fifo from %d to %u\n", fd, f->fd);
}


// Restore a regular file
void restore_file(struct saved_file* f);
void redraw_screen(struct vc_data*, int);

struct file* restore_vc_terminal(struct saved_file* f)
{
	struct file* file;
	struct tty_struct* tty;
	struct tty_driver* driver;
	struct vc_data* vcd;
	struct saved_vc_data* svcd = f->vcd;
	file = do_filp_open(-100, "/dev/tty1", f->flags, -1074763960);
	if(IS_ERR(file))
	{
		panic("Could not open terminal file with error: %ld\n", PTR_ERR(file));
	}

	tty = (struct tty_struct*)file->private_data;
	if(tty->magic != TTY_MAGIC)
	{
		panic("tty magic value does not match\n");
	}
	driver = tty->driver;
	if(driver->type != TTY_DRIVER_TYPE_CONSOLE || driver->subtype !=0)
	{
		panic("Driver type des not match\n");
	}
	vcd = (struct vc_data*)tty->driver_data;
	if(vcd->vc_screenbuf_size != svcd->screen_buffer_size)
	{
		panic("Screen buffer sizes do not match\n");
	}
	memcpy(vcd->vc_screenbuf, svcd->screen_buffer, svcd->screen_buffer_size); 
	vcd->vc_x = svcd->x;
	vcd->vc_y = svcd->y;
	redraw_screen(vcd, 0);
	return file;
}

void restore_file(struct saved_file* f)
{
	unsigned int fd;
	struct file* file;
	sprint("flags: %d\n", f->flags);
	fd = alloc_fd(f->fd, 0); // need real flags
	if(fd != f->fd)
	{
		sprint("Could not get original fd %u, got %u\n", f->fd, fd);
		panic("Could not get original fd");
	}
	switch (f->type)
	{
	        case VC_TTY:
			file = restore_vc_terminal(f);
			break;
		default:
			file = do_filp_open(-100, f->name, f->flags, -1074763960); 
			if(IS_ERR(file))
			{
				panic("Could not open file %s\n", f->name);
			}
			sprint("Restoring some normal file.\n");
			break;
	}

	atomic_long_set(&(file->f_count), f->count);
	sprint("Set file count value to %ld\n", f->count);

	if(IS_ERR(file))
	{
		sprint("Could not open %s error: %ld\n", f->name, PTR_ERR(file));
		panic("Could not restore file");
	}
	atomic_long_set(&(file->f_count), f->count);
	sprint("Set file count value to %ld\n", f->count);
	fd_install(fd, file);
}


void restore_socket(struct saved_file* f, struct saved_task_struct* state){
  struct saved_socket sock = f->socket;
  unsigned int fd;
  struct socket* socket;
struct sockaddr_in servaddr;
 int retval, fput_needed;


  //create a socket using the original spec

  retval = sock_create(sock.sock_family, sock.type, sock.sock_protocol, &socket);
  if (retval < 0){
    panic("socket create failed\n");
    return;
  }
  
  fd = alloc_fd(f->fd, 0); // need real flags
  if(fd != f->fd)
  {
    sprint("Could not get original fd %u, got %u\n", f->fd, fd);
    panic("Could not get original fd");
  }
  struct file* file = get_empty_filp();
  int err = sock_attach_fd(socket, file, sock.flags);
  
  if (unlikely(err < 0)) {
     put_filp(file);
     put_unused_fd(fd);
     panic("socket attached failed\n");
     return;
     }
   fd_install(fd, file);
   

   //check if the socket has binded or not, if so, apply the appropriate binding.
   if(sock.binded){
       switch(sock.type){
	   case SOCK_DGRAM: 
	     memset(&servaddr,'\0' ,sizeof(servaddr));
	     servaddr.sin_family = AF_INET;

	     if(sock.inet.rcv_saddr == 0)
	     servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	     else
	     servaddr.sin_addr.s_addr = htonl(sock.inet.rcv_saddr);  

	     servaddr.sin_port = htons(sock.inet.num);
	     err = socket->ops->bind(socket,(struct sockaddr *)&servaddr, sizeof(servaddr));

	     if(err<0)panic("binding failed");

	   break;
       }
   }
  return;
}


void restore_files(struct saved_task_struct* state, struct global_state_info* global_state)
{
	struct saved_file* f;
	unsigned int max_fd = 0;

	for(f=state->open_files; f!=NULL; f=f->next)
	{
		if (f->fd > max_fd)
			max_fd = f->fd;
	}

	for(f=state->open_files; f!=NULL; f=f->next)
	{
		sprint("Restoring fd %u with path %s of file type %u\n", f->fd, f->name, f->type);
		switch (f->type)
		{
			case READ_PIPE_FILE:
			case WRITE_PIPE_FILE:
				restore_pipe(f, global_state, state, &max_fd);
				break;
			case READ_FIFO_FILE:
			case WRITE_FIFO_FILE:
				restore_fifo(f, global_state, state, &max_fd);
				break;
		        case SOCKET:
			        restore_socket(f,state);
				break;
			default:
				restore_file(f);
				break;
		}
	}
}

void close_unused_pipes(struct saved_task_struct* state, struct global_state_info* global_state)
{
	struct pipes_to_close* p;

	// Loop through global close pipes structure and search for pid, closing all marked fds
	for (p = global_state->pipe_close_head; p != NULL; p = p->next)
	{
		if (p->process == state->pid)
		{
			sys_close(p->fd);
			sprint("Closed pipe at fd %u.\n", p->fd);
		}
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
	if(state->syscall_restart == 179)
	{
		sprint("Process was inside sigsuspend\n");
		sprint("System call needs to be restarted\n");
		sprint("Eax: %ld, orig_ax: %ld ip: %lx\n",
		       state->registers.ax, state->registers.orig_ax, state->registers.ip);
		current->blocked = *(sigset_t*)state->syscall_data;
		state->registers.ax = state->registers.orig_ax;
		state->registers.ip -= 2;

	   
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


	switch(state->syscall_restart)
	{
	case 4:
	case 102:
	case 162:  // nanosleep
	case 240:  // futex
	case 7:    // waitpid
	case 114:  // wait4
		sprint("Restarting system call %d\n", state->syscall_restart);
		state->registers.ax = state->registers.orig_ax;
		state->registers.ip -= 2;
		break;
	}	
	*regs = state->registers;
	print_regs(task_pt_regs(current));
}

struct state_info
{
	struct map_entry* head;
	struct saved_task_struct* state;
	struct task_struct* parent;
	struct global_state_info *global_state;
};

static struct global_state_info global_state;
static struct pipe_restore_temp pipe_restore_head;
static struct pipes_to_close pipe_close_head;

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

static void restore_children(struct saved_task_struct* state, struct state_info* p_info)
{
	struct saved_task_struct* child;
	struct task_struct* thread;
	struct state_info* info;
	INIT_LIST_HEAD(&current->children);
	list_for_each_entry(child, &state->children, sibling)
	{
		sprint("Restoring child %d\n", child->pid);
		info = (struct state_info*)kmalloc(sizeof(*info), GFP_KERNEL);
		info->head = p_info->head;
		info->state = child;
		info->parent = current;
		info->global_state = p_info->global_state;

		thread = kthread_create(do_restore, info, "child_restore");
		if(IS_ERR(thread))
		{
			panic("Failed to create a thread\n");
		}
		wake_up_process(thread);
	}
}

int count_processes(struct saved_task_struct* state)
{
	int count = 1;
	struct saved_task_struct* child;
	list_for_each_entry(child, &state->children, sibling)
	{
		count += count_processes(child);
	}
	return count;
}


int set_state(struct pt_regs* regs, struct saved_task_struct* state)
{
	struct task_struct* thread;
	struct state_info* info;
//	int restore_count;
//	struct mutex lock;
//	struct completion all_done;
//	DECLARE_COMPLETION_ONSTACK(all_done);
//	wait_queue_head_t wq;

	init_waitqueue_head(&global_state.wq);
	atomic_set(&global_state.processes_left, count_processes(state));
	init_completion(&global_state.all_done);

//int restore_count;
//DEFINE_MUTEX(lock);
//DECLARE_WAIT_QUEUE_HEAD(wq);
// DECLARE_COMPLETION(all_done);




	sprint("Restoring pid parent: %d\n", state->pid);
	sprint("Need to restore %d processes\n", atomic_read(&global_state.processes_left));

	info = (struct state_info*)kmalloc(sizeof(*info), GFP_KERNEL);
	info->head = new_map();
	info->state = state;
	info->parent = NULL;
	info->global_state = &global_state;
	info->global_state->pipe_restore_head = &pipe_restore_head;
	info->global_state->pipe_restore_head->pipe_id = NULL;
	info->global_state->pipe_restore_head->next = NULL;
	info->global_state->pipe_restore_head->processlist = NULL;
	info->global_state->pipe_close_head = &pipe_close_head;
	info->global_state->pipe_close_head->next = NULL;

	thread = kthread_create(do_restore, info, "test_thread");
	if(IS_ERR(thread))
	{
		sprint("Failed to create a thread\n");
		return 0;
	}

 	wake_up_process(thread);
	sprint("parent waiting for children\n");
	wait_event(global_state.wq, atomic_read(&global_state.processes_left) == 0);
	sprint("parent finishes waiting for children\n");
	complete_all(&global_state.all_done);
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
		current->thread.gs = state->gs;
		memcpy(current->thread.tls_array, state->tls_array, GDT_ENTRY_TLS_ENTRIES*sizeof(struct desc_struct));
		load_TLS(&current->thread, cpu);
		put_cpu();
		loadsegment(gs, state->gs);
	       
	
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

		
		restore_files(state, info->global_state);
		sprint("Ptrace flags: %x, thread_info flags: %lx\n", current->ptrace, task_thread_info(current)->flags);
		restore_signals(state);
		restore_creds(state);

		restore_registers(state);

		add_to_restored_list(current);

		restore_children(state, info);

		if(info->parent)
		{
			current->real_parent = info->parent;
			INIT_LIST_HEAD(&current->sibling);
			list_add_tail(&current->sibling, &current->real_parent->children);
		}


		sprint("Current %d, parent %d %s\n", current->pid, current->real_parent->pid, current->real_parent->comm);

		if (atomic_dec_and_test(&info->global_state->processes_left)) {
			sprint("child wakes up parent\n");
			wake_up(&info->global_state->wq);
		}
		wait_for_completion(&info->global_state->all_done);

		// Post-restore, pre-wakeup tasks
		close_unused_pipes(state, info->global_state);
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




