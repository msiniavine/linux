#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/tcp.h>
#include <net/route.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
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
#include <linux/console.h>
#include <linux/vt_kern.h>
#include <linux/kbd_kern.h>

#include <asm/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/tlb.h>

#include <linux/ramfs.h>
#include <linux/set_state.h>
#include <linux/string.h>

#include <linux/mousedev.h>

#include <linux/kbd_kern.h>
#include <linux/smp_lock.h>

#include <linux/termios.h>

#define NOSET_MASK(x, y, z) (x = ((x) & ~(z)) | ((y) & (z)))

void restore_listen_socket ( struct saved_file *saved_file );

static int restore_fb_info ( struct fb_info *info, struct saved_fb_info *saved_info );
static int restore_fb_contents ( struct fb_info *info, char *contents );
static int restore_con2fbmaps ( struct fb_info *info, struct fb_con2fbmap *con2fbs );
static struct file *restore_fb ( struct saved_file *saved_file );
static struct file *restore_mouse ( struct saved_file *saved_file );

static void restore_unix_socket ( struct saved_file *saved_file, struct map_entry *head );

// These three are altered versions of the socket(), bind(), and listen() system calls, respectively.
struct file *create_socket ( int fd, int flags_additional, int family, int type, int protocol );
int bind_socket ( struct file *file, struct sockaddr *address, int address_length );
int listen_socket ( struct file *file, int backlog );
//

// This is an altered version of do_unlinkat() in fs/namei.c.
int unlink_file ( char *path );
//

// The function set_owner() is an altered version of the chown() system call in fs/open.c.
static int chown_common ( struct path *path, uid_t user, gid_t group );
int set_owner ( char *path, uid_t user, gid_t group );
//

//
static void restore_fown_struct ( struct saved_file *saved_file, struct file *file );
//

// This is an altered version of the combination of set_termios() and change_termios() in drivers/char/tty_ioctl.c.
int set_termios ( struct tty_struct *tty, struct ktermios *kterm );
//

static bool valid_arg_len(struct linux_binprm *bprm, long len)
{
	return len <= MAX_ARG_STRLEN;
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
	
	install_exec_creds(bprm);

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

// This function allocates memory for a new used_file object, initializes its
// list_head object, and then returns a pointer to the new used_file object.
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
//

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
	filep = do_filp_open(AT_FDCWD, filename, O_RDONLY|O_LARGEFILE, 0, 0);
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
  	// The code below first checks to see if the "saved" memory descriptor has been
  	// encountered before.  If it has been encountered, then increment the mm_users
  	// field of the associated "real" memory descriptor by 1 and then set the mm field
  	// of bprm to point to that mm_struct; otherwise, allocate
  	// memory and initialize that memory for a new mm_struct, and then "insert" it
  	// and the associated saved_mm_struct into the map_entry objects list...
  	//
  	// If memory could not be allocated for a new mm_struct, then -ENOMEM is returned.
  	// -ENOMEM is the out of memory error number.
  	//
  	// nr_ptes is...?
  	//
  	// clone_pgd_range(mm->pgd, state->mm->pgd, SAVED_PGD_SIZE) appears to
  	// copy SAVED_PGD_SIZE amount of PGDs starting from state->mm->pgd to
  	// mm->pgd...
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
	//

	// Copy over the heap start and end addresses.
	mm->start_brk = state->mm->start_brk;
	mm->brk = state->mm->brk;
	//

	// ???
	err = init_new_context(current, mm);
	if (err)
		goto err;
	sprint("Created new context\n");
	err = create_vmas(bprm, state, files);
	if (err)
		goto err;
	sprint("Created vmas\n");
	return 0;
	//

	// ???
err:
	if (mm) {
		bprm->mm = NULL;
		mmdrop(mm);
	}

	return err;
	//
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
		if (do_pipe_flags(pipe_fd, 0) < 0)
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

// Warning: This function does not restore everything that should be restore.
struct file* restore_vc_terminal(struct saved_file* f)
{
	//
	struct file* file;
	struct tty_struct* tty;
	struct tty_driver* driver;
	struct vc_data* vcd;
	struct saved_vc_data* svcd = f->vcd;
	
	struct kbd_struct *kbd;
	
	char full_name[PATH_LENGTH];
	unsigned long arg = 0;
	int ret;
	//
	
	//memset(full_name, 0, sizeof(full_name));
	//strcat(full_name, "/dev");
	//strcat(full_name, f->name);
	strcpy( full_name, f->name );
	file = do_filp_open(-100, full_name, f->flags, -1074763960, 0);
	if(IS_ERR(file))
	{
		panic("Could not open terminal file with error: %ld\n", PTR_ERR(file));
	}
	
	tty = file->private_data;
	driver = tty->driver;
	vcd = tty->driver_data;
	kbd = &kbd_table[vcd->vc_num];
	//
	
	//
	restore_fown_struct( f, file );
	//
	
	lock_kernel();
	
	//
	arg = svcd->v_active;
	if ( arg == 0 || arg > MAX_NR_CONSOLES )
	{
		panic( "Unable to continue due to invalid VT number, %d.\n", arg );
	}
	else 
	{
		arg--;
		acquire_console_sem();
		ret = vc_allocate( arg );
		release_console_sem();
		if ( ret )
		{
			panic( "Function vc_allocate() failed.\n" );
		}
		set_console( arg );
	}
	
	
	if ( svcd->vt_mode.mode != VT_AUTO && svcd->vt_mode.mode != VT_PROCESS )
	{
		panic( "Unable to continue due to invalid VT modes.\n" );
	}
	acquire_console_sem();
	vcd->vt_mode = svcd->vt_mode;
	// the frsig is ignored, so we set it to 0
	vcd->vt_mode.frsig = 0;
	put_pid( vcd->vt_pid );
	vcd->vt_pid = get_pid( task_pid( current ) );
	// no switch is required -- saw@shade.msu.ru
	vcd->vt_newvt = -1;
	release_console_sem();
	
	
	arg = svcd->vc_mode;
	switch ( arg )
	{
		case KD_GRAPHICS:
			break;
		case KD_TEXT0:
		case KD_TEXT1:
			arg = KD_TEXT;
		case KD_TEXT:
			break;
		default:
			panic( "Unable to continue due to invalid VC modes.\n" );
	}
	if ( vcd->vc_mode != ( unsigned char ) arg )
	{
		vcd->vc_mode = ( unsigned char ) arg;
		if ( vcd->vc_num == fg_console )
		{
			//
			// explicitly blank/unblank the screen if switching modes
			//
			acquire_console_sem();
			if ( arg == KD_TEXT )
			{
				do_unblank_screen( 1 );
			}
			else
			{
				do_blank_screen( 1 );
			}
			release_console_sem();
		}
	}
	//
	
	//
	arg = ((svcd->kbdmode == VC_RAW) ? K_RAW :
				 (kbd->kbdmode == VC_MEDIUMRAW) ? K_MEDIUMRAW :
				 (kbd->kbdmode == VC_UNICODE) ? K_UNICODE :
				 K_XLATE);
	
	switch ( arg )
	{
		case K_RAW:
			kbd->kbdmode = VC_RAW;
			break;
		case K_MEDIUMRAW:
			kbd->kbdmode = VC_MEDIUMRAW;
			break;
		case K_XLATE:
			kbd->kbdmode = VC_XLATE;
			compute_shiftstate();
			break;
		case K_UNICODE:
			kbd->kbdmode = VC_UNICODE;
			compute_shiftstate();
			break;
		default:
			panic( "Unable to restore VC terminal due to invalid KBD mode %d.\n", arg );
	}
	tty_ldisc_flush(tty);
	//
	
	//
	ret = set_termios( tty, &svcd->kterm );
	if ( ret < 0 )
	{
		panic( "Unable to restore VC terminal attributes.  Error: %d\n", ret );
	}
	//

	//tty = (struct tty_struct*)file->private_data;
	if(tty->magic != TTY_MAGIC)
	{
		panic("tty magic value does not match\n");
	}
	//driver = tty->driver;
	if(driver->type != TTY_DRIVER_TYPE_CONSOLE || driver->subtype !=0)
	{
		panic("Driver type des not match\n");
	}
	//vcd = (struct vc_data*)tty->driver_data;
	if(vcd->vc_screenbuf_size != svcd->screen_buffer_size)
	{
		panic("Screen buffer sizes do not match\n");
	}
	memcpy(vcd->vc_screenbuf, svcd->screen_buffer, svcd->screen_buffer_size); 
	vcd->vc_x = svcd->x;
	vcd->vc_y = svcd->y;
	redraw_screen(vcd, 0);
	
	unlock_kernel();
	
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
		case FRAMEBUFFER:
			file = restore_fb( f );
			break;
		case MOUSE:
			file = restore_mouse( f );
			break;
		default:
			file = do_filp_open(-100, f->name, f->flags, -1074763960, 0); 
			if(IS_ERR(file))
			{
				panic("Could not open file %s\n", f->name);
			}
			sprint("Restoring some normal file.\n");
			break;
	}
	
	//
	//file->f_pos = f->f_pos;
	//

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

int __inet_check_established(struct inet_timewait_death_row *death_row,
				    struct sock *sk, __u16 lport,
			     struct inet_timewait_sock **twp);



// rewrite of __inet_hash_connect to restore the desired port for the restored socket
int restore_inet_hash(struct inet_timewait_death_row* death_row, struct sock* sk, unsigned short desired_port)
{
	struct inet_hashinfo *hinfo = death_row->hashinfo;
	struct inet_bind_hashbucket *head;
	struct inet_bind_bucket *tb;
	struct net* net = sock_net(sk);
	struct hlist_node* node;
	struct inet_timewait_sock* tw = NULL;

	sprint("hashing socket to the desired port %u\n", desired_port);
	local_bh_disable();
	head = &hinfo->bhash[inet_bhashfn(net, desired_port, hinfo->bhash_size)];
	spin_lock(&head->lock);

	inet_bind_bucket_for_each(tb, node, &head->chain)
	{
		if(tb->ib_net == net && tb->port == desired_port)
		{
			WARN_ON(hlist_empty(&tb->owners));
			if(tb->fastreuse >= 0)
			{
				//panic("Could not get desired port because of fastreuse\n");
				sprint("Ignoring fast reuse\n");
			}
			if(!__inet_check_established(death_row, sk, desired_port, &tw))
			{
				sprint("not established\n");
				goto ok;
			}
			panic("Could not get desired port\n");
		}
	}

	sprint("creating new bhash bucket\n");
	tb = inet_bind_bucket_create(hinfo->bind_bucket_cachep, net, head, desired_port);
	if(!tb)
	{
		spin_unlock(&head->lock);
		panic("Could not allocate a new bhash bucket\n");
	}
	tb->fastreuse = -1;

ok:
	sprint("binding socket to a port %u\n", desired_port);
	inet_bind_hash(sk, tb, desired_port);
	if(sk_unhashed(sk))
	{
		inet_sk(sk)->sport = htons(desired_port);
		__inet_hash_nolisten(sk);
	}
	spin_unlock(&head->lock);
	if(tw)
	{
		inet_twsk_deschedule(tw, death_row);
		inet_twsk_put(tw);
	}

	local_bh_enable();
	return 0;
	

	
/*	inet_sk(sk)->sport = htons(desired_port);
	__inet_hash_nolisten(sk);
	return 0;
	*/
}


/* void test_restore_sockets() */
/* { */
/* 	int retval; */

/* 	unsigned int fd; */
/* 	struct file* file; */
/* 	//struct saved_socket* saved_socket = &f->socket; */
/* //	int flags = saved_socket->flags; */
/* 	struct socket* sock; */

/* 	struct inet_sock* inet; */
/* 	struct tcp_sock* tp; */
/* 	struct rtable* rt; */
/* 	__be32 daddr, nexthop; */
/* 	struct sock* sk; */
/* 	sprint("Restoring TCP socket\n"); */
/* //	sprint("saddr %u, sport %u, daddr %u, dport %u\n", saved_socket->tcp->saddr, saved_socket->tcp->sport, */
/* //	       saved_socket->tcp->daddr, saved_socket->tcp->dport); */
	
/* //	retval = sock_create(saved_socket->sock_family, saved_socket->sock_type, saved_socket->sock_protocol, &sock); */
/* 	retval = sock_create(2, 1, 6, &sock); */
/* 	if(retval < 0) */
/* 	{ */
/* 		panic("Socket create failed: %d", retval); */
/* 	} */

/* 	fd=alloc_fd(4, 0); // need real flags */
/* 	if(fd != 4) */
/* 	{ */
/* 		//sprint("Could not get original fd %u got %u\n", f->fd, fd); */
/* 		panic("Could not get original fd"); */
/* 	} */
	
/* 	file = get_empty_filp(); */
/* //	if(f->flags & O_NONBLOCK) */
/* //		flags |=O_NONBLOCK; */
/* 	retval = sock_attach_fd(sock, file, 0); */
/* 	if(retval < 0) */
/* 	{ */
/* 		put_filp(file); */
/* 		put_unused_fd(fd); */
/* 		panic("socket attach failed\n"); */
/* 	} */
/* 	fd_install(fd, file); */

/* 	sk=sock->sk; */
/* 	inet = inet_sk(sk); */
/* 	tp = tcp_sk(sk); */

/* 	sprint("Setting state %d\n", 0); */
/* 	tcp_set_state(sk, 1); */

/* 	sprint("Setting routing information\n"); */
/* 	nexthop = daddr = 24842412; */
/* 	sprint("inet->saddr %u sport %u\n", inet->saddr, inet->sport); */
/* 	retval = ip_route_connect(&rt, nexthop, inet->saddr, RT_CONN_FLAGS(sk), sk->sk_bound_dev_if, IPPROTO_TCP, */
/* 				  inet->sport, htons(60449), sk, 1); */

/* 	if(retval < 0) */
/* 	{ */
/* 		panic("Could not get routing information\n"); */
/* 	} */

/* 	if(!inet->opt || !inet->opt->srr) */
/* 	{ */
/* 		daddr = rt->rt_dst; */
/* 	} */

/* 	if(!inet->saddr) */
/* 	{ */
/* 		inet->saddr = rt->rt_src; */
/* 	} */
/* 	inet->rcv_saddr = inet->saddr; */
/* 	sprint("inet->saddr %u sport %u\n", inet->saddr, inet->sport); */

/* 	if(tp->rx_opt.ts_recent_stamp && inet->daddr != daddr) */
/* 	{ */
/* 		tp->rx_opt.ts_recent = 0; */
/* 		tp->rx_opt.ts_recent_stamp = 0; */
/* 		tp->write_seq = 0; */
/* 	} */

/* 	// some peer stuff might need to go here */
	
/* 	inet->dport = htons(60449); */
/* 	inet->daddr = daddr; */
/* 	inet_csk(sk)->icsk_ext_hdr_len = 0; */


/* 	tp->rx_opt.mss_clamp = 536; */
/* 	retval = restore_inet_hash(&tcp_death_row, sk, 5001); */
/* 	if(retval) */
/* 	{ */
/* 		panic("inet_hash_connect failed %d\n", retval); */
/* 	} */
/* 	sprint("assigned socket to port %u (%u)\n", inet->sport, ntohs(inet->sport)); */

/* 	retval = ip_route_newports(&rt, IPPROTO_TCP, inet->sport, inet->dport, sk); */
/* 	if(retval) */
/* 	{ */
/* 		panic("ip_route_newports failed %d\n", retval); */
/* 	} */

/* 	sk->sk_gso_type = SKB_GSO_TCPV4; */
/* 	sk_setup_caps(sk, &rt->u.dst); */

/* 	//set seq number */
/* 	// set other tcp state */

/* } */

extern struct inet_timewait_death_row tcp_death_row;
void restore_tcp_socket(struct saved_file* f)
{
	int retval;

	unsigned int fd;
	struct file* file;
	struct saved_socket* saved_socket = &f->socket;
	int flags = saved_socket->flags;
	struct socket* sock;

	struct inet_sock* inet;
	struct inet_connection_sock* icsk;
	struct tcp_sock* tp;
	struct rtable* rt;
	__be32 daddr, nexthop;
	struct sock* sk;
	sprint("Restoring TCP socket\n");
	sprint("saddr %u, sport %u, daddr %u, dport %u\n", saved_socket->tcp->saddr, saved_socket->tcp->sport,
	       saved_socket->tcp->daddr, saved_socket->tcp->dport);
	
	retval = sock_create(saved_socket->sock_family, saved_socket->sock_type, saved_socket->sock_protocol, &sock);
	if(retval < 0)
	{
		panic("Socket create failed: %d", retval);
	}

	fd=alloc_fd(f->fd, 0); // need real flags
	if(fd != f->fd)
	{
		sprint("Could not get original fd %u got %u\n", f->fd, fd);
		panic("Could not get original fd");
	}
	
	file = get_empty_filp();
	if(f->flags & O_NONBLOCK)
		flags |=O_NONBLOCK;
	retval = sock_attach_fd(sock, file, flags);
	if(retval < 0)
	{
		put_filp(file);
		put_unused_fd(fd);
		panic("socket attach failed\n");
	}
	fd_install(fd, file);

	sk=sock->sk;
	inet = inet_sk(sk);
	icsk = inet_csk(sk);
	tp = tcp_sk(sk);

	sprint("Setting state %d\n", saved_socket->tcp->state);
	tcp_set_state(sk, saved_socket->tcp->state);

	sprint("Setting routing information\n");
	nexthop = daddr = saved_socket->tcp->daddr;
	retval = ip_route_connect(&rt, nexthop, inet->saddr, RT_CONN_FLAGS(sk), sk->sk_bound_dev_if, IPPROTO_TCP,
				  inet->sport, htons(saved_socket->tcp->dport), sk, 1);

	if(retval < 0)
	{
		panic("Could not get routing information\n");
	}

	if(!inet->opt || !inet->opt->srr)
	{
		daddr = rt->rt_dst;
	}

	if(!inet->saddr)
	{
		inet->saddr = rt->rt_src;
	}
	inet->rcv_saddr = inet->saddr;

	if(tp->rx_opt.ts_recent_stamp && inet->daddr != daddr)
	{
		tp->rx_opt.ts_recent = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		tp->write_seq = 0;
	}

	// some peer stuff might need to go here
	
	inet->dport = htons(saved_socket->tcp->dport);
	inet->daddr = daddr;
	inet_csk(sk)->icsk_ext_hdr_len = 0;


	tp->rx_opt.mss_clamp = 536;
	
	retval = restore_inet_hash(&tcp_death_row, sk, saved_socket->tcp->sport);
	if(retval)
	{
		panic("inet_hash_connect failed %d\n", retval);
	}
	sprint("assigned socket to port %u (%u)\n", inet->sport, ntohs(inet->sport));

	retval = ip_route_newports(&rt, IPPROTO_TCP, inet->sport, inet->dport, sk);
	if(retval)
	{
		panic("ip_route_newports failed %d\n", retval);
	}

	sk->sk_gso_type = SKB_GSO_TCPV4;
	sk_setup_caps(sk, &rt->u.dst);

	// set other tcp state
	icsk->icsk_ack.rcv_mss = saved_socket->tcp->rcv_mss;

	tp->rcv_nxt = saved_socket->tcp->rcv_nxt;
	tp->rcv_wnd = saved_socket->tcp->rcv_wnd;
	tp->rcv_wup = saved_socket->tcp->rcv_wup;
	tp->snd_nxt = saved_socket->tcp->snd_nxt;

	tp->snd_una = saved_socket->tcp->snd_una;
	tp->snd_wl1 = saved_socket->tcp->snd_wl1;
	tp->snd_wnd = saved_socket->tcp->snd_wnd;
	tp->max_window = saved_socket->tcp->max_window;
	tp->mss_cache = saved_socket->tcp->mss_cache;
	
	tp->window_clamp = saved_socket->tcp->window_clamp;
	tp->rcv_ssthresh = saved_socket->tcp->rcv_ssthresh;
	tp->advmss = saved_socket->tcp->advmss;
	tp->rx_opt.rcv_wscale = saved_socket->tcp->rcv_wscale;

	tp->pred_flags = saved_socket->tcp->pred_flags;
	tp->tcp_header_len = saved_socket->tcp->tcp_header_len;

	//set seq number
	tp->write_seq = saved_socket->tcp->write_seq;
	tp->copied_seq = saved_socket->tcp->copied_seq;


}

void restore_udp_socket(struct saved_file* f){
	struct saved_socket sock = f->socket;
	unsigned int fd;
	struct socket* socket;
	struct sockaddr_in servaddr;
	int retval;
	struct file* file;
	int err;
	int flags = sock.flags;
	

	//create a socket using the original spec
	sprint("Restoring udp socket\n");

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
	file = get_empty_filp();
	if(f->flags & O_NONBLOCK)
		flags |= O_NONBLOCK;
	err = sock_attach_fd(socket, file, flags);
	
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

void restore_socket ( struct saved_file* f, struct map_entry *head )
{
	struct saved_socket* sock = &f->socket;
	
	//
	switch ( sock->sock_family )
	{
		case AF_INET:
			switch ( sock->sock_type )
			{
				case SOCK_STREAM:
					if ( sock->tcp->state == TCP_LISTEN )
					{
						restore_listen_socket( f );
					}
					
					else
					{
						restore_tcp_socket( f );
					}
					
					break;
					
				case SOCK_DGRAM:
					restore_udp_socket( f );
					
					break;
			}
			
			break;
			
		case AF_UNIX:
			restore_unix_socket( f, head );
			
			break;
			
		default:
			sprint( "Unknown socket family %d, type %d.\n", sock->sock_family, sock->sock_type );
			
			break;
	}
	//
}

void restore_listen_socket ( struct saved_file *saved_file )
{
	//
	struct file *file;
	int fd = saved_file->fd;
	int flags = saved_file->flags;
	
	int family = saved_file->socket.sock_family;
	int type = saved_file->socket.sock_type;
	int protocol = saved_file->socket.sock_protocol;
	
	int backlog = saved_file->socket.tcp->backlog;
	
	struct sockaddr_in address;
	
	int status = 0;
	//

	//
	file = create_socket( fd, flags, family, type, protocol  );
	if ( IS_ERR( file ) )
	{
		panic( "Unable to recreate TCP listening socket.  Error: %d\n", -( ( int ) file ) );
	}
	//
	
	//
	memset( &address, 0, sizeof( address ) );
	
	address.sin_family = AF_INET;
	address.sin_port = htons( saved_file->socket.inet.num );
	
	address.sin_addr.s_addr = htonl( INADDR_ANY );
	if ( saved_file->socket.inet.rcv_saddr )
	{
		address.sin_addr.s_addr = htonl( saved_file->socket.inet.rcv_saddr );
	}
	
	status = bind_socket( file, ( struct sockaddr * ) &address, sizeof( address ) );
	if ( status < 0 )
	{
		panic( "Unable to rebind TCP listening socket.  Error: %d\n", -status );
	}
	//
	
	//
	status = listen_socket( file, backlog );
	if ( status < 0 )
	{
		panic( "Unable to put TCP listening socket back to listening state.  Error: %d\n", -status );
	}
	//
}

void restore_files ( struct saved_task_struct* state, struct global_state_info* global_state, struct map_entry *head )
{
	struct saved_file* f;
	unsigned int max_fd = 0;

	// Finds the largest file descriptor index...
	for(f=state->open_files; f!=NULL; f=f->next)
	{
		if (f->fd > max_fd)
			max_fd = f->fd;
	}
	//

	// Finds out what kind file the file is/was and then calls then appropraite function
	// to "restore" the file...
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
			        restore_socket( f, head );
				break;
			default:
				restore_file(f);
				break;
		}
		
		
	}
	//
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

int check_unsafe_exec(struct linux_binprm *);

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

	// Appears to be allocating memory from some kind of cache for a single
	// struct pid object.
	sprint("Changing pid from %d to %d/n", task_pid_nr(current), original_pid);
	pid = kmem_cache_alloc(ns->pid_cachep, GFP_KERNEL);
	if (!pid)
		goto out;
	sprint("Allocated pid structure\n");
	//

	// ???
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
	//

	// level is...?
	//
	// atomic_set(&pid->count, 1) sets the number of tasks using this pid to 1...
	//
	// INIT_HLIST_HEAD() sets the first field of the object pointed to by the 
	// passed in pointer to NULL...
	//
	//get_pid_ns(ns);
	pid->level = ns->level;
	atomic_set(&pid->count, 1);
	for (type = 0; type < PIDTYPE_MAX; ++type)
		INIT_HLIST_HEAD(&pid->tasks[type]);
	//

	// ???
	spin_lock_irq(&pidmap_lock);
	for (i = ns->level; i >= 0; i--) {
		upid = &pid->numbers[i];
		hlist_add_head_rcu(&upid->pid_chain,
				&pid_hash[pid_hashfn(upid->nr, upid->ns)]);
	}
	spin_unlock_irq(&pidmap_lock);
	//

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
	current->flags &= ~PF_KTHREAD;
}

void restore_creds(struct saved_task_struct* state)
{
	struct cred *new_creds;
	
	rcu_read_lock();
	
	new_creds = prepare_creds();
	if ( !new_creds )
	{
		panic( "Unable to prepare new set of credentials for modification.\n" );
	}

	new_creds->uid = state->uid;
	new_creds->euid = state->euid;
	new_creds->suid = state->suid;
	new_creds->fsuid = state->fsuid;

	new_creds->gid = state->gid;
	new_creds->egid = state->egid;
	new_creds->sgid = state->sgid;
	new_creds->fsgid = state->fsgid;

	new_creds->cap_effective = state->cap_effective;
	new_creds->cap_inheritable = state->cap_inheritable;
	new_creds->cap_permitted = state->cap_permitted;
	new_creds->cap_bset = state->cap_bset;
	
	commit_creds( new_creds );
	
	rcu_read_unlock();
	
	return;
}

void restore_registers(struct saved_task_struct* state)
{
	struct pt_regs* regs;

	sprint("Restoring registers\n");
	regs = task_pt_regs(current);


	switch(state->syscall_restart)
	{
	case 4:
	case 102:  // socketcall
	case 162:  // nanosleep
	case 240:  // futex
	case 7:    // waitpid
	case 114:  // wait4
	case 142:  // select
		sprint("Restarting system call %d\n", state->syscall_restart);
		state->registers.ax = state->registers.orig_ax;
		state->registers.ip -= 2;
		break;
	default:
		sprint("Was in system call %d, taking no action\n", state->syscall_restart);
		break;
	}	
	*regs = state->registers;
	print_regs(task_pt_regs(current));
}

// head is the head pointer to the doubly-linked list of map_entry objects.
// The list of map_entry objects used or refered to in this file appear
// to have nothing to do with the ones created in saved_state.c...?
//
// state is the pointer to the "saved process" of interest.
//
// parent is the pointer to the process descriptor of the parent of "*state".
//
// global_state is...?
struct state_info
{
	struct map_entry* head;
	struct saved_task_struct* state;
	struct task_struct* parent;
	struct global_state_info *global_state;
};
//

struct global_state_info global_state;
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

// Why is this function required if it pretty much just calls another function?
int do_restore(void* data)
{
	struct state_info* info = (struct state_info*)data;


	do_set_state(info);
	sprint("state restored need to return to user space\n");
	return 0;
}
//

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

// What calls this function?  Where is this function called?
int set_state(struct pt_regs* regs, struct saved_task_struct* state)
{
	struct task_struct* thread;
	struct state_info* info;
//	int restore_count;
//	struct mutex lock;
//	struct completion all_done;
//	DECLARE_COMPLETION_ONSTACK(all_done);
//	wait_queue_head_t wq;

	//
	static struct map_entry *map_entry_head = NULL;
	//
	
	//
	if ( !map_entry_head )
	{
		map_entry_head = new_map();
	}
	//

	// init_waitqueue_head() sets the variable pointed to by the argument to NULL.
	//
	// atomic_set() sets (v)->counter to equal to its second argument, where v is
	// the function's first argument.
	//
	// init_completion() sets x->done to equal to 0 and passes in &x->wait as an
	// argument into init_wait_queue_head(), where x is the function's first and
	// and only argument.
	init_waitqueue_head(&global_state.wq);
	atomic_set(&global_state.processes_left, count_processes(state));
	init_completion(&global_state.all_done);
	//

//int restore_count;
//DEFINE_MUTEX(lock);
//DECLARE_WAIT_QUEUE_HEAD(wq);
// DECLARE_COMPLETION(all_done);


	sprint("Restoring pid parent: %d\n", state->pid);
	sprint("Need to restore %d processes\n", atomic_read(&global_state.processes_left));

	// Some setting up of the state_info object...
	//
	// What is the stuff after info->parent = NULL;?
	info = (struct state_info*)kmalloc(sizeof(*info), GFP_KERNEL);
	info->head = map_entry_head;
	info->state = state;
	info->parent = NULL;
	info->global_state = &global_state;
	info->global_state->pipe_restore_head = &pipe_restore_head;
	info->global_state->pipe_restore_head->pipe_id = NULL;
	info->global_state->pipe_restore_head->next = NULL;
	info->global_state->pipe_restore_head->processlist = NULL;
	info->global_state->pipe_close_head = &pipe_close_head;
	info->global_state->pipe_close_head->next = NULL;
	//

	// Creates a thread that begins executing do_restore().  The variable
	// info is the argument into do_restore().
	thread = kthread_create(do_restore, info, "test_thread");
	if(IS_ERR(thread))
	{
		sprint("Failed to create a thread\n");
		return 0;
	}
	//

	// wake_up_process() is required to start the thread created by kthread_create().
	//
	// ???
 	wake_up_process(thread);
	sprint("parent waiting for children\n");
	wait_event(global_state.wq, atomic_read(&global_state.processes_left) == 0);
	sprint("parent finishes waiting for children\n");
	complete_all(&global_state.all_done);
	return 0;
	//
}
//

int do_set_state(struct state_info* info)
{
  	// ???
	struct linux_binprm* bprm;
	struct files_struct* displaced;
	int retval;
	struct file* file;
	struct used_file* used_files;
	struct saved_task_struct* state = info->state;
	//

	// current is the task_struct of the current process, which is
	// the process that is executing this code.
	//
	// Besides setting displaced to point to the "current" task's files
	// descriptor, what else does unshare_files() do?
	sprint("Ptrace flags: %x, thread_info flags: %x\n", current->ptrace, task_thread_info(current)->flags);
	retval = unshare_files(&displaced); // this seems to copy the open files of the current task (displaced is released later)
	if(retval)
		goto out_ret;
	sprint( "Unsared files\n");
	//

	// Allocating memory for a single struct linux_binprm object.
	//
	// -ENOMEM is the out of memory error number.
	retval = -ENOMEM;
	bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
	if(!bprm)
		goto out_files;

	retval=prepare_bprm_creds(bprm);
	if(retval)
	  	goto out_kfree;	

	retval = check_unsafe_exec(bprm);
	if(retval < 0)
	  	goto out_kfree;
	sprint( "Allocated bprm\n");
	
	
	// open_exec() "opens" the file specified by the given path and returns a 
	// pointer to a struct file object?  Which process descriptor is the open file
	// "associated" with?  The kernel process?
	//
	// PTR_ERR() appears to just type-cast the passed in pointer into a long type and then
	// returns that value.
	file = open_exec(state->exe_file);
	retval = PTR_ERR(file);
	if (IS_ERR(file))
		goto out_kfree;
	//

	// file is a pointer to a struct file object representing the executable file.
	//
	// filename is the full path and name of the executable...
	//
	// interp is the full path and name of the file being executed...
	//
	//
	// init_used_files() creates a new used_file object, does some initializing, and then
	// returns a pointer to it.
	//
	// filename appears to be the full path and name of the same executable.
	//
	// filep is the pointer to the struct file object representing the executable file.
	//
	//
	// What does get_file() do?
	bprm->file = file;
	bprm->filename = state->exe_file;
	bprm->interp = state->exe_file;
	used_files = init_used_files();
	used_files->filename = state->exe_file;
	used_files->filep = file;
	get_file(file);
	sprint( "Opened executable file\n");
	//

	// ???
	retval = bprm_mm_create(bprm, state, used_files, info->head);
	if(retval)
		goto out_file;
	sprint( "Allocated new mm_struct\n");
	print_mm(bprm->mm);
	//

	sprint( "Allocated security\n");

	//here original exec was changing the value of bprm->p which has something to do with the stack
	//but i am skipping that for now, since I dont know what it does

	// ???
	retval = prepare_binprm(bprm);
	if(retval < 0)
		goto out;
	sprint( "bprm prepared\n");
	//
	
	sprint( "##### state->name: %s\n", state->name );
	sprint( "####1 current->comm: %s\n", current->comm );

	//here execve used to call load_elf_binary
	retval = load_saved_binary(bprm, state);
	if(retval >= 0)
	{
		int cpu;
		struct pid* pid;
		struct pid* current_pid;

		// Turn off the "current" process'PF_KTHREAD flag.
		// The PF_KTHREAD flag is an indication that that process is
		// a kernel process.
		become_user_process();
		//

		// ???
		current_pid = task_pid(current);
		sprint("Current pid count:%d\n", atomic_read(&current_pid->count));
		//
		
		// First line gets the processor that is currently executing this code?
		//
		// Is gs a register?  What is this one for?
		//
		// The third line is copying over the contents of Thread-Local Storage of the
		// saved process into the current process?
		//
		// What is load_TLS()?
		// What does put_cpu() do?
		// What does loadsegment do?
		cpu = get_cpu();
		current->thread.gs = state->gs;
		memcpy(current->thread.tls_array, state->tls_array, GDT_ENTRY_TLS_ENTRIES*sizeof(struct desc_struct));
		load_TLS(&current->thread, cpu);
		put_cpu();
		loadsegment(gs, state->gs);
		//
	       

		// This at least changes this process' pid to, perhaps, the one that
		// the saved process that this process will become used to have...
		//
		// ???
		pid = alloc_orig_pid(state->pid, current->nsproxy->pid_ns);
		change_pid(current, PIDTYPE_PID, pid);
		current->pid = pid_nr(pid);
		current->tgid = current->pid;
		//


		// ???
		tracehook_report_exec(NULL, bprm, &state->registers);
		//

		// ???
		acct_update_integrals(current);
		free_files(used_files);
		free_bprm(bprm);
		if (displaced)
			put_files_struct(displaced);
		//

		// ???
		restore_files( state, info->global_state, info->head );
		sprint("Ptrace flags: %x, thread_info flags: %x\n", current->ptrace, task_thread_info(current)->flags);
		restore_signals(state);
		restore_creds(state);
		//

		restore_registers(state);
		
		//
		strcpy( current->comm, state->name );
		sprint( "##### state->name: %s\n", state->name );
		sprint( "####2 current->comm: %s\n", current->comm );
		//

		add_to_restored_list(current);

		restore_children(state, info);

		if(info->parent)
		{
			current->real_parent = info->parent;
			current->parent = info->parent;
			INIT_LIST_HEAD(&current->sibling);
			list_add_tail(&current->sibling, &current->real_parent->children);
		}

		sprint("Current %d, parent %d %s\n", current->pid, current->real_parent->pid, current->real_parent->comm);

		if (atomic_dec_and_test(&info->global_state->processes_left)) {
			sprint("child wakes up parent\n");
			wake_up(&info->global_state->wq);
		}
		wait_for_completion(&info->global_state->all_done);
		
		//
		wait_for_completion( &info->global_state->all_parents_restored );
		//
		
		sprint( "##### After wait_for_completion() for \'%s\'.\n", current->comm );

		// Post-restore, pre-wakeup tasks
		close_unused_pipes(state, info->global_state);
		kfree(info);
		//unregister_set_state_hook();
		resume_saved_state();
		
		sprint( "####3 current->comm: %s\n", current->comm );
		
		return 0;
	}
	
	sprint( "####4 current->comm: %s\n", current->comm );

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

static int restore_fb_info ( struct fb_info *info, struct saved_fb_info *saved_info )
{
	//
	int ret = 0;
	//

	if ( !info || !saved_info )
	{
		ret = -EINVAL;
		
		goto done;
	}
	
	if ( !lock_fb_info( info ) )
	{
		ret = -ENODEV;
		
		goto done;
	}
	
	// Restore struct fb_var_screeninfo.
	sprint( "####1 info: 0x%.8X\t&saved_info->var: 0x%.8X\n", info, &saved_info->var );
	
	acquire_console_sem();
	
	info->flags |= FBINFO_MISC_USEREVENT;
	fb_set_var( info, &saved_info->var );
	info->flags &= ~FBINFO_MISC_USEREVENT;
	
	release_console_sem();
	
	sprint( "####2 info: 0x%.8X\t&saved_info->var: 0x%.8X\n", info, &saved_info->var );
	//
	
	// Restore the struct fb_cmap object.
	sprint( "####3 &saved_info->cmap: 0x%.8X\tinfo: 0x%.8X\n", &saved_info->cmap, info );
	
	fb_set_cmap( &saved_info->cmap, info );
	
	sprint( "####4 &saved_info->cmap: 0x%.8X\tinfo: 0x%.8X\n", &saved_info->cmap, info );
	//
	
	//
unlock:
	unlock_fb_info( info );
	//
	
	//
done:
	return ret;
	//
}

// This function is an altered version of fb_write() in the file drivers/video/fbmem.c.
static int restore_fb_contents ( struct fb_info *info, char *contents )
{
	u32 *src;
	u32 __iomem *dst;
	int c, i, cnt = 0;
	int count = 0;
	int ret = 0;
	
	if ( !info || !contents )
	{
		ret = -EINVAL;
		
		goto done;
	}
	
	if ( !lock_fb_info( info ) )
	{
		ret = -ENODEV;
		
		goto done;
	}
		
	if ( !info->screen_base )
	{
		ret = -ENODEV;
		
		goto unlock;
	}

	if ( info->state != FBINFO_STATE_RUNNING )
	{
		ret = -EPERM;
		
		goto unlock;
	}
	
	//
	count = info->screen_size;

	if ( count == 0 )
		count = info->fix.smem_len;
	//

	dst = ( u32 __iomem  *) ( info->screen_base );

	if (info->fbops->fb_sync)
		info->fbops->fb_sync(info);
		
	src = ( u32 * ) contents;

	while ( count > 0 )
	{
		c = ( count > PAGE_SIZE ) ? PAGE_SIZE : count;

		for ( i = c >> 2; i > 0; i-- )
		{
			fb_writel( *src, dst );
			
			src++;
			dst++;
		}

		if ( c & 3 )
		{
			u8 *src8 = ( u8 * ) src;
			u8 __iomem *dst8 = ( u8 __iomem * ) dst;

			for ( i = c & 3; i > 0; i-- )
			{
				fb_writeb( *src8, dst8 );
				
				src8++;
				dst8++;
			}

			src = ( u32 __iomem * ) src8;
			dst = ( u32 __iomem * ) dst8;
		}

		cnt += c;
		count -= c;
	}

	//ret = cnt;
	ret = 0;
	
unlock:
	unlock_fb_info( info );
	
done:
	return ret;
}
//

static int restore_con2fbmaps ( struct fb_info *info, struct fb_con2fbmap *con2fbs )
{
	//
	int ret = 0;
	
	struct fb_event event;
	
	int index = 0;
	//
	
	if ( !info || !con2fbs )
	{
		ret = -EINVAL;
		
		goto done;
	}
	
	if ( !lock_fb_info( info ) )
	{
		ret = -ENODEV;
		
		goto done;
	}

	//
	for ( index = 0; index < MAX_NR_CONSOLES; index++ )
	{
		request_module( "fb%d", con2fbs[index].framebuffer );
		
		event.data = &con2fbs[index];
		event.info = info;
		fb_notifier_call_chain( FB_EVENT_SET_CONSOLE_MAP, &event );
	}
	//
	
unlock:
	unlock_fb_info( info );

done:
	return ret;
}

static struct file *restore_fb ( struct saved_file *saved_file )
{
	//
	//struct saved_state *state = ( struct saved_state * ) get_reserved_region();
	
	struct file *file = NULL;
	char filename[MAX_PATH] = "";
	
	int status = 0;
	//
	
	//sprintf( filename, "/dev/fb%d", saved_file->fb.minor );
	strcpy( filename, saved_file->name );
	
	// The function filp_open() does not return NULL on error?
	file = filp_open( filename, saved_file->flags, 0 );
	if ( IS_ERR( file ) )
	{
		panic( "Unable to open framebuffer file \'%s\'.\n", filename );
	}
	//
	
	sprint( "##### Restoring framebuffer %d.\n", saved_file->fb.minor );
	
	//
	if ( saved_file->fb.info )
	{
		sprint( "##### Restoring the framebuffer information of framebuffer %d.\n", saved_file->fb.minor );
		status = restore_fb_info( file->private_data, saved_file->fb.info );
		if ( status )
		{
			panic( "Unable to restore the framebuffer information of framebuffer %d.\n", saved_file->fb.minor );
		}
	}
	
	if ( saved_file->fb.contents )
	{
		sprint( "##### Restoring the contents of framebuffer %d.\n", saved_file->fb.minor );
		status = restore_fb_contents( file->private_data, saved_file->fb.contents );
		if ( status )
		{
			panic( "Unable to restore the contents of framebuffer %d.\n", saved_file->fb.minor );
		}
		
		//state->saved_fb_contents = 0;
	}
	
	if ( saved_file->fb.con2fbs )
	{
		sprint( "##### Restoring the con2fbmaps.\n" );
		status = restore_con2fbmaps( file->private_data, saved_file->fb.con2fbs );
		if ( status )
		{
			panic( "Unable to restore the con2fbmaps.\n" );
		}
		
		//state->saved_con2fbmaps = 0;
	}
	
	/*if ( status1 || status2 || status3 )
	{
		panic( "Unable to restore framebuffer %d.\n", saved_file->fb.minor );
	}*/
	//
	
	return file;
}

static struct file *restore_mouse ( struct saved_file *saved_file )
{
	//
	struct file *file;
	
	struct mousedev_client *client;
	struct mousedev *mousedev;
	
	struct saved_mousedev_client *saved_client = &saved_file->mouse.client;
	struct saved_mousedev *saved_mousedev = &saved_file->mouse.mousedev;
	//
	
	//
	file = filp_open( saved_file->name, saved_file->flags, 0 );
	if ( IS_ERR( file ) )
	{
		panic( "Unable to open mouse file \'%s\'.\n", saved_file->name );
	}
	
	client = file->private_data;
	mousedev = client->mousedev;
	//
	
	//
	//
	
	//
	spin_lock_irq( &client->packet_lock );
	memcpy( client->packets, saved_client->packets, sizeof( client->packets ) );
	spin_unlock_irq( &client->packet_lock );
	
	client->head = saved_client->head;
	client->tail = saved_client->tail;
	client->pos_x = saved_client->pos_x;
	client->pos_y = saved_client->pos_y;

	memcpy( client->ps2, saved_client->ps2, sizeof( client->ps2 ) );
	client->ready = saved_client->ready;
	client->buffer = saved_client->buffer;
	client->bufsiz = saved_client->bufsiz;
	client->imexseq = saved_client->imexseq;
	client->impsseq = saved_client->impsseq;
	client->mode = saved_client->mode;
	client->last_buttons = saved_client->last_buttons;
	
	
	mousedev->packet = saved_mousedev->packet;
	mousedev->pkt_count = saved_mousedev->pkt_count;
	memcpy( mousedev->old_x, saved_mousedev->old_x, sizeof( mousedev->old_x ) );
	memcpy( mousedev->old_y, saved_mousedev->old_y, sizeof( mousedev->old_y ) );
	mousedev->frac_dx = saved_mousedev->frac_dx;
	mousedev->frac_dy = saved_mousedev->frac_dy;
	mousedev->touch = saved_mousedev->touch;
	//
	
	return file;
}

// Warning: Listening sockets must be restored before accept sockets or else terrible
// things might happen...
static void restore_unix_socket ( struct saved_file *saved_file, struct map_entry *head )
{
	//
	struct file *file;
	
	int fd = saved_file->fd;
	int flags = saved_file->flags;
	
	int state = saved_file->socket.unix.state;
	int backlog = saved_file->socket.backlog;
	
	int family = saved_file->socket.sock_family;
	int type = saved_file->socket.sock_type;
	int protocol = saved_file->socket.sock_protocol;
	
	struct sockaddr_un address;
	
	struct socket *socket;
	struct sock *sock;
	struct unix_sock *unix;
	
	struct saved_unix_socket *saved_unix = &saved_file->socket.unix;
	struct socket *socket_other;
	struct sock *sock_other;
	struct unix_sock *unix_other;
	
	struct map_entry *entry_current;
	
	struct sk_buff *skb;
	struct saved_sk_buff *cur;
	
	int status = 0;
	//
	
	sprint( "##### start restore_unix_socket()\n" );
	
	//
	file = create_socket( fd, flags, family, type, protocol );
	if ( IS_ERR( file ) )
	{
		panic( "Unable to recreate UNIX socket.  Error: %d\n", -( ( int ) file ) );
	}
	
	socket = file->private_data;
	sock = socket->sk;
	unix = unix_sk( sock );
	
	if ( !socket->sk )
	{
		sprint( "After create_socket().\n" );
		panic( "socket->sk is NULL.\n" );
	}
	
	if ( saved_unix->kind == SOCKET_BOUND )
	{
		sprint( "saved_unix->kind == SOCKET_BOUND\n" );
	
		//
		address = saved_unix->unix_address.address;
		if ( address.sun_path[0] )
		{
			sprint( "address.sun_path: \"%s\"", address.sun_path );
			
			if ( address.sun_path[0] != '/' )
			{
				panic( "Unable to handle UNIX socket bind address of non-absolute path \'%s\'.\n", address.sun_path );
			}
		
			status = unlink_file( address.sun_path );
			if ( status < 0 )
			{
				sprint( "Unable to unlink file \'%s\'.  Error: %d\n", address.sun_path, -status );
			}
		}
		//
	
		//
		status = bind_socket( file, ( struct sockaddr * ) &address, saved_unix->unix_address.length );
		if ( status < 0 )
		{
			panic( "Unable to rebind UNIX socket.  Error: %d\n", -status );
		}
		//
		
		//
		if ( address.sun_path[0] )
		{
			sprint( "saved_unix->user: %d\n", saved_unix->user );
			sprint( "saved_unix->group: %d\n", saved_unix->group );
		
			status = set_owner( address.sun_path, saved_unix->user, saved_unix->group );
			if ( status < 0 )
			{
				panic( "Unable to restore ownership information of bounded UNIX socket file.  Error: %d\n", -status );
			}
		}
		//
		
		//
		if ( state == TCP_LISTEN )
		{
			sprint( "state == TCP_LISTEN\n" );
			
			status = listen_socket( file, backlog );
			if ( status < 0 )
			{
				panic( "Unable to put UNIX socket back to listening state.  Error: %d\n", -status );
			}
			
			// Broadcast self.
			insert_entry( head, saved_unix, sock );
			//
		}
		//
	}
	
	else if (	saved_unix->kind == SOCKET_ACCEPTED || 
			saved_unix->kind == SOCKET_CONNECTED )
	{
		sprint( "saved_unix->kind == SOCKET_ACCEPTED || saved_unix->kind == SOCKET_CONNECTED\n" );
		
		//
		if ( !saved_unix->peer )
		{
			panic( "Unable to restore UNIX connected socket due to missing peer.\n" );
		}
		//
		
		unix_state_lock( sock );
		
		//
		sock->sk_state = TCP_ESTABLISHED;
		socket->state = SS_CONNECTED;
		//
		
		// Form connection with peer and broadcast self.
		socket_other = find_by_first( head, saved_unix->peer );
		if ( socket_other )
		{
			sprint( "socket_other\n" );
			
			if ( !socket_other->sk )
			{
				sprint( "After find_by_first().\n" );
				
				sprint( "socket_other->state: %d\n", socket_other->state );
				sprint( "socket_other->type: %d\n", socket_other->type );
				sprint( "socket_other->flags: %d\n", socket_other->type );
				sprint( "socket_other->fasync_list: 0x%.8X\n", socket_other->fasync_list );
				sprint( "socket_other->file: 0x%.8X\n", socket_other->file );
				sprint( "socket_other->sk: 0x%.8X\n", socket_other->sk );
				sprint( "socket_other->ops: 0x%.8X\n", socket_other->ops );
				
				
				panic( "socket_other->sk is NULL.\n" );
			}
			
			sock_other = socket_other->sk;
			sprint( "socket_other->sk: 0x%.8X\n", ( unsigned int ) socket_other->sk );
			unix_other = unix_sk( sock_other );
			sprint( "unix_other: 0x%.8X\n", ( unsigned int ) unix_other );
			
			unix_state_lock( sock_other );
			
			sock_hold( sock );
			sprint( "sock: 0x%.8X\n", ( unsigned int ) sock );
			sock_hold( sock_other );
			sprint( "sock_other: 0x%.8X\n", ( unsigned int ) sock_other );
			
			unix->peer = sock_other;
			sprint( "sock_other: 0x%.8X\n", ( unsigned int ) sock_other );
			unix_other->peer = sock;
			sprint( "sock: 0x%.8X\n", ( unsigned int ) sock );
			
			if ( sock->sk_type != SOCK_DGRAM )
			{
				sprint( "sock->sk_type != SOCK_DGRAM\n" );
				
				sock->sk_state = TCP_ESTABLISHED;
				sock_other->sk_state = TCP_ESTABLISHED;
				
				socket->state = SS_CONNECTED;
				socket_other->state = SS_CONNECTED;
			}
			
			unix_state_unlock( sock_other );

		}
		
		sprint( "Before insert_entry( head, saved_unix, socket );\n" );
		if ( !socket->sk )
		{
			sprint( "Before insert_entry().\n" );
			panic( "socket->sk is NULL.\n" );
		}
		
		insert_entry( head, saved_unix, socket );
		sprint( "After insert_entry( head, saved_unix, socket );\n" );
		
		socket_other = find_by_first( head, saved_unix->peer->peer );
		if ( socket_other && !socket_other->sk )
		{
			panic( "socket_other->sk is NULL.\n" );
		}
		//
		
		//
		if ( saved_unix->kind == SOCKET_ACCEPTED )
		{
			sprint( "saved_unix->kind == SOCKET_ACCEPTED\n" );
			
			// Link self addr, dentry, and mnt to that of the listening socket.
			if ( saved_unix->listen )
			{
				sprint( "saved_unix->listen\n" );
				
				sock_other = find_by_first( head, saved_unix->listen );
				if ( !sock_other )
				{
					panic( "Unable to restore UNIX \'accept\' socket before the listening socket.\n" );
				}
				
				unix_other = unix_sk( sock_other );
				
				if ( unix_other->addr )
				{
					sprint( "unix_other->addr\n" );
					
					atomic_inc( &unix_other->addr->refcnt );
					
					unix->addr = unix_other->addr;
				}
				
				if ( unix_other->dentry )
				{
					sprint( "unix_other->dentry\n" );
					
					unix->dentry = dget( unix_other->dentry );
					
					unix->mnt = mntget( unix_other->mnt );
				}
			}
			
			else
			{
				sprint( "else\n" );
				
				unix->addr = kmalloc( sizeof( struct unix_address ) + saved_unix->unix_address.length, GFP_KERNEL );
				if ( !unix->addr )
				{
					panic( "Unable to allocate memory for UNIX \'accept\' socket address.\n" );
				}
				
				// Warning: These two aren't quite correct...
				unix->dentry = NULL;
					
				unix->mnt = NULL;
				//
			}
			//
		}
		
		if ( !socket->sk )
		{
			sprint( "After if ( saved_unix->kind == SOCKET_ACCEPTED ) block.\n" );
			panic( "socket->sk is NULL.\n" );
		}
		//
		
		unix_state_unlock( sock );
	}
	//
	
	// ???
	sprint( "start ???" );
	sock->sk_shutdown = saved_unix->shutdown;
	
	sock->sk_peercred = saved_unix->peercred;
	sprint( "end ???" );
	//
	
	// Restore the receive queue.
	sprint( "Before loop.\n" );
	cur = saved_unix->head;
	
	unix_state_lock( sock );
	
	while ( cur )
	{
		//
		skb = sock_alloc_send_skb( sock, cur->len, 1, &status );
		if ( !skb || status < 0 )
		{
			panic( "Unable to allocate UNIX socket buffer.  Error: %d\n", -status );
		}
		//
		
		//
		sprint( "Before copies.\n" );
		memcpy( skb->cb, cur->cb, sizeof( skb->cb ) );
		
		memcpy( skb_put( skb, cur->len ), cur->data, cur->len );
		
		skb_queue_tail( &sock->sk_receive_queue, skb );
		sprint( "After copies.\n" );
		//
		
		//
		cur = cur->next;
		//
	}
	
	unix_state_unlock( sock );
	
	sprint( "After loop.\n" );
	//
	
	sprint( "##### end restore_unix_socket()\n" );
	
	return;
}

// This is an altered version of the socket() system call in net/socket.c.
struct file *create_socket ( int fd, int flags_additional, int family, int type, int protocol )
{
	//
	struct socket *socket;
	int flags;
	
	int file_fd;
	struct file *file = NULL;
	
	int status = 0;
	//

	//
	BUILD_BUG_ON( SOCK_CLOEXEC != O_CLOEXEC );
	BUILD_BUG_ON( ( SOCK_MAX | SOCK_TYPE_MASK ) != SOCK_TYPE_MASK );
	BUILD_BUG_ON( SOCK_CLOEXEC & SOCK_TYPE_MASK );
	BUILD_BUG_ON( SOCK_NONBLOCK & SOCK_TYPE_MASK );
	//

	//
	flags = type & ~SOCK_TYPE_MASK;
	if ( flags & ~( SOCK_CLOEXEC | SOCK_NONBLOCK ) )
	{
		status = -EINVAL;
	
		goto done;
	}
	type &= SOCK_TYPE_MASK;

	if ( SOCK_NONBLOCK != O_NONBLOCK && ( flags & SOCK_NONBLOCK ) )
	{
		flags = ( flags & ~SOCK_NONBLOCK ) | O_NONBLOCK;
	}
	
	flags |= flags_additional;
	//

	//
	status = sock_create( family, type, protocol, &socket );
	if ( status < 0 )
	{
		goto done;
	}
	//
	
	//
	file_fd = alloc_fd( fd, 0 );
	if ( file_fd < 0 )
	{
		status = file_fd;
	
		goto release;
	}
	else if ( file_fd != fd && fd >= 0 )
	{
		status = -EEXIST;
	
		goto put_fd;
	}
	
	file = get_empty_filp();
	
	status = sock_attach_fd( socket, file, flags );
	if ( status < 0 )
	{
		goto put_file;
	}
	
	fd_install( file_fd, file );
	//
	
	goto done;
	
put_file:
	put_filp( file );
	file = NULL;
	
put_fd:
	put_unused_fd( file_fd );
	
release:
	sock_release( socket );
	
done:
	if ( status < 0 )
	{
		file = ERR_PTR( status );
	}

	return file;
}
//

// This is an altered version of the bind() system call in net/socket.c.
int bind_socket ( struct file *file, struct sockaddr *address, int address_length )
{
	//
	struct socket *socket;
	int status = 0;
	//
	
	//
	if ( !file || !file->private_data || !address || address_length < 0 )
	{
		status = -EINVAL;
		
		goto done;
	}
	
	socket = file->private_data;
	//

	//
	status = security_socket_bind( socket, address, address_length );
	if ( !status )
	{
		status = socket->ops->bind( socket, address, address_length );
	}
	//
	
done:
	return status;
}
//

// This is an altered version of the listen() system call in net/socket.c.
int listen_socket ( struct file *file, int backlog )
{
	//
	struct socket *socket;

	int somaxconn;
	
	int status = 0;
	//
	
	//
	if ( !file || !file->private_data )
	{
		status = -EINVAL;
		
		goto done;
	}
	
	socket = file->private_data;
	//

	//
	somaxconn = sock_net( socket->sk )->core.sysctl_somaxconn;
	if ( ( unsigned ) backlog > somaxconn )
	{
		backlog = somaxconn;
	}

	status = security_socket_listen( socket, backlog );
	if ( !status )
	{
		status = socket->ops->listen( socket, backlog );
	}
	//
	
done:
	return status;
}
//

// This is an altered version of do_unlinkat() in fs/namei.c.
int unlink_file ( char *path )
{
	//
	int error;
	struct dentry *dentry;
	struct nameidata nd;
	struct inode *inode = NULL;
	//

	/*error = user_path_parent(dfd, pathname, &nd, &name);
	if (error)
		return error;*/
	
	//
	if ( !path )
	{
		return -EINVAL;
	}
	
	error = path_lookup( path, LOOKUP_PARENT, &nd );
	if ( error < 0 )
	{
		return error;
	}
	//

	error = -EISDIR;
	if (nd.last_type != LAST_NORM)
		goto exit1;

	nd.flags &= ~LOOKUP_PARENT;

	mutex_lock_nested(&nd.path.dentry->d_inode->i_mutex, I_MUTEX_PARENT);
	dentry = lookup_hash(&nd);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		/* Why not before? Because we want correct error value */
		if (nd.last.name[nd.last.len])
			goto slashes;
		inode = dentry->d_inode;
		if (inode)
			atomic_inc(&inode->i_count);
		error = mnt_want_write(nd.path.mnt);
		if (error)
			goto exit2;
		error = security_path_unlink(&nd.path, dentry);
		if (error)
			goto exit3;
		error = vfs_unlink(nd.path.dentry->d_inode, dentry);
exit3:
		mnt_drop_write(nd.path.mnt);
	exit2:
		dput(dentry);
	}
	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	if (inode)
		iput(inode);	/* truncate the inode here */
exit1:
	path_put(&nd.path);
	return error;

slashes:
	error = !dentry->d_inode ? -ENOENT :
		S_ISDIR(dentry->d_inode->i_mode) ? -EISDIR : -ENOTDIR;
	goto exit2;
}
//

// The function set_owner() is an altered version of the chown() system call in fs/open.c.
static int chown_common ( struct path *path, uid_t user, gid_t group )
{
	struct inode *inode = path->dentry->d_inode;
	int error;
	struct iattr newattrs;

	newattrs.ia_valid =  ATTR_CTIME;
	if (user != (uid_t) -1) {
		newattrs.ia_valid |= ATTR_UID;
		newattrs.ia_uid = user;
	}
	if (group != (gid_t) -1) {
		newattrs.ia_valid |= ATTR_GID;
		newattrs.ia_gid = group;
	}
	if (!S_ISDIR(inode->i_mode))
		newattrs.ia_valid |=
			ATTR_KILL_SUID | ATTR_KILL_SGID | ATTR_KILL_PRIV;
	mutex_lock(&inode->i_mutex);
	error = security_path_chown(path, user, group);
	if (!error)
		error = notify_change(path->dentry, &newattrs);
	mutex_unlock(&inode->i_mutex);

	return error;
}

int set_owner ( char *path, uid_t user, gid_t group )
{
	//
	struct nameidata nd;
	struct path patho;
	
	int error = 0;
	//

	//
	error = path_lookup( path, LOOKUP_FOLLOW, &nd );
	if ( error < 0 )
	{
		goto done;
	}
	
	patho = nd.path;
	
	error = mnt_want_write( patho.mnt );
	if ( error < 0 )
	{
		goto put_path;
	}
	error = chown_common( &patho, user, group );
	mnt_drop_write( patho.mnt );
	//
	
	//
put_path:
	path_put( &patho );
done:
	return error;
	//
}
//

// Warning: This function is right now only called for VC terminals.
static void restore_fown_struct ( struct saved_file *saved_file, struct file *file )
{
	//
	struct pid *pid;
	//
	
	//
	rcu_read_lock();
	
	security_file_set_fowner( file );
	
	pid = find_vpid( saved_file->owner.pid );
	if ( !pid && saved_file->owner.pid )
	{
		panic( "Unable to restore file's \'struct fown_struct\' due to missing \'struct pid\' of pid %d\n", saved_file->owner.pid );
	}
	
	write_lock_irq( &file->f_owner.lock );
	
	put_pid( file->f_owner.pid );
	file->f_owner.pid = get_pid( pid );
	file->f_owner.pid_type = saved_file->owner.pid_type;
	file->f_owner.uid = saved_file->owner.uid;
	file->f_owner.euid = saved_file->owner.euid;
	file->f_owner.signum = saved_file->owner.signum;
	
	write_unlock_irq( &file->f_owner.lock );
	
	rcu_read_unlock();
	//
	
	return;
}
//

// This is an altered version of the combination of set_termios(), 
// change_termios(), and unset_locked_termios() in drivers/char/tty_ioctl.c.
int set_termios ( struct tty_struct *tty, struct ktermios *kterm )
{
	//
	struct tty_ldisc *ld;
	
	int i;
	
	struct ktermios old_kterm;
	unsigned long flags;
	
	int retval = 0;
	//

	//
	if ( !tty || !kterm )
	{
		return -EINVAL;
	}
	
	retval = tty_check_change( tty );
	if ( retval )
	{
		return retval;
	}
	//

	//
	ld = tty_ldisc_ref( tty );
	if ( ld )
	{
		tty_ldisc_deref( ld );
	}
	//

	//
	mutex_lock( &tty->termios_mutex );
	
	old_kterm = *tty->termios;
	*tty->termios = *kterm;
	
	//
	if ( tty->termios_locked )
	{
		NOSET_MASK( tty->termios->c_iflag, old_kterm.c_iflag, tty->termios_locked->c_iflag );
		NOSET_MASK( tty->termios->c_oflag, old_kterm.c_oflag, tty->termios_locked->c_oflag );
		NOSET_MASK( tty->termios->c_cflag, old_kterm.c_cflag, tty->termios_locked->c_cflag );
		NOSET_MASK( tty->termios->c_lflag, old_kterm.c_lflag, tty->termios_locked->c_lflag );
		tty->termios->c_line = tty->termios_locked->c_line ? old_kterm.c_line : tty->termios->c_line;
		for ( i = 0; i < NCCS; i++ )
		{
			tty->termios->c_cc[i] = tty->termios_locked->c_cc[i] ? old_kterm.c_cc[i] : tty->termios->c_cc[i];
		}
	}
	//

	// See if packet mode change of state.
	if ( tty->link && tty->link->packet )
	{
		int old_flow = ((old_kterm.c_iflag & IXON) &&
				(old_kterm.c_cc[VSTOP] == '\023') &&
				(old_kterm.c_cc[VSTART] == '\021'));
		int new_flow = (I_IXON(tty) &&
				STOP_CHAR(tty) == '\023' &&
				START_CHAR(tty) == '\021');
		if ( old_flow != new_flow )
		{
			//
			spin_lock_irqsave( &tty->ctrl_lock, flags );
			
			tty->ctrl_status &= ~( TIOCPKT_DOSTOP | TIOCPKT_NOSTOP );
			if ( new_flow )
			{
				tty->ctrl_status |= TIOCPKT_DOSTOP;
			}
			else
			{
				tty->ctrl_status |= TIOCPKT_NOSTOP;
			}
			
			spin_unlock_irqrestore( &tty->ctrl_lock, flags );
			//
			
			wake_up_interruptible( &tty->link->read_wait );
		}
	}

	if ( tty->ops->set_termios )
	{
		tty->ops->set_termios( tty, &old_kterm );
	}
	else
	{
		tty_termios_copy_hw( tty->termios, &old_kterm );
	}

	ld = tty_ldisc_ref( tty );
	if ( ld )
	{
		if ( ld->ops->set_termios )
		{
			ld->ops->set_termios( tty, &old_kterm );
		}
		tty_ldisc_deref( ld );
	}
	
	mutex_unlock( &tty->termios_mutex );
	//

	return 0;
}
//

