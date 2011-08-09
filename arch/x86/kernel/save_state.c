#include <linux/signal.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/syscalls.h>
#include <asm/linkage.h>
#include <asm/pgtable.h>
#include <linux/bootmem.h>
#include <linux/ioport.h>
#include <asm/e820.h>
#include <linux/fdtable.h>
#include <linux/pipe_fs_i.h>
#include <linux/tty.h>
#include <linux/kd.h>
#include <linux/console_struct.h>
#include <linux/console.h>
#include <net/inet_sock.h>
#include <net/inet_connection_sock.h>
#include <linux/net.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/fb.h>
#include <linux/vt.h>
#include <linux/set_state.h>
#include <linux/major.h>

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/limits.h>
#include <linux/vmalloc.h>
#include <linux/vt_kern.h>

#include <linux/mousedev.h>
#include <linux/skbuff.h>

static void get_path_absolute ( struct file *file, char *path );

static struct saved_fb_info *save_fb_info ( struct fb_info *info );
static char *save_fb_contents ( struct fb_info *info );
static struct fb_con2fbmap *save_con2fbmaps ( struct fb_info *info );
static int file_is_fb ( struct file *file );
static void save_fb ( struct file *file, struct saved_file *saved_file, struct map_entry *head );
/*static void save_fbs ( void );
static void restore_fbs ( void );
static void save_con2fbmaps ( void );
static void restore_con2fbmaps ( void );*/

static int file_is_mouse ( struct file *file );
static void save_mouse ( struct file *file, struct saved_file *saved_file );

static int file_is_unix_socket ( struct file *file );
static void save_unix_socket ( struct file *file, struct saved_file *saved_file, struct map_entry *head );

static int fr_reboot_notifier(struct notifier_block*, unsigned long, void*);
static struct notifier_block fr_notifier = {
  .notifier_call = fr_reboot_notifier,
    .next = NULL,
    .priority=INT_MAX
    };

unsigned long get_reserved_region(void)
{
	void* region;
	struct page* page = pfn_to_page(FASTREBOOT_REGION_START >> PAGE_SHIFT);
//  printk( "Page desc of region is %p\n", page);
	region = lowmem_page_address(page);//kmap(page);
//  sprint( "kmap returned %p\n", region);
	//kunmap(page);
	return (unsigned long)region;
}
//

static unsigned int allocated = 0;
static void* alloc(size_t size)
{
	void* ret;
//	sprint( "Need to allocate: %u, already allocated %u\n", size, allocated);
	if(allocated + size > FASTREBOOT_REGION_SIZE) return NULL;
	
	ret = (void*)(get_reserved_region() + allocated);
	allocated += size;
//	sprint( "Allocated chunk starts at %p\n", ret);
	memset(ret, 0, size);
	return ret;
}

static int reserve(unsigned long start, unsigned long size)
{
//	reserve_early(start, start+size, "SAVED_STATE_RESERVE");
	return reserve_bootmem(start, size, BOOTMEM_EXCLUSIVE);
}

// This function appears to reserve the pages that were used by all of the "saved"
// processes.
static void reserve_process_memory(struct saved_task_struct* task)
{
	struct shared_resource* elem;
	struct saved_task_struct* child;
	sprint("Reserving for task %s[%d]\n", task->name, task->pid);
	for(elem=task->mm->pages; elem!=NULL; elem=elem->next)
	{
		struct saved_page* page = (struct saved_page*)elem->data;
		int err;
		err = reserve(page->pfn << PAGE_SHIFT, PAGE_SIZE);
		if(err < 0)
		{
			sprint("Failed to reserve pfn: %ld, err: %d\n", page->pfn, err);
		}
		else
		{
			sprint("Reserved pfn: %ld\n", page->pfn);
		}
	}

	list_for_each_entry(child, &task->children, sibling)
	{
		reserve_process_memory(child);
	}

}
//

// This function just calls reserve_process_memory() for each of the saved tasks.
void reserve_saved_memory(void)
{
	struct saved_task_struct* task;
	struct saved_state* state = (struct saved_state*)get_reserved_region();

	if(state->processes == NULL)
	{
		sprint( "No state saved\n");
		return;
	}
	for(task = state->processes; task != NULL; task = task->next)
	{
		reserve_process_memory(task);

	}
}
//


static pte_t* get_pte(struct mm_struct* mm, unsigned long virtual_address)
{
	pgd_t* pgd;
	pud_t* pud;
	pmd_t* pmd;
	pte_t* pte;
	
	
	pgd = pgd_offset(mm, virtual_address);
	if(pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return NULL;
	}
	if(!pgd_present(*pgd))
	{
		return NULL;
	}
	
	pud = pud_offset(pgd, virtual_address);
	if(pud_none(*pud) || pud_bad(*pud))
	{
		return NULL;
	}
	
	pmd = pmd_offset(pud, virtual_address);
	if(pmd_none(*pmd) || pmd_bad(*pmd))
	{
		return NULL;
	}

	pte = pte_offset_map(pmd, virtual_address);
	return pte;
  

}

static int get_physical_address(struct mm_struct* mm, unsigned long virtual_address, unsigned long* physical_address)
{
	struct page* page;
	pte_t* pte;
	pte = get_pte(mm, virtual_address);
	if(!pte || !pte_present(*pte))
	{
		return 0;
	}
	
	page = pte_page(*pte);
	*physical_address = (page_to_pfn(page) << PAGE_SHIFT);
	pte_unmap(pte);
	return 1;
}


static void save_pages(struct saved_mm_struct* mm, struct vm_area_struct* area, struct map_entry* head)
{
	unsigned long virtual_address;
	for(virtual_address = area->vm_start; virtual_address < area->vm_end; virtual_address+=PAGE_SIZE)
	{
		unsigned long physical_address;
		struct saved_page* page;
		struct page* p;

		struct shared_resource* elem;

		if(!get_physical_address(area->vm_mm, virtual_address, &physical_address))
		{
			continue;
		}

		// pfn_to_page() takes a page frame number and returns a struct page object.
		//
		// The page frame number and its map count is backed up into the saved_page
		// object.
		p = pfn_to_page(physical_address >> PAGE_SHIFT);
		page = (struct saved_page*)find_by_first(head, p);
		if(page && page_mapcount(p) != 0)
		{
			page->mapcount += 1;
		}
		else if(page == NULL)
		{
			page = (struct saved_page*)alloc(sizeof(*page));
			page->pfn = page_to_pfn(p);
			page->mapcount = page_mapcount(p) > 0 ? 1 :0;
			insert_entry(head, p, page);
		}
		//

		// mm->pages appears to be a pointer to a singly-linked list of
		// shared_resource objects, whose data pointers each point to a single
		// struct saved_page object.
		elem = (struct shared_resource*)alloc(sizeof(*elem));
		elem->data = page;
		elem->next = mm->pages;
		mm->pages = elem;
	}
}

void print_regs(struct pt_regs* regs)
{
	sprint( "ax: %08lx bx: %08lx cx: %08lx dx: %08lx\n", regs->ax, regs->bx, regs->cx, regs->dx);
	sprint( "si: %08lx di: %08lx bp: %08lx sp: %08lx\n", regs->si, regs->di, regs->bp, regs->sp);
	sprint( "ds: %08lx es: %08lx fs: %08lx cs: %08lx ss:  %08lx\n", regs->ds, regs->es, regs->fs, regs->cs, regs->ss);
	sprint( "orig_ax: %08lx ip: %08lx flags: %08lx\n", regs->orig_ax, regs->ip, regs->flags);
}

static void save_pgd(struct mm_struct* mm, struct saved_mm_struct* saved_mm, struct map_entry* head)
{
	int i;
	// 1024 pgds in total, but only copy the first 3/4, the rest belong to the kernel
	clone_pgd_range(saved_mm->pgd, mm->pgd, 3*256);
	for(i = 0; i<3*256; i++)
	{
		struct saved_page* page;

		// What is the if statement doing?
		struct page* p;
		struct shared_resource* elem;
		pgd_t pgd = mm->pgd[i];
		if(pgd.pgd == 0 || pgd_bad(pgd) || !pgd_present(pgd))
			continue;
		//
		
		// pgd.pgd is a pointer to a page in the PTE containing pointers
		// to a physical page?
		elem = (struct shared_resource*)alloc(sizeof(*elem));
		p = pfn_to_page(pgd.pgd >> 12);

		// If the page has not been encountered before, then "insert" it into the
		// list containing the map_entry objects.
		//
		// In both blocks, the data pointer in elem is set to point to the
		// saved_page object called page.
		page = find_by_first(head, p);
		if(page == NULL)
		{
			page = (struct saved_page*)alloc(sizeof(*page));
			page->pfn = page_to_pfn(p);
			if(page_mapcount(p) != 0) panic("Expected 0 mapcount on pgd page\n");
			page->mapcount = 0;
			elem->data = page;
			insert_entry(head, p, page);
		}
		else
		{
			if(page_mapcount(p) != 0) panic("Expected 0 mapcount on pgd page\n");
			elem->data = page;
		}
		//

		// Appears to be inserting a new shared_resource object, which has an
		// associated saved_page object, into a singly-linked list pointed to
		// by saved_mm->pages.
		elem->next = saved_mm->pages;
		saved_mm->pages = elem;
		//


     	}
	sprint( "Saved pgd\n");
}


static void reverse_string(char* begin, char* end)
{
	end -= 1;
	while(begin < end)
	{
		char t = *begin;
		*begin = *end;
		*end = t;
		begin++;
		end--;
	}
}

/*static void get_file_path(struct file* f, char* filename)
{
	struct dentry* cur;
	char* begin, *end;

	// Store associated dentry object pointer into cur.
	cur = f->f_path.dentry;
	//

	while(1)
	{
		if(!cur->d_name.name) panic("dentry did not have a name");
		if(cur == cur->d_parent) break;
		strcat(filename, cur->d_name.name);
		strcat(filename, "/");
		cur = cur->d_parent;
	}
	reverse_string(filename, filename+strlen(filename));
	begin = strchr(filename, '/')+1;
	end = strchr(begin+1, '/');
	while(end != NULL)
	{
		reverse_string(begin, end);
		begin = end+1;
		end=strchr(begin+1, '/');
	}
	end = filename + strlen(filename);
	reverse_string(begin, end);
}*/

static void get_path_absolute ( struct file *file, char *path )
{
	//
	struct dentry *dentry = file->f_dentry;
	struct vfsmount *vfsmount = file->f_vfsmnt;
	
	struct dentry **elements;
	//static struct dentry *elements[PATH_MAX];
	int index = 0;
	//
	
	sprint( "##### start get_path_absolute()\n" );
	
	//
	sprint( "Before vmalloc().\n" );
	
	elements = ( struct dentry ** ) vmalloc( PATH_MAX * sizeof( struct dentry * ) );
	if ( !elements )
	{
		panic( "Unable to allocate memory in function get_path_absolute().\n" );
	}
	
	sprint( "After vmalloc().\n" );
	//
	
	sprint( "Before.\n" );
	
	//
	spin_lock( &dentry->d_lock );
	if ( strcmp( dentry->d_name.name, "/" ) == 0 )
	{
		strcpy( path, "/" );
		
		spin_unlock( &dentry->d_lock );
		
		goto free;
	}
	spin_unlock( &dentry->d_lock );
	//
	
	sprint( "After.\n" );
	
	//
	index = 0;
	
	do
	{
		elements[index] = dentry;
		index++;
	
		dentry = dentry->d_parent;
		if ( IS_ROOT( dentry ) )
		{
			dentry = vfsmount->mnt_mountpoint;
			vfsmount = vfsmount->mnt_parent;
		}
	}
	while ( !IS_ROOT( dentry ) );
	
	//elements[index] = dentry;
	index--;
	//
	
	//
	strcpy( path, "" );
	
	while ( index >= 0 )
	{
		strcat( path, "/" );
		
		spin_lock( &elements[index]->d_lock );
		strcat( path, elements[index]->d_name.name );
		spin_unlock( &elements[index]->d_lock );
		
		index--;
	}
	//
	
	//
free:
	vfree( elements );
	
//done:
	sprint( "path: \"%s\"\n", path );
	sprint( "##### end get_path_absolute()\n" );
	return;
	//
}

// This function is an altered version of do_unlinkat() in the file fs/namei.c.
/*static int unlink_file ( char *path )
{
	//
	int dfd = AT_FDCWD;
	
	int error;
	char *name;
	struct dentry *dentry;
	struct nameidata nd;
	struct inode *inode = NULL;
	//

	//error = user_path_parent(dfd, pathname, &nd, &name);
	//if (error)
	//	return error;
	// 
	if ( !path )
	{
		return -EINVAL;
	}
	
	error = do_path_lookup( dfd, path, LOOKUP_PARENT, &nd );
	if ( error )
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
		// Why not before? Because we want correct error value 
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
		iput(inode);	// truncate the inode here
exit1:
	path_put(&nd.path);
	putname(name);
	return error;

slashes:
	error = !dentry->d_inode ? -ENOENT :
		S_ISDIR(dentry->d_inode->i_mode) ? -EISDIR : -ENOTDIR;
	goto exit2;
}*/
//

static bool file_is_pipe(struct file* f)
{
	struct inode *inode = f->f_path.dentry->d_inode;
	struct pipe_inode_info *pipe =  f->f_path.dentry->d_inode->i_pipe;
	if (inode != NULL && pipe != NULL)
	{
		if (S_ISFIFO(inode->i_mode))
		{
			//sprint( "##### File is a pipe.\n" );
		
			return true;
		}
		else
		{
			return false;
		}
	}

	return false;
}

static void save_pipe_info(struct saved_task_struct* task, struct file* f, struct saved_file* file, struct map_entry* head)
{
	// file_is_pipe check already checks if pipe is null, so we don't need null check here
	int i = 0;
	struct pipe_inode_info *pipe = f->f_path.dentry->d_inode->i_pipe;

	// Assign pipe filetype (unnamed vs named, read vs write end)
	if (file->name[0] == '/' && file->name[1] == '\0') // Unnamed pipes have no path
	{
		if (f->f_flags & O_WRONLY)
			file->type = WRITE_PIPE_FILE;
		else
			file->type = READ_PIPE_FILE;
	}
	else
	{
		if (f->f_flags & O_WRONLY)
			file->type = WRITE_FIFO_FILE;
		else
			file->type = READ_FIFO_FILE;
	}
	file->pipe.nrbufs = pipe->nrbufs;
	file->pipe.curbuf = pipe->curbuf;
	// Copying inode only as a unique identifier for the pipe pair
	file->pipe.inode = pipe->inode; 

	// Save pipe buffers
	for (i=0; i < PIPE_BUFFERS; i++)
	{
		file->pipe.bufs[i].page = pipe->bufs[i].page;
		file->pipe.bufs[i].offset = pipe->bufs[i].offset;
		file->pipe.bufs[i].len = pipe->bufs[i].len;

		// If buffer page exists, reserve it
		if (pipe->bufs[i].page != 0)
		{
			struct page* p = pipe->bufs[i].page;
			struct saved_page* page_to_save;

			// Reserve the page only if it's not already reserved
			page_to_save = (struct saved_page*)find_by_first(head, p);
			if (page_to_save == NULL)
			{
				struct shared_resource* elem;
				page_to_save = (struct saved_page*)alloc(sizeof(*page_to_save));
				page_to_save->pfn = page_to_pfn(p);
				page_to_save->mapcount = page_mapcount(p) > 0 ? 1 :0;
				insert_entry(head, p, page_to_save);

				elem = (struct shared_resource*)alloc(sizeof(*elem));
				elem->data = page_to_save;
				elem->next = task->mm->pages;
				task->mm->pages = elem;
			}
		}
	}
}

// This does not return true for all "consoles"...
static int file_is_vc_terminal ( struct file *file )
{
	//I am cheating for now and assuming /tty1 or /console are the terminals I want
	/*if(!strcmp("/tty1", name) || !strcmp("/console", name))
	{
		//sprint( "##### File is a terminal.\n" );
	
		return 1;
	}
	else
	{
		return 0;
	}*/
	
	struct inode *inode = file->f_dentry->d_inode;
	int major = MAJOR( inode->i_rdev );
	int minor = MINOR( inode->i_rdev );
	
	return ( major == TTY_MAJOR && ( 1 <= minor && minor <= MAX_NR_CONSOLES ) || major == TTYAUX_MAJOR && minor == 1 );
}
//

// Warning: This function does not save everything that should be saved.
static void save_vc_term_info(struct file* f, struct saved_file* file)
{
	struct tty_struct* tty;
	struct tty_driver* driver;
	struct vc_data* vcd;
	struct saved_vc_data* svcd;
	unsigned char* screen_buffer;
	
	tty = (struct tty_struct*)f->private_data;
	//sprint("tty private data %p\n", tty);
	if(tty->magic != TTY_MAGIC)
	{
		panic("tty magic does not match expected: %x, got: %x\n", TTY_MAGIC, tty->magic);
	}
	driver = tty->driver;
	if(driver->type != TTY_DRIVER_TYPE_CONSOLE || driver->subtype !=0)
	{
		panic("Driver type was not a console type\n");
	}

	vcd = (struct vc_data*)tty->driver_data;
	//sprint("driver data %p\n", vcd);
	svcd = (struct saved_vc_data*)alloc(sizeof(*svcd));
	svcd->index = vcd->vc_num;
	svcd->rows = vcd->vc_rows;
	svcd->cols = vcd->vc_cols;
	svcd->x = vcd->vc_x;
	svcd->y = vcd->vc_y;
	svcd->screen_buffer_size = vcd->vc_screenbuf_size;
	screen_buffer = (unsigned char*)alloc(svcd->screen_buffer_size);
	
	//sprint("Copy screen state\n");
	//vcd->vc_sw->con_save_screen(vcd);	// vcd->vc_sw->con_save_screen is NULL...
	memcpy(screen_buffer, vcd->vc_screenbuf, svcd->screen_buffer_size);
	svcd->screen_buffer = screen_buffer;
	file->type = VC_TTY;
	file->vcd = svcd;
	
	//
	svcd->v_active = fg_console + 1;
	
	svcd->vt_mode = vcd->vt_mode;
	
	svcd->vc_mode = vcd->vc_mode;
	//

	sprint("Saved terminal state\n");
	
}

extern struct file_operations socket_file_ops;
static bool file_is_socket(struct file* file)
{
	sprint("f_op is %p, expecting %p\n", file->f_op, &socket_file_ops);
	if (file->f_op == &socket_file_ops)
	{
		//sprint( "##### File is a socket.\n" );
	
		return true;
	}
	else
		return false;
}

static bool should_be_saved(struct file* file)
{
	struct socket* sock;
	struct sock* sk;
	if(!file_is_socket(file))
		return true;

	sock = (struct socket*)file->private_data;
	sk = sock->sk;

	if(sk->sk_state != TCP_LISTEN)
	{
		return true;
	}
	else
	{
		sprint("Skipping listen socket\n");
		return false;
	}
}

static void save_tcp_state(struct saved_file* file, struct socket* sock)
{
	struct sock* sk = sock->sk;
	struct inet_sock* inet = inet_sk(sk);
	struct inet_connection_sock* icsk = inet_csk(sk);
	struct tcp_sock* tp = tcp_sk(sk);
	struct saved_tcp_state* saved_tcp = (struct saved_tcp_state*)alloc(sizeof(struct saved_tcp_state));
	struct dst_entry* dst = __sk_dst_get(sk);

	sprint("Getting lock\n");
	lock_sock(sk);
	sprint("Got lock\n");
	file->socket.tcp = saved_tcp;

	saved_tcp->state = sk->sk_state;
	saved_tcp->backlog = sk->sk_max_ack_backlog;
	saved_tcp->daddr = inet->daddr;
	saved_tcp->dport = ntohs(inet->dport);
	saved_tcp->saddr = inet->saddr;
	saved_tcp->sport = ntohs(inet->sport);

	saved_tcp->rcv_mss = icsk->icsk_ack.rcv_mss;

	saved_tcp->rcv_nxt = tp->rcv_nxt;
	saved_tcp->rcv_wnd = tp->rcv_wnd;
	saved_tcp->rcv_wup = tp->rcv_wup;
	saved_tcp->snd_nxt = tp->snd_nxt;

	saved_tcp->snd_una = tp->snd_una;
	saved_tcp->snd_wl1 = tp->snd_wl1;
	saved_tcp->snd_wnd = tp->snd_wnd;
	saved_tcp->max_window = tp->max_window;
	saved_tcp->mss_cache = tp->mss_cache;

	saved_tcp->window_clamp = tp->window_clamp;
	saved_tcp->rcv_ssthresh = tp->rcv_ssthresh;
	saved_tcp->advmss = tp->advmss;
	saved_tcp->rcv_wscale = tp->rx_opt.rcv_wscale;

	saved_tcp->write_seq = tp->write_seq;
	saved_tcp->copied_seq = tp->copied_seq;

	saved_tcp->pred_flags = tp->pred_flags;
	saved_tcp->tcp_header_len = tp->tcp_header_len;
	
}

/*static void save_unix_state ( struct saved_file *saved_file, struct socket *socket )
{
	//
	//
	
	//
	//
}*/

static void save_socket_info(struct saved_task_struct* task, struct file* f, struct saved_file* file, struct map_entry* head)
{
	//
	struct socket *sock = f->private_data;
	struct sock *sk = sock->sk;
	
	struct inet_sock *inet;
	//struct unix_sock *unix;
	//
	
	//
	file->type = SOCKET;
	
	file->socket.type = sock->type;
	file->socket.state = sock->state;
	file->socket.flags= sock->flags;
	file->socket.wait = sock->wait;
	file->socket.sock_protocol = sk->sk_protocol; 
	file->socket.sock_type = sk->sk_type;
	file->socket.sock_family = sk->sk_family;
	file->socket.backlog = sk->sk_max_ack_backlog;
	
	file->socket.userlocks = sk->sk_userlocks;
	
	if(f->f_flags & O_NONBLOCK)
		file->flags |= O_NONBLOCK;

	file->socket.binded = 0;
	if(sk->sk_userlocks)
		file->socket.binded = 1;
	//
	
	//
	switch ( file->socket.sock_family )
	{
		case AF_INET:
			inet = inet_sk( sk );
	
			file->socket.inet.daddr = inet->daddr;
			file->socket.inet.rcv_saddr = inet->rcv_saddr;
			file->socket.inet.dport = inet->dport;
			file->socket.inet.saddr = inet->saddr;
			file->socket.inet.num = inet->num;
			file->socket.inet.sport = inet->sport;
			
			if ( file->socket.sock_type == SOCK_STREAM )
			{
				sprint( "Saving TCP socket.\n" );
				
				save_tcp_state( file, sock );
			}
			
			break;
			
		case AF_UNIX:
			sprint( "Saving UNIX socket.\n" );
			
			save_unix_socket( f, file, head );
			
			break;
	}
	//
	
	return;
}


static void save_files(struct files_struct* files, struct saved_task_struct* task, struct map_entry* head)
{
	// fdtable is the file descriptor table.
	struct fdtable* fdt;
	unsigned int fd;
	
	struct saved_file *saved_last = NULL;
	//

	// spin_lock() is used to lock the files?
	// This obtains the file descriptor table of the process?
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	//
	
	// Back up some information in the file descriptors into the saved_task_struct
	// object.
	//sprint("max_fds: %d\n", fdt->max_fds);
	for(fd=0; fd<fdt->max_fds; fd++)
	{
	  	// fcheck_files() obtains the file descriptor with index fd.
		struct saved_file* file;
		struct file* f = fcheck_files(files, fd);
		//

//		sprint("Bit set: %s\n", FD_ISSET(fd, fdt->open_fds) ? "yes" : "no");

		// If file descriptor does not exist, then move on to finding the next
		// file descriptor; otherwise, copy over some things.
		if(f == NULL)
			continue;

		//if(!should_be_saved(f))
		//	continue;

		file = (struct saved_file*)alloc(sizeof(*file));
		get_path_absolute(f, file->name);
		sprint("fd %d points to %s\n", fd, file->name);
		file->fd = fd;
		file->count = file_count(f);
		//
		
		//
		/*if(f->f_mode & FMODE_READ)
		{
			file->flags = O_RDONLY;
		}
		if(f->f_mode & FMODE_WRITE)
		{
			file->flags = O_WRONLY;
		}

		if((f->f_mode & FMODE_READ) && (f->f_mode & FMODE_WRITE))
		{
			file->flags = O_RDWR;
		}*/
		
		file->flags = f->f_flags;
		file->f_pos = f->f_pos;
		//

		// The first three if and/or else if blocks identify what kind of file the
		// file is and also saves some other information that is specific to that
		// kind of file...
		//
		// The last two lines inserts the saved_file object into the
		// singly-linked list pointed to by task->open_files.
		if(file_is_vc_terminal(f))
		{
			sprint( "fd %d is a terminal.\n", fd );
			
			save_vc_term_info(f, file);
		}
		else if (file_is_pipe(f))
		{
			sprint( "fd %d is a pipe.\n", fd );
			
			save_pipe_info(task, f, file, head);
		}
		else if (file_is_socket(f))
		{
			sprint( "fd %d is a socket.\n", fd );
			
		  	save_socket_info(task, f, file, head);
		}
		else if ( file_is_fb( f ) )
		{
			sprint( "fd %d is a framebuffer.\n", fd );
			
			save_fb( f, file, head );
		}
		else if ( file_is_mouse( f ) )
		{
			sprint( "fd %d is a mouse.\n", fd );
			
			save_mouse( f, file );
		}
		//file->next = task->open_files;
		//task->open_files = file;
		
		// Warning: The below is not a good/permanent solution
		// for getting listening sockets to be restored before accept sockets.
		if ( !saved_last )
		{
			task->open_files = file;
		}
		
		else
		{
			saved_last->next = file;
		}
		
		file->next = NULL;
		saved_last = file;
		//
	}
	spin_unlock(&files->file_lock);
	//
}


struct save_state_permission
{
	pid_t pid;
	struct save_state_permission* next;
};

static struct save_state_permission* save_permitted;
static struct save_state_permission* state_restored; 

static void save_signals(struct task_struct* task, struct saved_task_struct* state)
{
  	// i is for...?
  	//
  	// sighand is a temporary pointer to a signal handler...
	//
  	// pending is a temporary object that holds the bits that indicate
	// which signals are pending.
  	//
	// tmp is...?
  	//
  	// blocked is a temporary pointer to an object that holds the bits that indicate
	// which signals are blocked.
	int i;
	struct sighand_struct* sighand = task->sighand;
	sigset_t pending;
	struct sigpending* tmp;
	sigset_t* blocked;
	//

	// sighand might stand for signals handler.
	//
	// The sighand member is of type struct sighand_struct.
	//
	// state->sighand.blocked = task->blocked copies over the set bits that are
	// indicating which signals are blocked?
	//
	// state->sighand.pending = task->pending.signal copies over the the set bits
	// that are indicating which signals are pending?
	//
	// state->sighand.shared_pending = task->signal->shared_pending.signal copies over
	// the set bits that are indicating which signals are pending for a thread group.
	sigemptyset(&pending);
	spin_lock_irq(&sighand->siglock);
	for(i = 0; i<_NSIG; i++)
	{
		state->sighand.action[i] = sighand->action[i];
	}
	state->sighand.blocked = task->blocked;
	state->sighand.pending = task->pending.signal;
	state->sighand.shared_pending = task->signal->shared_pending.signal;
	//

	// Isn't task->pending.list supposed to be a head pointer to a doubly-linked list
	// of sigqueue data structures?  How come the code below is obtaining sigpending
	// objects from the list?
	list_for_each_entry(tmp, &task->pending.list, list)
	{
		sigorsets(&pending, &pending, &tmp->signal);
		//sprint("Checking current->pending\n");
	}  

	list_for_each_entry(tmp, &task->signal->shared_pending.list, list)
	{
		sigorsets(&pending, &pending, &tmp->signal);
 		//sprint("Checking current->signal->shared_pending\n");
	}
	//


	state->sighand.state = task->state;

	// ???
	switch(task_pt_regs(task)->orig_ax)
	{
	case 179:    // sigsuspend
		blocked  = (sigset_t*)alloc(sizeof(*blocked));
		sprint("Saving state to restart sigsuspend upon reboot\n");
		state->syscall_restart = task_pt_regs(task)->orig_ax;
		*blocked = task->saved_sigmask;
		state->syscall_data = blocked;
		break;
	case 4:    // write
	case 102:  // socketcall
	case 162:  // nanosleep
	case 240:  // futex
	case 7:    // waitpid
	case 114:  // wait4
	case 142: // select
		state->syscall_restart = task_pt_regs(task)->orig_ax;
		sprint("Saving state to restore %d syscall\n", state->syscall_restart);
		state->syscall_data = NULL;
		break;
	default:
		state->syscall_restart = task_pt_regs(task)->orig_ax;
		break;
	}
	//

	spin_unlock_irq(&sighand->siglock);
}

static void save_creds(struct task_struct* task, struct saved_task_struct* state)
{
	const struct cred *cred;
	
	rcu_read_lock();
	
	cred = __task_cred(task);

	state->uid = cred->uid;
	state->euid = cred->euid;
	state->suid = cred->suid;
	state->fsuid = cred->fsuid;

	state->gid = cred->gid;
	state->egid = cred->egid;
	state->sgid = cred->sgid;
	state->fsgid = cred->fsgid;

	state->cap_effective = cred->cap_effective;
	state->cap_inheritable = cred->cap_inheritable;
	state->cap_permitted = cred->cap_permitted;
	state->cap_bset = cred->cap_bset;
	
	rcu_read_unlock();
}

static struct saved_task_struct* save_process(struct task_struct* task, struct map_entry* head)
{
  	// area is used to point to the vm_area_struct to "backup".
  	//
  	// current_task points to the "backed up" version of the task_struct pointed 
  	// to by task.
  	//
	// child is a pointer used point to the task_struct of one of this process' children
  	// The pointer is used in the saving of each child process.
  	//
  	// mm points to the "backup" version of the current process' memory descriptor.
  	//
  	// need_to_save_pages is for...?
	struct vm_area_struct* area = NULL;
	struct saved_task_struct* current_task = (struct saved_task_struct*)alloc(sizeof(*current_task));
	struct task_struct* child = NULL;
	struct saved_mm_struct* mm;
	int need_to_save_pages = 1;
	
	int major = 0;
	int minor = 0;
	int mapped_to_file = 0;
	//
	
	// INIT_LIST_HEAD() is used in the initializing of struct list_head objects, 
	// which are in turn are used in the implementation of circular-doubly-linked lists.
	INIT_LIST_HEAD(&current_task->children);
	INIT_LIST_HEAD(&current_task->sibling);
	//

	// the strcpy() function is copying the name of the executable over to the
	// saved_task_struct.
	sprint( "Target task %s pid: %d will be saved at %p\n", task->comm, task->pid, current_task);
	strcpy(current_task->name, task->comm);
	//
	
	// ???
	current_task->registers = *task_pt_regs(task);
	savesegment(gs, current_task->gs);
	memcpy(current_task->tls_array, task->thread.tls_array, GDT_ENTRY_TLS_ENTRIES*sizeof(struct desc_struct));
	//
	
	// Checks to see if the memory descriptor, pointed to by task->mm has been
	// encountered before.
	mm = find_by_first(head, task->mm);
	if(mm == NULL)
	{
		//sprint("mm %p not seen previously\n", task->mm);
		mm = (struct saved_mm_struct*)alloc(sizeof(*mm));
		insert_entry(head, task->mm, mm);
		save_pgd(task->mm, mm, head);
	}
	else
	{
		//sprint("mm %p was seen before and was saved to %p\n", task->mm, mm);
		need_to_save_pages = 0;
	}
	//

	// Appears to be backing up some of the members of some memory descriptor.
	//
	// nr_ptes is...?
	// start_brk is start address of the heap.
	// br is the final address of the heap.
	// pid is the process identification number?  Why is pid_vnr() needed?
	current_task->mm = mm;
	current_task->mm->nr_ptes = task->mm->nr_ptes;
	current_task->mm->start_brk = task->mm->start_brk;
	current_task->mm->brk = task->mm->brk;
	current_task->pid = pid_vnr(task_pid(task));
	//
	
	// Back up current executable path and do some file descriptor saving.
	get_path_absolute(task->mm->exe_file, current_task->exe_file); 
	save_files(task->files, current_task, head);
	//
	
	// save_signals() backs up the signal descriptor and signal handler descriptor
	// of the process...
	//
	// save_creds() backs up the process credentials...
	save_signals(task, current_task);
	save_creds(task, current_task);
	//


	//sprint("mm address %p\n", task->mm);
	

	for(area = task->mm->mmap; area != NULL; area = area->vm_next)
	{
	  	// prev appears to be a saved_vm_area associated
	  	// with a previosuly encountered vm_area_struct.
	  	//
	  	// cur_area appears to be used as a temporary saved_vm_area pointer.
	  	// Later, the saved_vm_area objects will each be pointed to by the data
	  	// pointer in a shared resource object.
	  	//
	  	// elem appears to be used as temporary shared_resource pointer.
	  	// Later, the shared_resource objects will be chained together and pointed
	  	// to be current_task->memory.
		struct saved_vm_area* prev = find_by_first(head, area);
		struct saved_vm_area* cur_area = NULL;
		struct shared_resource* elem = NULL;
		//

		//sprint( "Saving area:%08lx-%08lx\n", area->vm_start, area->vm_end);

		// Some memory allocation and "giving" the shared_resource object its
		// "associated" saved_vm_area.
		//
		// The data pointer of the shared_resource object is set to point
		// to the saved_vm_area pointed to by cur_area.
		cur_area = (struct saved_vm_area*)alloc(sizeof(*cur_area));
		elem = (struct shared_resource*)alloc(sizeof(*elem));
		elem->data = cur_area;
		//

		// Another singly-linked list?  It looks like current_task->memory
		// is supposed to be a pointer to a list of shared_resource objects.
		elem->next = current_task->memory;
		current_task->memory = elem;
		//

		// Appears to be backing up certain members of a vm_area_struct object
		// into a saved_vm_area object.
		//
		// vm_start is the start (inclusive) of the memory area of VMA.
		// vm_end is the end (exclusive) of the memory area or VMA.
		// vm_file is a pointer to a struct file, which is a file object.
		// vm_page_prot is the access permissions of the memory aea.
		// vm_pgoff is...?
		cur_area->begin = area->vm_start;
		cur_area->end = area->vm_end;
		if(area->vm_file)
		{
			cur_area->filename = (char*)alloc(256);
			get_path_absolute(area->vm_file, cur_area->filename);
		}
		cur_area->protection_flags = area->vm_page_prot;
		cur_area->vm_flags = area->vm_flags;
		cur_area->vm_pgoff = area->vm_pgoff;
		//
		
		// !!!!!
		//sprint( "##### Before finding major and minor.\n" );
		//sprint( "##### Name: %s\n", area->vm_file->f_dentry->d_name.name );
		//major = MAJOR( area->vm_file->f_dentry->d_inode->i_rdev );
		//minor = MINOR( area->vm_file->f_dentry->d_inode->i_rdev );
		//sprint( "##### After finding major and minor.\n" );
		//sprint( "##### Major: %d Minor: %d\n", major, minor );
		//

		// Pages need to be saved if the encountered memory descriptor has not
		// been encountered previously?
		//
		// The second if statement will set the pointer stack, which is a pointer
		// to a saved_vm_area, to the saved_vm_area pointed to by cur_area if
		// the memory area represented by *area overlaps the process' stack.
		//
		// What are the stack members of the saved_task_struct and task_struct
		// used for?  What are current_task->stack and task->stack used for?
		//
		// The condition is that if both the major and minor numbers of the file
		// are zero, as in the file is a normal file, then save the pages; otherwise,
		// do not save the pages, since the file is a device file and saving pages
		// would result in "invalid pages" being saved; however, is this
		// assumption correct?
		
		mapped_to_file = 0;
		major = -1;
		minor = -1;
		if ( area->vm_file )
		{
			major = MAJOR( area->vm_file->f_dentry->d_inode->i_rdev );
			minor = MINOR( area->vm_file->f_dentry->d_inode->i_rdev );
			
			mapped_to_file = 1;
			
			sprint( "##### Name: %s\n", area->vm_file->f_dentry->d_name.name );
			sprint( "##### Major:\t%d Minor: %d\n", major, minor );
		}
		
		/*if ( major == FB_MAJOR && minor == 0 )
		{
			struct saved_state *state = ( struct saved_state * ) get_reserved_region();
			state->counter++;
		}*/
		
		if( need_to_save_pages && ( !mapped_to_file || !major && !minor ) )
		{
			sprint("Saving pages...\n");
			save_pages(current_task->mm, area, head);
		}
		else
		{
			struct saved_state *state = ( struct saved_state * ) get_reserved_region();
			state->counter++;
			
			sprint("Pages not saved.\n");
		}
		if(area->vm_start <= task->mm->start_stack && area->vm_end >= task->mm->start_stack)
		{
			current_task->stack = cur_area;
			//sprint("stack: %08lx-%08lx\n", cur_area->begin, cur_area->end);
		}
		//

		insert_entry(head, area, cur_area);
		
	}

	// Saves all of the children processes of this process.
	// The call to save the children is done here and not in save_running_processes()?
	list_for_each_entry(child, &task->children, sibling)
	{
		struct saved_task_struct* saved_child = save_process(child, head);
		list_add_tail(&saved_child->sibling, &current_task->children);
		//sprint("Parent %d child %d\n", task->pid, child->pid);
	}
	//

	return current_task;
}

static void save_running_processes(void)
{
	struct saved_state* state;
	struct task_struct* task;
	struct map_entry* head;
	
	struct saved_task_struct *saved_task;
	struct saved_task_struct *saved_last;
	
	// ???
	read_lock(&tasklist_lock);
	task = find_task_by_vpid(1);
	
	if(task == NULL)
	{
		sprint( "Could not find the init process\n");
		read_unlock(&tasklist_lock);
		return;
	}
	//
	
	//sprint( "##### Before allocating \'struct saved_state\'.\n" );
	
	// new_map() just creates a new map_entry object, initializes it and then
	// returns a pointer to it.
	//
	// state->processes is the head pointer to a singly-linked list of saved_task_struct.
	head = new_map();
	state = (struct saved_state*)alloc(sizeof(*state));
	
	state->processes = NULL;
	
	//memset( state->saved_fb_ic, 0, FB_MAX * sizeof( int ) );
	//state->saved_con2fbmaps = 0;
	
	state->counter = 0;
	//
	
	//printksprint( "##### After allocating \'struct saved_state\'.\n" );

	//sprint( "State is at: %p\n", state);
	//sprint( "Processes are at: %p\n", state->processes);
	
	// Saving each parent process?
	// The code below actually obtains a pointer to a saved_task_struct
	// using save_process() and then appears to insert the saved_task_struct 
	// into a singly-linked list
	// that has a head pointer that is state->processes.
	saved_task = NULL;
	saved_last = NULL;
	for_each_process(task)
	{
		//struct saved_task_struct* current_task = NULL;
	     
		if(!is_save_enabled(task)) continue;
		
		/*current_task = save_process(task, head);
		current_task->next = state->processes;
		state->processes = current_task;*/
		
		saved_task = save_process(task, head);
		
		if ( !saved_last )
		{
			state->processes = saved_task;
			saved_task->next = NULL;
			
			saved_last = saved_task;
		}
		
		else
		{
			saved_last->next = saved_task;
			saved_task->next = NULL;
			saved_last = saved_task;
		}
	}
	//
	
	//sprint( "\n");
	read_unlock(&tasklist_lock);
}

static void print_saved_process(struct saved_task_struct* task)
{
	struct shared_resource* elem;
	struct saved_file* file;
	struct saved_task_struct* child;
	sprint( "Next process is at: %p\n", task);
	sprint( "%s %s\n", task->name, task->exe_file);
	
	print_regs(&task->registers);
	sprint("Memory:\n");
	for(elem=task->mm->pages; elem != NULL;elem=elem->next)
	{
		struct saved_page* page = (struct saved_page*)elem->data;
		struct page* p = pfn_to_page(page->pfn);
		sprint("pfn: %lx, count: %d, flags: %08lx, reserved: %s\n", page->pfn, atomic_read(&p->_count), 
		       p->flags, PageReserved(p) ? "yes" : "no");
	}

	for(file = task->open_files; file!=NULL; file = file->next)
	{
		sprint("fd: %u - %s\n", file->fd, file->name);
	}

	list_for_each_entry(child, &task->children, sibling)
	{
		print_saved_process(child);
	}
	
}


static void print_saved_processes(void)
{
	struct saved_state* state;
	struct saved_task_struct* task;
	state = (struct saved_state*)get_reserved_region();
	//sprint( "State is at: %p\n", state);
	for(task=state->processes; task!=NULL; task = task->next)
	{
		print_saved_process(task);
	}
}

static int load_state = 0;
static int fr_reboot_notifier(struct notifier_block* this, unsigned long code, void* x)
{
	local_irq_disable();
	save_running_processes();
	local_irq_enable();
	
	//save_fbs();
	//save_con2fbmaps();
	
	sprint( "State saved\n");
	return 0;
}

asmlinkage void sys_save_state(void)
{
	local_irq_disable();
	save_running_processes();
	local_irq_enable();
	
	//save_fbs();
	//save_con2fbmaps();
}

static int set_load_state(char* arg)
{
  load_state = 1;
  return 0;
}

__setup("load_state", set_load_state);

static __init void fr_init(void)
{
	save_permitted = NULL;
	state_restored = NULL;
	register_reboot_notifier(&fr_notifier);
}

late_initcall(fr_init);


asmlinkage int sys_enable_save_state(struct pt_regs regs)
{
	pid_t pid = regs.bx; 
	struct save_state_permission* p = kmalloc(sizeof(*p), GFP_KERNEL);
	if(pid)
	{
		p->pid = pid;
	}
	else
	{
		p->pid = pid_vnr(task_pid(current));
	}
	p->next = save_permitted;
	save_permitted = p;
	sprint("Save state enabled for process %d\n", p->pid);
	return 0;
}

int is_save_enabled(struct task_struct* task)
{
	struct save_state_permission* cur = save_permitted;
	for(;cur!=NULL; cur=cur->next)
	{
		if(cur->pid == pid_vnr(task_pid(task)))
			return 1;
	}

	return 0;
}

void add_to_restored_list(struct task_struct* task)
{
	struct save_state_permission* p = kmalloc(sizeof(*p), GFP_KERNEL);
	p->pid = pid_vnr(task_pid(task));
	p->next = state_restored;
	state_restored = p;
	sprint("State was restored for proccess %d, current->pid: %d\n", p->pid, task->pid);
}


int was_state_restored(struct task_struct* task)
{
	struct save_state_permission* cur = state_restored;
	for(;cur!=NULL;cur=cur->next)
	{
		if(cur->pid == pid_vnr(task_pid(task))) 
		{
//			sprint("State was restored for process %d\n", task_pid_nr(task));
			return 1;
		}
	}
//	sprint("State was not restored for process %d\n", task_pid_nr(task));
	return 0;
}

asmlinkage int sys_was_state_restored(struct pt_regs regs)
{
	int ret = was_state_restored(current);
	if(ret)
	{
		sprint("State was restored for process %d\n", task_pid_nr(current));
	}
	else
	{
		sprint("State was not restored for process %d\n", task_pid_nr(current));
	}
	return ret;
}


void test_restore_sockets(void);
asmlinkage int sys_state_present(struct pt_regs regs)
{
	struct saved_state* state;
	state = (struct saved_state*)get_reserved_region();
	return state->processes != NULL;
}

extern struct resource crashk_res;
asmlinkage int sys_load_saved_state(struct pt_regs regs)
{
	//
	int ret;

	struct saved_state* state;
	//
	
	sprint( "##### start sys_load_saved_state()\n" );
	
	/*   unsigned long i; */
	/*   unsigned long start = FASTREBOOT_REGION_START; */
	/*   unsigned long end = FASTREBOOT_REGION_START + FASTREBOOT_REGION_SIZE; */
	/*   sprint("Begin: %lu End:%lu\n",  start >> PAGE_SHIFT,  */
	/* 	 end >> PAGE_SHIFT); */
	/*   for(i = start; i<=end; i+=PAGE_SIZE) */
	/*   { */
	/* 	  unsigned long pfn = i>>PAGE_SHIFT; */
	/* 	  struct page* page = pfn_to_page(pfn); */
	/* 	  if(atomic_read(&page->_count) != 1 || page->flags != 1073742848 || !PageReserved(page)) */
	/* 	  { */
	/* 		  sprint("Bad page %lu: count: %d, flags: %08lx, reserved: %s\n", pfn, atomic_read(&page->_count),  */
	/* 			 page->flags, PageReserved(page) ? "yes" : "no"); */
	/* 		  return 0; */
	/* 	  } */
	/*   } */

	state = (struct saved_state*)get_reserved_region();
	
	if(state->processes == NULL)
	{
		sprint( "No more saved state\n");
		sprint( "##### end sys_load_saved_state()\n" );
		return -1;
	}
	
	local_irq_disable();
	//while ( state->processes )
	//{
		print_saved_processes();
		ret = set_state(&regs, state->processes);
		sprint( "set_state returned %d\n", ret);
		if(ret == 0)
		{
			state->processes = state->processes->next;
			add_to_restored_list(current);
		}
	
		sprint( "state->counter: %d\n", state->counter );
	//}
	local_irq_enable();
	
	/*if( !state->processes )
	{
		sprint( "No more saved state.\n" );
		sprint( "##### end sys_load_saved_state()\n" );
		return -1;
	}*/
	
	sprint( "##### end sys_load_saved_state()\n" );

	return regs.ax;
}

static struct saved_fb_info *save_fb_info ( struct fb_info *info )
{
	//
	int status = 0;
	
	struct saved_fb_info *saved_info = NULL;
	
	int total_size = 0;
	//
	
	//
	if ( !info || !lock_fb_info( info ) )
	{
		saved_info = NULL;
		
		goto done;
	}
	//
	
	//
	saved_info = alloc( sizeof( struct saved_fb_info ) );
	if ( !saved_info )
	{
		saved_info = NULL;
		
		goto unlock;
	}
	//
	
	// Save the struct fb_var_screeninfo object.
	saved_info->var = info->var;
	//
	
	// Save the struct fb_cmap object.
	saved_info->cmap.start = info->cmap.start;
	saved_info->cmap.len = info->cmap.len;
	
	total_size = saved_info->cmap.len * sizeof( __u16 );
	
	saved_info->cmap.red = alloc( total_size );
	saved_info->cmap.green = alloc( total_size );
	saved_info->cmap.blue = alloc( total_size );
	saved_info->cmap.transp = info->cmap.transp;
	if ( info->cmap.transp )
	{
		saved_info->cmap.transp = alloc( total_size );
	}
	
	if (	!saved_info->cmap.red || 
		!saved_info->cmap.green || 
		!saved_info->cmap.blue || 
		!saved_info->cmap.transp && info->cmap.transp )
	{
		saved_info = NULL;
		
		goto unlock;
	}
	
	status = fb_copy_cmap( &info->cmap, &saved_info->cmap );
	if ( status )
	{
		saved_info = NULL;
		
		goto unlock;
	}
	//
	
unlock:
	unlock_fb_info( info );
	
done:
	return saved_info;
}

// This function is an altered version of fb_read() in the file drivers/video/fbmem.c.
static char *save_fb_contents ( struct fb_info *info )
{
	u32 *dst;
	u32 __iomem *src;
	int c, i;
	size_t count = 0;
	//int ret = 0;
	char *contents = NULL;

	if ( !info )
	{
		//ret = -EINVAL;
		contents = NULL;
		
		goto done;
	}
	
	if ( !lock_fb_info( info ) )
	{
		//ret = -ENODEV;
		contents = NULL;
		
		goto done;
	}
	
	if ( !info->screen_base )
	{
		//ret = -ENODEV;
		contents = NULL;
		
		goto unlock;
	}

	if ( info->state != FBINFO_STATE_RUNNING )
	{
		//ret = -EPERM;
		contents = NULL;
		
		goto unlock;
	}

	count = info->screen_size;

	if ( count == 0 )
	{
		count = info->fix.smem_len;
	}
	
	contents = ( char * ) alloc( count );
	if ( !contents )
	{
		//ret = -ENOMEM;
		contents = NULL;
		
		goto unlock;
	}

	src = ( u32 __iomem * ) ( info->screen_base );

	if (info->fbops->fb_sync)
		info->fbops->fb_sync(info);
		
	dst = ( u32 __iomem * ) contents;

	while ( count > 0 )
	{
		c  = ( count > PAGE_SIZE ) ? PAGE_SIZE : count;
		for ( i = c >> 2; i > 0; i-- )
		{
			*dst = fb_readl( src );
			
			dst++;
			src++;
		}
		if ( c & 3 )
		{
			u8 *dst8 = ( u8 * ) dst;
			u8 __iomem *src8 = ( u8 __iomem * ) src;

			for ( i = c & 3; i > 0; i-- )
			{
				*dst8 = fb_readb( src8 );
				
				dst8++;
				src8++;
			}

			dst = ( u32 __iomem * ) dst8;
			src = ( u32 __iomem * ) src8;
		}

		count -= c;
	}
	
unlock:
	unlock_fb_info( info );

done:
	//return ret;
	return contents;
}
//

static struct fb_con2fbmap *save_con2fbmaps ( struct fb_info *info )
{
	//
	struct fb_con2fbmap *con2fbs = NULL;
	struct fb_event event;
	
	int index = 0;
	//
	
	if ( !info || !lock_fb_info( info ) )
	{
		goto done;
	}
	
	con2fbs = alloc( MAX_NR_CONSOLES * sizeof( struct fb_con2fbmap ) );
	if ( !con2fbs )
	{
		goto unlock;
	}

	//
	for ( index = 0; index < MAX_NR_CONSOLES; index++ )
	{
		con2fbs[index].console = index + 1;
		con2fbs[index].framebuffer = -1;
		
		event.data = &con2fbs[index];
		event.info = info;
		fb_notifier_call_chain( FB_EVENT_GET_CONSOLE_MAP, &event );
	}
	//

unlock:
	unlock_fb_info( info );
	
done:
	return con2fbs;
}

static int file_is_fb ( struct file *file )
{
	struct inode *inode = file->f_dentry->d_inode;
	int major = MAJOR( inode->i_rdev );
	
	//
	/*if ( major == FB_MAJOR )
	{
		sprint( "##### File is a framebuffer.\n" );
	}*/
	//
	
	return major == FB_MAJOR;
}

static void save_fb ( struct file *file, struct saved_file *saved_file, struct map_entry *head )
{
	//
	//struct saved_state *state = ( struct saved_state * ) get_reserved_region();
	
	struct fb_info *info = file->private_data;
	//
	
	//
	saved_file->type = FRAMEBUFFER;
	saved_file->fb.minor = MINOR( file->f_dentry->d_inode->i_rdev );
	if ( !( 0 <= saved_file->fb.minor && saved_file->fb.minor < FB_MAX ) )
	{
		panic( "Invalid framebuffer minor, %d.\n", saved_file->fb.minor );
	}
	//
	
	//
	saved_file->fb.info = NULL;
	saved_file->fb.contents = NULL;
	saved_file->fb.con2fbs = NULL;
	
	sprint( "##### Saving framebuffer %d.\n", saved_file->fb.minor );
	
	if ( !find_by_first( head, info ) )
	{
		sprint( "##### Saving the framebuffer information of framebuffer %d.\n", saved_file->fb.minor );
		saved_file->fb.info = save_fb_info( info );
		if ( !saved_file->fb.info )
		{
			panic( "Unable to save the framebuffer information of framebuffer %d.\n", saved_file->fb.minor );
		}
		
		sprint( "##### Saving the contents of framebuffer %d.\n", saved_file->fb.minor );
		saved_file->fb.contents = save_fb_contents( info );
		if ( !saved_file->fb.contents )
		{
			panic( "Unable to save the contents of framebuffer %d.\n", saved_file->fb.minor );
		}
		
		//state->saved_fb_ic[saved_file->fb.minor] = 1;
		insert_entry( head, info, saved_file );
	}
	
	if ( !find_by_first( head, registered_fb ) )
	{
		sprint( "##### Saving the con2fbmaps.\n" );
		saved_file->fb.con2fbs = save_con2fbmaps( info );
		if ( !saved_file->fb.con2fbs )
		{
			panic( "Unable to save the con2fbmaps.\n" );
		}
		
		//state->saved_con2fbmaps = 1;
		insert_entry( head, registered_fb, saved_file->fb.con2fbs );
	}
	
	/*if ( !saved_file->fb.info || !saved_file->fb.contents || !saved_file->fb.con2fbs )
	{
		panic( "Unable to save framebuffer %d.\n", saved_file->fb.minor );
	}*/
	//
	
	return;
}

/*static void save_fbs ( void )
{
	//
	struct saved_state *state = ( struct saved_state * ) get_reserved_region();
	
	int index = 0;
	struct fb_info *info = NULL;
	//
	
	//
	for ( index = 0; index < FB_MAX; index++ )
	{
		info = registered_fb[index];
	
		state->fbs[index].info = save_fb_info( info );
		state->fbs[index].contents = save_fb_contents( info );
		
		// I am not sure about this...
		if (	( info && info->fbops ) && 
			( !state->fbs[index].info || !state->fbs[index].contents ) )
		{
			panic( "Unable to save framebuffer %d.\n", index );
		}
		//
	}
	//
	
	return;
}

static void restore_fbs ( void )
{
	//
	struct saved_state *state = ( struct saved_state * ) get_reserved_region();
	
	int index = 0;
	struct fb_info *info = NULL;
	
	int status1 = 0;
	int status2 = 0;
	//
	
	//
	for ( index = 0; index < FB_MAX; index++ )
	{
		info = registered_fb[index];
	
		status1 = restore_fb_info( info, state->fbs[index].info );
		status2 = restore_fb_contents( info, state->fbs[index].contents );
		
		// I am not sure about this...
		if (	( info && info->fbops ) && 
			( status1 || status2 ) )
		{
			panic( "Unable to restore framebuffer %d.\n", index );
		}
		//
	}
	//
	
	return;
}

static void save_con2fbmaps ( void )
{
	//
	struct saved_state *state = ( struct saved_state * ) get_reserved_region();
	
	struct fb_info *info = registered_fb[0];
	
	int index = 0;
	struct fb_event event;
	//
	
	//
	if ( !info || !lock_fb_info( info ) )
	{
		return;
	}
	//
	
	//
	
	//
	//state->con2fbs = alloc( MAX_NR_CONSOLES * sizeof( struct fb_con2fbmap ) );

	for ( index = 0; index < MAX_NR_CONSOLES; index++ )
	{
		state->con2fbs[index].console = index + 1;
		state->con2fbs[index].framebuffer = -1;
		
		event.data = &state->con2fbs[index];
		event.info = info;
		fb_notifier_call_chain( FB_EVENT_GET_CONSOLE_MAP, &event );
	}
	//
	
	//
	unlock_fb_info( info );
	//
	
	return;
}

static void restore_con2fbmaps ( void )
{
	//
	struct saved_state *state = ( struct saved_state * ) get_reserved_region();
	
	struct fb_info *info = registered_fb[0];
	
	int index = 0;
	struct fb_event event;
	//
	
	if ( !info || !lock_fb_info( info ) )
	{
		return;
	}
	
	//
	for ( index = 0; index < MAX_NR_CONSOLES; index++ )
	{
		request_module( "fb%d", state->con2fbs[index].framebuffer );
		
		event.data = &state->con2fbs[index];
		event.info = info;
		fb_notifier_call_chain( FB_EVENT_SET_CONSOLE_MAP, &event );
	}
	//
	
	//
	unlock_fb_info( info );
	//
	
	return;
}*/

// Warning: This function might only detect '/dev/input/mice', '/dev/input/mouse0', and '/dev/input/mouse1'.
static int file_is_mouse ( struct file *file )
{
	//
	struct inode *inode = file->f_dentry->d_inode;
	int major = MAJOR( inode->i_rdev );
	int minor = MINOR( inode->i_rdev );
	
	int index = minor - MOUSEDEV_MINOR_BASE;
	
	int is_mouse = 0;
	//
	
	//
	if ( major == INPUT_MAJOR && ( index == 0 || index == 1 || index == 31 ) )
	{
		is_mouse = 1;
	}
	
	return is_mouse;
	//
}

static void save_mouse ( struct file *file, struct saved_file *saved_file )
{
	//
	struct mousedev_client *client = file->private_data;
	struct mousedev *mousedev = client->mousedev;
	
	struct saved_mousedev_client *saved_client = &saved_file->mouse.client;
	struct saved_mousedev *saved_mousedev = &saved_file->mouse.mousedev;
	//
	
	//
	saved_file->type = MOUSE;
	
	/*if( file->f_flags & O_NONBLOCK )
	{
		saved_file->flags |= O_NONBLOCK;
	}*/
	//
	
	// Interrupts already disabled before call to save_running_processes().
	spin_lock( &client->packet_lock );
	memcpy( saved_client->packets, client->packets, sizeof( client->packets ) );
	spin_unlock( &client->packet_lock );
	
	saved_client->head = client->head;
	saved_client->tail = client->tail;
	saved_client->pos_x = client->pos_x;
	saved_client->pos_y = client->pos_y;

	memcpy( saved_client->ps2, client->ps2, sizeof( client->ps2 ) );
	saved_client->ready = client->ready;
	saved_client->buffer = client->buffer;
	saved_client->bufsiz = client->bufsiz;
	saved_client->imexseq = client->imexseq;
	saved_client->impsseq = client->impsseq;
	saved_client->mode = client->mode;
	saved_client->last_buttons = client->last_buttons;
	
	
	saved_mousedev->packet = mousedev->packet;
	saved_mousedev->pkt_count = mousedev->pkt_count;
	memcpy( saved_mousedev->old_x, mousedev->old_x, sizeof( mousedev->old_x ) );
	memcpy( saved_mousedev->old_y, mousedev->old_y, sizeof( mousedev->old_y ) );
	saved_mousedev->frac_dx = mousedev->frac_dx;
	saved_mousedev->frac_dy = mousedev->frac_dy;
	saved_mousedev->touch = mousedev->touch;
	//
	
	return;
}

static int file_is_unix_socket ( struct file *file )
{
	//
	struct socket *socket;
	struct sock *sock;
	
	int is_unix_socket = 0;
	//
	
	//
	if ( file_is_socket( file ) )
	{
		socket = file->private_data;
		sock = socket->sk;
		
		if ( sock->sk_family == AF_UNIX )
		{
			is_unix_socket = 1;
		}
	}
	//
	
	return is_unix_socket;
}

static void save_unix_socket ( struct file *file, struct saved_file *saved_file, struct map_entry *head )
{
	//
	struct socket *socket = file->private_data;
	struct sock *sock = socket->sk;
	struct unix_sock *unix = unix_sk( sock );
	
	struct saved_unix_socket *saved_unix = &saved_file->socket.unix ;
	struct saved_unix_socket *saved_unix_other;
	
	struct map_entry *entry_current;
	
	struct sk_buff *skb;
	struct saved_sk_buff *saved_skb;
	struct saved_sk_buff *tail;
	//
	
	// This here may be temporary...
	if ( sock->sk_type != SOCK_STREAM )
	{
		panic( "Unable to save UNIX socket of unsupported type %d.\n", sock->sk_type );
	}
	//
	
	unix_state_lock( sock );
	
	// Determines the kind of UNIX socket we have and saves the necessary information.
	saved_unix->kind = SOCKET_NONE;
	
	if ( unix->addr )
	{
		//
		if ( sock->sk_state == TCP_ESTABLISHED )
		{
			// Link to peer and link peer to self and broadcast self.
			saved_unix->peer = NULL;
			
			saved_unix_other = find_by_first( head, unix->peer );
			if ( saved_unix_other )
			{
				saved_unix->peer = saved_unix_other;
				
				saved_unix_other->peer = saved_unix;
			}
			
			insert_entry( head, sock, saved_unix );
			//
			
			// Link to listening socket and broadcast self.
			saved_unix->listen = NULL;
			list_for_each_entry ( entry_current, &head->list, list )
			{
				saved_unix_other = entry_current->second;
				
				if (	entry_current->first == unix->addr && 
					saved_unix_other->state == TCP_LISTEN )
				{
					saved_unix->listen = saved_unix_other;
				}
			}
			
			insert_entry( head, unix->addr, saved_unix );
			//
		
			saved_unix->kind = SOCKET_ACCEPTED;
		}
		
		else
		{
			if ( sock->sk_state == TCP_LISTEN )
			{
				// Link accept sockets to self and broadcast self.
				list_for_each_entry ( entry_current, &head->list, list )
				{
					saved_unix_other = entry_current->second;
					
					if (	entry_current->first == unix->addr && 
						saved_unix_other->kind == SOCKET_ACCEPTED )
					{
						saved_unix_other->listen = saved_unix;
					}
				}
				
				insert_entry( head, unix->addr, saved_unix );
				//
			}
		
			saved_unix->kind = SOCKET_BOUND;
		}
		//
		
		//
		memcpy( &saved_unix->unix_address.address, unix->addr->name, unix->addr->len );
		
		saved_unix->unix_address.length = unix->addr->len;
		//
	}
	
	else if ( sock->sk_state == TCP_ESTABLISHED )
	{
		// Link to peer and link peer to self and broadcast self.
		saved_unix->peer = NULL;
	
		saved_unix_other = find_by_first( head, unix->peer );
		if ( saved_unix_other )
		{
			saved_unix->peer = saved_unix_other;
			
			saved_unix_other->peer = saved_unix;
		}
		
		insert_entry( head, sock, saved_unix );
		//
	
		saved_unix->kind = SOCKET_CONNECTED;
	}
	//
	
	// ???
	saved_unix->state = sock->sk_state;
	
	saved_unix->shutdown = sock->sk_shutdown;
	
	saved_unix->peercred = sock->sk_peercred;
	//
	
	// Saves the receive queue.
	saved_unix->head = NULL;
	tail = NULL;
	
	spin_lock( &sock->sk_receive_queue.lock );
	
	skb_queue_walk ( &sock->sk_receive_queue, skb )
	{
		//
		saved_skb = alloc( sizeof( struct saved_sk_buff ) );
		if ( !saved_skb )
		{
			panic( "Out of reserved memory.\n" );
		}
		//
		
		//
		memcpy( saved_skb->cb, skb->cb, sizeof( skb->cb ) );
		
		saved_skb->len = skb->len;
		
		saved_skb->data = alloc( skb->len );
		memcpy( saved_skb->data, skb->data, skb->len );
		
		saved_skb->next = NULL;
		//
		
		//
		if ( !saved_unix->head )
		{
			saved_unix->head = saved_skb;
			
			tail = saved_skb;
		}
		
		else
		{
			tail->next = saved_skb;
			tail = saved_skb;
		}
		//
	}
	
	spin_unlock( &sock->sk_receive_queue.lock );
	//
	
	unix_state_unlock( sock );
	
	return;
}

