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
#include <net/tcp.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/vmalloc.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <net/af_unix.h>

#include <linux/set_state.h>

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

static void reserve_process_memory(struct saved_task_struct* task)
{
	struct shared_resource* elem;
	struct saved_task_struct* child;
	list_for_each_entry(elem, &task->mm->pages, list)
	{
		struct saved_page* page = (struct saved_page*)elem->data;
		int err;
		err = reserve(page->pfn << PAGE_SHIFT, PAGE_SIZE);
		if(err < 0)
		{
//			sprint("Failed to reserve pfn: %ld, err: %d\n", page->pfn, err);
		}
		else
		{
			//sprint("Reserved pfn: %ld\n", page->pfn);
		}
	}

	list_for_each_entry(child, &task->children, sibling)
	{
		reserve_process_memory(child);
	}

}
void reserve_saved_memory(void)
{
	struct saved_task_struct* task;
	struct saved_state* state = (struct saved_state*)get_reserved_region();

	if(state->processes.next == NULL)
	{
		INIT_LIST_HEAD(&state->processes);
	}

	if(list_empty(&state->processes))
	{
		sprint( "No state saved\n");
		return;
	}
	list_for_each_entry(task, &state->processes, next)
	{
		reserve_process_memory(task);
	}
}


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

		elem = (struct shared_resource*)alloc(sizeof(*elem));
		elem->data = page;
		INIT_LIST_HEAD(&elem->list);
		list_add_tail(&elem->list, &mm->pages);
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

		struct page* p;
		struct shared_resource* elem;
		pgd_t pgd = mm->pgd[i];
		if(pgd.pgd == 0 || pgd_bad(pgd) || !pgd_present(pgd))
			continue;
		
		elem = (struct shared_resource*)alloc(sizeof(*elem));
		INIT_LIST_HEAD(&elem->list);
		p = pfn_to_page(pgd.pgd >> 12);

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

		list_add_tail(&elem->list, &saved_mm->pages);

     	}
	sprint( "Saved pgd\n");
}


static struct dentry* elements[PATH_MAX];

static void get_path_absolute_dentry (struct dentry* dentry, struct vfsmount* vfsmount, char *path )
{
	int index = 0;
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
	
	index--;
	
	strcpy( path, "" );
	
	while ( index >= 0 )
	{
		strcat( path, "/" );
		
		spin_lock( &elements[index]->d_lock );
		strcat( path, elements[index]->d_name.name );
		spin_unlock( &elements[index]->d_lock );
		
		index--;
	}
	return;
}

static void get_path_absolute(struct file* file, char* path)
{
	struct dentry *dentry = file->f_dentry;
	struct vfsmount *vfsmount = file->f_vfsmnt;
	get_path_absolute_dentry(dentry, vfsmount, path);
}

// This is an altered version of the function vfs_fstatat() in fs/stat.c
int get_status ( char *path, struct kstat *stat )
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
	//

	//
	error = vfs_getattr( patho.mnt, patho.dentry, stat );
	path_put( &patho );
	//
	
	//
done:
	return error;
	//
}


static bool file_is_pipe(struct file* f)
{
	struct inode *inode = f->f_path.dentry->d_inode;
	struct pipe_inode_info *pipe =  f->f_path.dentry->d_inode->i_pipe;
	if (inode != NULL && pipe != NULL)
	{
		if (S_ISFIFO(inode->i_mode))
			return true;
		else
			return false;
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
				INIT_LIST_HEAD(&elem->list);
				elem->data = page_to_save;
				list_add_tail(&elem->list, &task->mm->pages);
			}
		}
	}
}

static int file_is_vc_terminal(struct file* file)
{
	struct inode *inode = file->f_dentry->d_inode;
	int major = MAJOR( inode->i_rdev );
	int minor = MINOR( inode->i_rdev );
	
	return ( (major == TTY_MAJOR && ( 1 <= minor && minor <= MAX_NR_CONSOLES )) || (major == TTYAUX_MAJOR && minor == 1) );
}

static void save_vc_term_info(struct file* f, struct saved_file* file)
{
	struct tty_struct* tty;
	struct tty_driver* driver;
	struct vc_data* vcd;
	struct saved_vc_data* svcd;
	unsigned char* screen_buffer;

	tty = (struct tty_struct*)f->private_data;
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
	svcd = (struct saved_vc_data*)alloc(sizeof(*svcd));
	svcd->index = vcd->vc_num;
	svcd->rows = vcd->vc_rows;
	svcd->cols = vcd->vc_cols;
	svcd->x = vcd->vc_x;
	svcd->y = vcd->vc_y;
	svcd->screen_buffer_size = vcd->vc_screenbuf_size;
	screen_buffer = (unsigned char*)alloc(svcd->screen_buffer_size);

	vcd->vc_sw->con_save_screen(vcd);  
	memcpy(screen_buffer, vcd->vc_screenbuf, svcd->screen_buffer_size);
	svcd->screen_buffer = screen_buffer;
	file->type = VC_TTY;
	file->vcd = svcd;
	
}

extern struct file_operations socket_file_ops;
static bool file_is_socket(struct file* file)
{
	sprint("f_op is %p, expecting %p\n", file->f_op, &socket_file_ops);
	if (file->f_op == &socket_file_ops)
		return true;
	else
		return false;
}

static void save_socket_write_queue(struct sock* sk, struct saved_tcp_state* saved_tcp);
static void save_tcp_state(struct saved_file* file, struct socket* sock, struct saved_task_struct* tsk)
{
	struct sock* sk = sock->sk;
	struct inet_sock* inet = inet_sk(sk);
	struct inet_connection_sock* icsk = inet_csk(sk);
	struct tcp_sock* tp = tcp_sk(sk);
	struct saved_tcp_state* saved_tcp = (struct saved_tcp_state*)alloc(sizeof(struct saved_tcp_state));
	struct dst_entry* dst = __sk_dst_get(sk);

//	lock_sock(sk);
	bh_lock_sock_nested(sk);
	file->socket.tcp = saved_tcp;

	// Save addresses and port numbers
	saved_tcp->state = sk->sk_state;
	saved_tcp->daddr = inet->daddr;
	saved_tcp->dport = ntohs(inet->dport);
	saved_tcp->saddr = inet->saddr;
	saved_tcp->sport = ntohs(inet->sport);

	sprint("state %d sport %u dport %u\n", saved_tcp->state, saved_tcp->sport, saved_tcp->dport);

	// Save protocol state
	saved_tcp->rcv_mss = icsk->icsk_ack.rcv_mss;

	saved_tcp->rcv_nxt = tp->rcv_nxt;
	saved_tcp->rcv_wnd = tp->rcv_wnd;
	saved_tcp->rcv_wup = tp->rcv_wup;

	saved_tcp->snd_una = tp->snd_una;
	saved_tcp->snd_nxt = tp->snd_nxt;
	saved_tcp->snd_wl1 = tp->snd_wl1;
	saved_tcp->snd_wnd = tp->snd_wnd;
	saved_tcp->max_window = tp->max_window;

	saved_tcp->window_clamp = tp->window_clamp;
	saved_tcp->rcv_ssthresh = tp->rcv_ssthresh;
	saved_tcp->advmss = tp->advmss;
	saved_tcp->rcv_wscale = tp->rx_opt.rcv_wscale;
	saved_tcp->snd_wscale = tp->rx_opt.snd_wscale;

	saved_tcp->pred_flags = tp->pred_flags;
	saved_tcp->tcp_header_len = tp->tcp_header_len;

	saved_tcp->copied_seq = tp->copied_seq;
	saved_tcp->mss_cache = tp->mss_cache;
	saved_tcp->xmit_size_goal = tp->xmit_size_goal;		
	saved_tcp->rx_opt_mss_clamp = tp->rx_opt.mss_clamp;

	saved_tcp->snd_cwnd = tp->snd_cwnd;
	saved_tcp->packets_in_flight = tcp_packets_in_flight(tp);
	
	if(dst)
	{
		saved_tcp->dst_mtu = dst_mtu(dst);
	}
	else
	{
		saved_tcp->dst_mtu = 0;
	}
	
	// RTT state and setting
	saved_tcp->rto = inet_csk(sk)->icsk_rto;
	saved_tcp->srtt = tp->srtt;
	saved_tcp->mdev = tp->mdev;
	saved_tcp->mdev_max = tp->mdev_max;
	saved_tcp->rttvar = tp->rttvar;
	saved_tcp->rtt_seq = tp->rtt_seq;
	saved_tcp->tcp_tstamp_offset = tcp_time_stamp(tp);

	saved_tcp->timestamp_ok = tp->rx_opt.tstamp_ok;
	saved_tcp->tsval = tp->rx_opt.rcv_tsval;
	saved_tcp->tsecr = tp->rx_opt.rcv_tsecr;
	saved_tcp->saw_tstamp = tp->rx_opt.saw_tstamp;
	saved_tcp->ts_recent = tp->rx_opt.ts_recent;
	saved_tcp->ts_recent_stamp = tp->rx_opt.ts_recent_stamp;

	saved_tcp->rx_opt = tp->rx_opt;

	saved_tcp->sk_sndbuf = sk->sk_sndbuf;
	saved_tcp->nonagle = tp->nonagle;

	save_socket_write_queue(sk, saved_tcp);


	if(sk->io_in_progress)
	{
		struct tcp_io_progress* iop = (struct tcp_io_progress*)alloc(sizeof(*iop));
		iop->progress = sk->io_progress;
		tsk->syscall_data = iop;
	}


//	release_sock(sk);
	bh_unlock_sock(sk);
}
// Save the contents of the sockets write queue
// Write queue has the data that the application wrote to the socket
// but it has not been sent yet
static void save_socket_write_queue(struct sock* sk, struct saved_tcp_state* saved_tcp)
{
	struct sk_buff* sk_tail;
	struct sk_buff* sk_pos;
	struct tcp_sock* tp = tcp_sk(sk);
	int sk_buff_count = 0;
	int segs_buffered = 0;
	int byte_count = 0;

	INIT_LIST_HEAD(&saved_tcp->sk_buffs);

	sk_tail = tcp_write_queue_tail(sk);

	tcp_for_write_queue(sk_pos, sk)
	{
		struct tcp_skb_cb* tcb = TCP_SKB_CB(sk_pos);

		if(tcb->seq >= tp->snd_una)
		{
			struct saved_sk_buff* s_buff;
			sk_buff_count++;
			byte_count += sk_pos->len;

			s_buff = (struct saved_sk_buff*)alloc(sizeof(*s_buff));
			INIT_LIST_HEAD(&s_buff->list);

			s_buff->len = sk_pos->len;
			s_buff->csum = sk_pos->csum;
			s_buff->seq = tcb->seq;
			s_buff->ip_summed = sk_pos->ip_summed;
			s_buff->tstamp = tcb->when;
			s_buff->flags = tcb->flags;

			if(sk_pos->len > 0)
			{
				s_buff->content = alloc(sk_pos->len);
				memcpy(s_buff->content, sk_pos->data, sk_pos->len);
			}

			list_add_tail(&s_buff->list, &saved_tcp->sk_buffs);
		}

		if(tcb->seq >= tp->snd_nxt)
		{
			segs_buffered ++;
		}

		if(sk_pos == sk_tail)
			break;
	}

	saved_tcp->num_saved_buffs = sk_buff_count;
}

static void save_unix_socket ( struct file *file, struct saved_file *saved_file, struct map_entry *head )
{
	//
	struct socket *socket = file->private_data;
	struct sock *sock = socket->sk;
	struct unix_sock *u = unix_sk( sock );
	
	struct saved_unix_socket *saved_unix = &saved_file->socket.unx ;
	struct saved_unix_socket *saved_unix_other;
	
	struct map_entry *entry_current;
	
	struct sockaddr_un address;
	struct kstat stat;
	
	struct sk_buff *skb;
	struct saved_sk_buff *saved_skb;
	
	int status = 0;
	//
	
	// This here may be temporary...
	if ( sock->sk_type != SOCK_STREAM )
	{
		panic( "Unable to save UNIX socket of unsupported type %d.\n", sock->sk_type );
	}
	//

	INIT_LIST_HEAD(&saved_unix->sk_buffs);
	
	unix_state_lock( sock );
	
	// Determines the kind of UNIX socket we have and saves the necessary information.
	saved_unix->kind = SOCKET_NONE;
	
	if ( u->addr )
	{
		//
		memcpy( &saved_unix->unix_address.address, u->addr->name, u->addr->len );
		
		saved_unix->unix_address.length = u->addr->len;
		//
		
		//
		if ( sock->sk_state == TCP_ESTABLISHED )
		{
			// Link to peer and link peer to self and broadcast self.
			saved_unix->peer = NULL;
			
			saved_unix_other = find_by_first( head, u->peer );
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
				
				if (	entry_current->first == u->addr && 
					saved_unix_other->state == TCP_LISTEN )
				{
					saved_unix->listen = saved_unix_other;
				}
			}
			
			insert_entry( head, u->addr, saved_unix );
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
					
					if (	entry_current->first == u->addr && 
						saved_unix_other->kind == SOCKET_ACCEPTED )
					{
						saved_unix_other->listen = saved_unix;
					}
				}
				
				insert_entry( head, u->addr, saved_unix );
				//
			}
			
			//
			address = saved_unix->unix_address.address;
			
			if ( address.sun_path[0] )
			{
				if ( address.sun_path[0] != '/' )
				{
					panic( "Unable to handle UNIX socket bind address of non-absolute path \'%s\'.\n", address.sun_path );
				}
				
				status = get_status( address.sun_path, &stat );
				if ( status < 0 )
				{
					panic( "Unable to obtain ownership information of bounded UNIX socket file.  Error: %d\n", -status );
				}
		
				saved_unix->user = stat.uid;
				saved_unix->group = stat.gid;
			}
			//
		
			saved_unix->kind = SOCKET_BOUND;
		}
		//
	}
	
	else if ( sock->sk_state == TCP_ESTABLISHED )
	{
		// Link to peer and link peer to self and broadcast self.
		saved_unix->peer = NULL;
	
		saved_unix_other = find_by_first( head, u->peer );
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
		INIT_LIST_HEAD(&saved_skb->list);
		
		//
		memcpy( saved_skb->cb, skb->cb, sizeof( skb->cb ) );
		
		saved_skb->len = skb->len;
		
		saved_skb->content = alloc( skb->len );
		memcpy( saved_skb->content, skb->data, skb->len );
		
		list_add_tail(&saved_skb->list, &saved_unix->sk_buffs);
	}
	
	spin_unlock( &sock->sk_receive_queue.lock );
	//
	
	unix_state_unlock( sock );
	
	return;
}


static void save_socket_info(struct saved_task_struct* task, struct file* f, struct saved_file* file, struct map_entry* head)
{
	struct socket *sock = f->private_data;
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	file->type = SOCKET;
	file->socket.type = sock->type;
	file->socket.state = sock->state;
	file->socket.flags= sock->flags;
	file->socket.wait = sock->wait;
	file->socket.sock_protocol = sk->sk_protocol; 
	file->socket.sock_type = sk->sk_type;
	file->socket.sock_family = sk->sk_family;
	file->socket.userlocks = sk->sk_userlocks;
	file->socket.backlog = sk->sk_ack_backlog;
	file->socket.binded = 0;
	if(f->f_flags & O_NONBLOCK)
		file->flags |= O_NONBLOCK;

	if(sk->sk_userlocks) file->socket.binded = 1;

	switch(file->socket.sock_family)
	{
	case AF_INET:
			file->socket.inet.daddr = inet->daddr;
			file->socket.inet.rcv_saddr = inet->rcv_saddr;
			file->socket.inet.dport = inet->dport;
			file->socket.inet.saddr = inet->saddr;
			file->socket.inet.num = inet->num;
			file->socket.inet.sport = inet->sport;
			
			if(file->socket.sock_type == SOCK_STREAM)
			{
				sprint("Saving tcp socket\n");
				save_tcp_state(file, sock, task);
			}
			break;
	case AF_UNIX:
		sprint( "Saving UNIX socket.\n" );
		
		save_unix_socket( f, file, head );
		
		break;
	}


}

static void save_fs(struct fs_struct* fs, struct saved_task_struct* task, struct map_entry* head)
{
	struct saved_fs_struct* saved_fs;

	if((saved_fs = find_by_first(head, fs)) != NULL)
	{
		task->fs = saved_fs;
		return;
	}

	saved_fs = alloc(sizeof(*saved_fs));
	saved_fs->umask = fs->umask;
	get_path_absolute_dentry(fs->pwd.dentry, fs->pwd.mnt, saved_fs->pwd);
	get_path_absolute_dentry(fs->root.dentry, fs->root.mnt, saved_fs->root);
	sprint("pwd %s root %s mask %08x\n", saved_fs->pwd, saved_fs->root, saved_fs->umask);
	task->fs = saved_fs;
	insert_entry(head, fs, saved_fs);
	
}

int save_state_mutex_debug = 0;
int do_path_lookup(int dfd, const char *name,
		   unsigned int flags, struct nameidata *nd);


static void save_files(struct files_struct* files, struct saved_task_struct* task, struct map_entry* head)
{
	struct fdtable* fdt;
	unsigned int fd;
	struct saved_files* shared_files;

	// Check if the file descriptor table is shared between tasks
	if((shared_files = find_by_first(head, files)) != NULL)
	{
		sprint("Already saved shared files\n");
		task->open_files = shared_files;
		return;
	}

	// They are not shared or this is the first time files are saved
	shared_files = alloc(sizeof(*shared_files));
	sprint("shared_files %p\n", shared_files);
	insert_entry(head, files, shared_files);
	task->open_files = shared_files;

	INIT_LIST_HEAD(&shared_files->files);

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	
	sprint("files %p\n", files);
	sprint("max_fds: %d\n", fdt->max_fds);
	for(fd=0; fd<fdt->max_fds; fd++)
	{
		struct saved_file* file;
		struct file* f = fcheck_files(files, fd);
		struct shared_resource* file_res;

//		sprint("Bit set: %s\n", FD_ISSET(fd, fdt->open_fds) ? "yes" : "no");

		if(f == NULL)
			continue;
		
		if((file = find_by_first(head, f)) != NULL)
		{
			sprint("file %u %s is shared and was saved already\n", fd, file->name);
			file_res = alloc(sizeof(*file_res));
			INIT_LIST_HEAD(&file_res->list);
			file_res->data = file;
			file_res->fd = fd;
			list_add_tail(&file_res->list, &shared_files->files);
			continue;
		}

		file = (struct saved_file*)alloc(sizeof(*file));
		file_res = alloc(sizeof(*file_res));
		INIT_LIST_HEAD(&file_res->list);
		get_path_absolute(f, file->name);
		sprint("fd %d points to %s %p\n", fd, file->name, f);
		file_res->fd = fd;
		file->count = file_count(f);
		file->ino = f->f_dentry->d_inode->i_ino;
		sprint("link count %d\n", f->f_dentry->d_inode->i_nlink);
		if(f->f_dentry->d_inode->i_nlink == 0)
		{
			file->temporary = 1;
		}
		
		if(f->f_mode & FMODE_READ)
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
		}
		
		if(f->f_flags & O_NONBLOCK)
		{
			sprint("Setting O_NONBLOCK bit\n");
			file->flags |= O_NONBLOCK;
		}
		
		if(f->f_flags & O_LARGEFILE)
		{
			sprint("Saving large file\n");
			file->flags |= O_LARGEFILE;
		}

		file->pos = f->f_pos;

		if(file_is_vc_terminal(f))
		{
			save_vc_term_info(f, file);
		}
		else if (file_is_pipe(f))
		{
			save_pipe_info(task, f, file, head);
		}
		else if (file_is_socket(f))
		{
			sprint("fd %d is a socket\n", fd);
		  	save_socket_info(task, f, file, head);
		}

		file_res->data = file;
		list_add_tail(&file_res->list, &shared_files->files);
		insert_entry(head, f, file);
		
	}
	spin_unlock(&files->file_lock);
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
	int i;
	struct sighand_struct* sighand = task->sighand;
	sigset_t pending;
	struct sigpending* tmp;
	sigset_t* blocked;

	sigemptyset(&pending);
	spin_lock_irq(&sighand->siglock);
	for(i = 0; i<_NSIG; i++)
	{
		state->sighand.action[i] = sighand->action[i];
	}
	state->sighand.blocked = task->blocked;
	state->sighand.pending = task->pending.signal;
	state->sighand.shared_pending = task->signal->shared_pending.signal;

	list_for_each_entry(tmp, &task->pending.list, list)
	{
		sigorsets(&pending, &pending, &tmp->signal);
		sprint("Checking current->pending\n");
	}

	list_for_each_entry(tmp, &task->signal->shared_pending.list, list)
	{
		sigorsets(&pending, &pending, &tmp->signal);
		sprint("Checking current->signal->shared_pending\n");
	}


	state->sighand.state = task->state;

	switch(task_pt_regs(task)->orig_ax)
	{
	case 179:    // sigsuspend
		blocked  = (sigset_t*)alloc(sizeof(*blocked));
		sprint("Saving state to restart sigsuspend upon reboot\n");
		*blocked = task->saved_sigmask;
		state->syscall_data = blocked;
		break;
	case 102:  // socketcall
		if(state->registers.bx == SYS_SEND)
			break;

		//else fall through
	case 4:    // write
	case 162:  // nanosleep
	case 240:  // futex
	case 7:    // waitpid
	case 114:  // wait4
	case 142: // select
		state->syscall_restart = task_pt_regs(task)->orig_ax;
		sprint("Saving state to restore %d syscall\n", state->syscall_restart);
		state->syscall_data = NULL;
		break;
	}

	state->syscall_restart = task_pt_regs(task)->orig_ax;


	spin_unlock_irq(&sighand->siglock);
}

static void save_creds(struct task_struct* task, struct saved_task_struct* state)
{
	state->uid = task->real_cred->uid;
	state->euid = task->real_cred->euid;
	state->suid = task->real_cred->suid;
	state->fsuid = task->real_cred->fsuid;

	state->gid = task->real_cred->gid;
	state->egid = task->real_cred->egid;
	state->sgid = task->real_cred->sgid;
	state->fsgid = task->real_cred->fsgid;

	state->cap_effective = task->real_cred->cap_effective;
	state->cap_inheritable = task->real_cred->cap_inheritable;
	state->cap_permitted = task->real_cred->cap_permitted;
	state->cap_bset = task->real_cred->cap_bset;
}

static struct saved_task_struct* save_process(struct task_struct* task, struct map_entry* head)
{
	struct vm_area_struct* area = NULL;
	struct saved_task_struct* current_task = (struct saved_task_struct*)alloc(sizeof(*current_task));
	struct task_struct* child = NULL;
	struct saved_mm_struct* mm;
	int need_to_save_pages = 1;
	
	INIT_LIST_HEAD(&current_task->children);
	INIT_LIST_HEAD(&current_task->sibling);
	INIT_LIST_HEAD(&current_task->next);
	INIT_LIST_HEAD(&current_task->thread_group);
	INIT_LIST_HEAD(&current_task->vm_areas);

	sprint( "Target task %s pid: %d will be saved at %p\n", task->comm, task->pid, current_task);
	strcpy(current_task->name, task->comm);
	
	current_task->registers = *task_pt_regs(task);
	savesegment(gs, current_task->gs);
	memcpy(current_task->tls_array, task->thread.tls_array, GDT_ENTRY_TLS_ENTRIES*sizeof(struct desc_struct));
	
	mm = find_by_first(head, task->mm);
	if(mm == NULL)
	{
		sprint("mm %p not seen previously\n", task->mm);
		mm = (struct saved_mm_struct*)alloc(sizeof(*mm));
		INIT_LIST_HEAD(&mm->pages);
		insert_entry(head, task->mm, mm);
		save_pgd(task->mm, mm, head);
	}
	else
	{
		sprint("mm %p was seen before and was saved to %p\n", task->mm, mm);
		need_to_save_pages = 0;
	}
	current_task->mm = mm;
	current_task->mm->nr_ptes = task->mm->nr_ptes;
	current_task->mm->start_brk = task->mm->start_brk;
	current_task->mm->brk = task->mm->brk;
	current_task->pid = pid_vnr(task_pid(task));
	
	get_path_absolute(task->mm->exe_file, current_task->exe_file); 
	save_fs(task->fs, current_task, head);
	save_files(task->files, current_task, head);
	
	save_signals(task, current_task);
	save_creds(task, current_task);


	sprint("mm address %p\n", task->mm);
	

	for(area = task->mm->mmap; area != NULL; area = area->vm_next)
	{
		struct saved_vm_area* cur_area = NULL;
		struct shared_resource* elem = NULL;

		sprint( "Saving area:%08lx-%08lx\n", area->vm_start, area->vm_end);

		cur_area = (struct saved_vm_area*)alloc(sizeof(*cur_area));
		elem = (struct shared_resource*)alloc(sizeof(*elem));
		INIT_LIST_HEAD(&elem->list);
		elem->data = cur_area;

		list_add_tail(&elem->list, &current_task->vm_areas);

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
		cur_area->anon_vma = area->anon_vma ? 1 : 0;
		
		if(need_to_save_pages)
		{
			save_pages(current_task->mm, area, head);
		}

		if(area->vm_start <= task->mm->start_stack && area->vm_end >= task->mm->start_stack)
		{
			current_task->stack = cur_area;
			sprint("stack: %08lx-%08lx\n", cur_area->begin, cur_area->end);
		}

		insert_entry(head, area, cur_area);
		
	}

	list_for_each_entry(child, &task->children, sibling)
	{
		struct saved_task_struct* saved_child = save_process(child, head);
		list_add_tail(&saved_child->sibling, &current_task->children);
		sprint("Parent %d child %d\n", task->pid, child->pid);
	}

	return current_task;
	
}

static void save_running_processes(void)
{
	struct saved_state* state;
	struct task_struct* task;
	struct map_entry* head;
	
	read_lock(&tasklist_lock);
	
	head = new_map();
	state = (struct saved_state*)alloc(sizeof(*state));
	INIT_LIST_HEAD(&state->processes);

	//sprint( "State is at: %p\n", state);
	//sprint( "Processes are at: %p\n", state->processes);

	for_each_process(task)
	{
		struct task_struct* thread;
		sprint("pid %d group leader pid %d\n", task->pid, task->group_leader->pid);
		list_for_each_entry_rcu(thread, &task->thread_group, thread_group)
		{
			sprint("thread tid %d\n", thread->pid);
		}
	}
	
	
	sprint("head prev %p next %p\n", state->processes.prev, state->processes.next);
	for_each_process(task)
	{
		struct saved_task_struct* current_task = NULL;
		struct task_struct* thread;
	     
		if(!is_save_enabled(task)) continue;
		
		current_task = save_process(task, head);
		current_task->group_leader = 1;
		list_add_tail(&current_task->next, &state->processes);
		sprint("head prev %p next %p\n", state->processes.prev, state->processes.next);
		sprint("current prev %p next %p\n", current_task->next.prev, current_task->next.next);
		list_for_each_entry(thread, &task->thread_group, thread_group)
		{
			struct saved_task_struct* saved_thread;
			saved_thread = save_process(thread, head);
			list_add_tail(&saved_thread->thread_group, &current_task->thread_group);
			
		}
	}
	
	//sprint( "\n");
	read_unlock(&tasklist_lock);
}

static void print_saved_process(struct saved_task_struct* task)
{
	struct shared_resource* elem;
	struct saved_task_struct* child;
	sprint( "Next process is at: %p\n", task);
	sprint( "%s %s\n", task->name, task->exe_file);
	
	print_regs(&task->registers);
	/* sprint("Memory: %p\n", task->mm); */
	/* list_for_each_entry(elem, &task->mm->pages, list) */
	/* { */
	/* 	struct saved_page* page = (struct saved_page*)elem->data; */
	/* 	struct page* p = pfn_to_page(page->pfn); */
	/* 	sprint("pfn: %lx, count: %d, flags: %08lx, reserved: %s\n", page->pfn, atomic_read(&p->_count),  */
	/* 	       p->flags, PageReserved(p) ? "yes" : "no"); */
	/* } */

	sprint("Files: %p\n", &task->open_files->files);
	list_for_each_entry(elem, &task->open_files->files, list)
	{
		struct saved_file* file = elem->data;
		sprint("fd: %u - %s\n", elem->fd, file->name);
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
	sprint( "State is at: %p\n", state);
	sprint("head prev %p next %p\n", state->processes.prev, state->processes.next);
	list_for_each_entry(task, &state->processes, next)
	{
		print_saved_process(task);
	}
}

static void prepare_shutdown(void)
{
	device_shutdown();
	sysdev_shutdown();
	machine_shutdown();
}

static int load_state = 0;
static int fr_reboot_notifier(struct notifier_block* this, unsigned long code, void* x)
{
//	prepare_shutdown();
	save_running_processes();
	sprint( "State saved\n");
	return 0;
}

asmlinkage void sys_save_state(void)
{
	save_running_processes();
	print_saved_processes();
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
//	sprint("State was restored for proccess %d, current->pid: %d\n", p->pid, task->pid);
}


int was_state_restored(struct task_struct* task)
{
	struct save_state_permission* cur = state_restored;
//	sprint("Checking restore state for %d\n", task_pid_nr(task));
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
	/* if(ret) */
	/* { */
	/* 	sprint("State was restored for process %d\n", task_pid_nr(current)); */
	/* } */
	/* else */
	/* { */
	/* 	sprint("State was not restored for process %d\n", task_pid_nr(current)); */
	/* } */
	return ret;
}

int set_state_present()
{
	struct saved_state* state;
	state = (struct saved_state*)get_reserved_region();
	return !list_empty(&state->processes);
}

void test_restore_sockets(void);
asmlinkage int sys_state_present(struct pt_regs regs)
{
	return set_state_present();
}

extern struct resource crashk_res;
asmlinkage int sys_load_saved_state(struct pt_regs regs)
{
	int ret;

	struct saved_state* state;
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

	if(list_empty(&state->processes))
	{
		sprint( "No more saved state\n");
		return -1;
	}
 
	print_saved_processes();
	ret = set_state(&regs, list_first_entry(&state->processes, struct saved_task_struct, next));
	sprint( "set_state returned %d\n", ret);
/*   if(ret == 0) */
/*   { */
/* 	  state->processes = state->processes->next; */
/* 	  add_to_restored_list(current); */
/*   } */
	return regs.ax;
}
