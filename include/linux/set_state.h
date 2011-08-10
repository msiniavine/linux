
#define FASTREBOOT_REGION_SIZE 64 * 1024 * 1024
#define FASTREBOOT_REGION_START (0x1000000 + FASTREBOOT_REGION_SIZE)
void reserve_saved_memory(void);


extern int set_stack_state;
extern struct saved_vm_area* saved_stack;
struct saved_task_struct;
struct socket;

unsigned long get_reserved_region(void);

void print_regs(struct pt_regs* regs);
int set_state(struct pt_regs* regs, struct saved_task_struct* state);
int is_save_enabled(struct task_struct*);
int was_state_restored(struct task_struct*);
void add_to_restored_list(struct task_struct*);
int sock_attach_fd(struct socket *sock, struct file *file, int flags);
struct page* alloc_specific_page(unsigned long pfn, int mapcount);

// TCP hook used to drop some incoming tcp packets until the state is restored
void set_state_tcp_hook(void);
void unregister_set_state_hook(void);

#define STATE_DEBUG 1
#if STATE_DEBUG
extern int debug_was_state_restored;
#define sprint(format, ...) printk(KERN_EMERG format, ##__VA_ARGS__)
#define csprint(format, ...) if(debug_was_state_restored) printk(KERN_EMERG format, ##__VA_ARGS__)
#else
#define sprint(format, ...)
#define csprint(format, ...)
#endif

// Enable some cheesy work arounds, in tcp 
#define SET_STATE_HAX 1

#define tlprintf(format, ...) {		       \
		struct task_struct* __tsk = current;		\
		if(!strcmp("test_sockload", __tsk->comm))		\
			printk(KERN_EMERG format, ##__VA_ARGS__); }

static void inline busy_wait(unsigned long timeout)
{
	unsigned long j = jiffies+timeout*HZ;
	while(time_before(jiffies, j))
		cpu_relax();
}

struct map_entry;

struct map_entry* new_map(void);
void delete_map(struct map_entry*);
void insert_entry(struct map_entry* head, void* first, void* second);
void* find_by_first(struct map_entry* head,  void* first);

#ifndef SET_STATE_ONLY_FUNCTIONS
#define PATH_LENGTH 256
#define PIPE_BUFFERS (16)

// File types
#define REGULAR_FILE 0
#define READ_PIPE_FILE 1
#define WRITE_PIPE_FILE 2
#define READ_FIFO_FILE 3
#define WRITE_FIFO_FILE 4
// Terminal that outputs to a virtual console
#define VC_TTY  5
#define SOCKET 6

struct saved_inet_sock
{     
	__be32			daddr;
	__be32			rcv_saddr;
	__be16			dport;
	__u16			num;
	__be32			saddr;
	__be16			sport;
};

struct saved_sk_buff
{
	unsigned int len;
	__wsum csum;
	int ip_summed;
	u32 seq;
	void* content;
	struct list_head list;
};

struct saved_tcp_state
{
	int state;
	__be32 daddr;
	__be32 saddr;
	__be16 sport;  // source port in host format
	__be16 dport; // destination port in host format

	unsigned short backlog; // listen socket backlog

	//inet_connection_sock state
	int rcv_mss;
	
	//tcp_sock state
	u32 rcv_nxt;
	u32 rcv_wnd;
	u32 rcv_wup;

	// Notice that snd_nxt and write_seq are missing
	// snd_una is where tcp needs to be restarted
	// because its the data thats been sent but unacknowledged
	// data from this point on will have to be retransmitted
	// and and write_seq need to be recalculated from this point on
	u32 snd_nxt;
	u32 snd_una;

	u32 snd_wl1;
	u32 snd_wnd;
	u32 max_window;

	u32 window_clamp;
	u32 rcv_ssthresh;
	u16 advmss;

	u32 pred_flags;
	u16 tcp_header_len;

	int rcv_wscale;

	u32 copied_seq;

	u32 mss_cache;
	u16 xmit_size_goal;
	u32 dst_mtu;  // 0 if dst is not available
	u32 rx_opt_mss_clamp;

	u32 sk_sndbuf;

	u32 nonagle;
	struct list_head sk_buffs;
	int num_saved_buffs; // number of saved socket buffers

};


// for returning from the tcp socket read/write system calls with the right number of
// bytes to maintain the correct progress
struct tcp_io_progress
{
	int progress;
};

struct saved_socket
{
        int		        state;
	short			type;
	unsigned long		flags;
        wait_queue_head_t	wait;
        unsigned char		sock_protocol;
	unsigned short		sock_type;
	unsigned short		sock_family;
        struct saved_inet_sock  inet;
	struct saved_tcp_state* tcp;
  int userlocks;
  int binded;
};


struct saved_ipv6_pinfo
{
  //ignore ipv6 for now
};



struct saved_pipe_buffer {
	struct page *page;
	unsigned int offset, len;
};

struct saved_pipe
{
	unsigned int nrbufs, curbuf;
	struct inode *inode;
	struct saved_pipe_buffer bufs[PIPE_BUFFERS];
};

struct pipe_pidlist
{
	struct pipe_pidlist* next;
	pid_t process;
};

struct pipe_restore_temp
{
	struct pipe_restore_temp* next;
	unsigned int type;
	struct inode* pipe_id;
	struct pipe_pidlist* processlist;
	unsigned int read_fd, write_fd;
	struct file *read_file, *write_file;
};

struct pipes_to_close
{
	struct pipes_to_close* next;
	pid_t process;
	unsigned int fd;
};

struct saved_vc_data
{
	int rows;
	int cols;
	int index;
	int screen_buffer_size;
	unsigned char* screen_buffer;
	unsigned int x, y;
};

struct saved_file
{
	unsigned int type;
	char name[PATH_LENGTH];
	unsigned int fd;
	long count;
	int flags;
	struct saved_pipe pipe;
	struct saved_vc_data* vcd;
	struct saved_socket socket;
	struct list_head next;
};

struct saved_page
{
	unsigned long pfn;
	int mapcount;
};

struct shared_resource
{
	void* data;  
	struct shared_resource* next;
};

struct saved_vm_area
{
	unsigned long begin, end;
	char* filename;
	pgprot_t protection_flags;
	unsigned long vm_flags;
	unsigned long vm_pgoff;
};

struct saved_sighand
{
	struct k_sigaction action[_NSIG];
	sigset_t blocked;

	sigset_t pending;
	sigset_t shared_pending;

	int state;
};

#define SAVED_PGD_SIZE 3*256

struct saved_mm_struct
{
	unsigned long start_brk, brk;
	unsigned long nr_ptes;
	struct shared_resource* pages;
	pgd_t pgd[SAVED_PGD_SIZE];  // leave the upper 256 out of 1024 entries unchanged because they are used by the kernel
};


struct saved_task_struct
{
	struct saved_task_struct* next;
	
	struct list_head children, sibling;
	
	struct saved_mm_struct* mm;

	struct shared_resource* memory;
	struct saved_vm_area* stack;

	char name[16];

	struct pt_regs registers;
	unsigned int gs;                                      // gs registor is not saved automatically
	struct desc_struct tls_array[GDT_ENTRY_TLS_ENTRIES];  // Thread local storage segment descriptors



	char exe_file[PATH_LENGTH];         // name of the executable file
	struct list_head open_files;

	pid_t pid;

	struct saved_sighand sighand;

	uid_t uid,euid,suid,fsuid;
	gid_t gid,egid,sgid,fsgid;
	kernel_cap_t   cap_effective, cap_inheritable, cap_permitted, cap_bset;

	// number of the system call to restart, 0 if returning restarting directly to user space
	int syscall_restart; 
	void* syscall_data;  // what ever data needed to restart a system call

};


struct saved_state
{
  struct saved_task_struct* processes;
};

struct global_state_info
{
	wait_queue_head_t wq;
	atomic_t processes_left;

	struct completion all_done;
	struct pipe_restore_temp *pipe_restore_head;
	struct pipes_to_close *pipe_close_head;
};

#endif
