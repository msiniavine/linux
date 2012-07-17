
#define FASTREBOOT_REGION_SIZE 64 * 1024 * 1024
#define FASTREBOOT_REGION_START (0x1000000 + FASTREBOOT_REGION_SIZE)
void reserve_saved_memory(void);


extern int set_stack_state;
extern struct saved_vm_area* saved_stack;
struct saved_task_struct;
struct socket;

unsigned long get_reserved_region(void);

struct pt_regs;
void print_regs(struct pt_regs* regs);
int set_state(struct pt_regs* regs, struct saved_task_struct* state);
int is_save_enabled(struct task_struct*);
int was_state_restored(struct task_struct*);
void add_to_restored_list(struct task_struct*);
int sock_attach_fd(struct socket *sock, struct file *file, int flags);
struct page* alloc_specific_page(unsigned long pfn, int mapcount);
int set_state_present(void);
int save_state(void);
void save_running_processes(void);
int are_user_tasks_ready(void);
int are_all_tasks_ready(void);
void install_syscall_blocker(void);
void activate_syscall_blocker(void);
void hardlink_temp_files(void);

// timing specific functions
void time_start_quiescence(void);
void time_end_quiescence(void);
void time_start_checkpoint(void);
void time_end_checkpoint(void);
void time_start_kernel_init(void);
void time_end_kernel_init(void);
void time_start_restore(void);
void time_end_restore(void);

// TCP hook used to drop some incoming tcp packets until the state is restored
void set_state_tcp_hook(void);
void unregister_set_state_hook(void);
void unblock_port(u16 port);

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
		if(!strcmp("test_loop", __tsk->comm))		\
			printk(KERN_INFO format, ##__VA_ARGS__); }

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

struct saved_state
{
	struct list_head processes;
	unsigned long checkpoint_size;
	struct timespec start_quiescence, end_quiescence, start_checkpoint, end_checkpoint;
};


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
	char cb[48];
	unsigned int len;   // length of the data in the buffer
	__wsum csum;        // partial tcp checksum of this buffer
	int ip_summed;     
	u32 seq;            // sequence number of the first byte of this packet 
	u32 tstamp;         // timestamp of this packet
	u8 flags;           // tcp flags
	void* content;      // data in this packet
	struct list_head list;
};

struct saved_tcp_state
{
	int state;
	__be32 daddr;
	__be32 saddr;
	__be16 sport;  // source port in host format
	__be16 dport; // destination port in host format


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
	int snd_wscale;

	u32 copied_seq;

	u32 mss_cache;
	u16 xmit_size_goal;
	u32 dst_mtu;  // 0 if dst is not available
	u32 rx_opt_mss_clamp;

	// Packets in flight and congestion window
	u32 packets_in_flight;
	u32 snd_cwnd;

	// RTT setting 
	u32 rto;
	u32 srtt; // smoothed rtt << 3
	u32 mdev;
	u32 mdev_max;
	u32 rttvar;
	u32 rtt_seq;

	// How do we handle the time stamps?
	// We calculate the offset that needs to be added to the current time to generate the right timestamp
	// but the initial current time is set to -5 minutes in unsigned int
	// so the offset is calculated as:
	// offset = current1-current2
	// where current1 was the current time during save state and current2 is the current time after restore
	// tcp_tstamp_offset is the saved current time
	u32 tcp_tstamp_offset;

	u32 timestamp_ok; // Are we doing tcp timestamps
	u32 tsval;
	u32 tsecr;
	u32 saw_tstamp;
	u32 ts_recent;
	u32 ts_recent_stamp;

	struct tcp_options_received rx_opt;

	u32 sk_sndbuf;

	u32 nonagle;
	struct list_head sk_buffs;
	int num_saved_buffs; // number of saved socket buffers
	int num_rcv_queue;

};


// for returning from the tcp socket read/write system calls with the right number of
// bytes to maintain the correct progress
struct tcp_io_progress
{
	int progress;
};

// unix socket states
enum {	SOCKET_NONE,
	SOCKET_BOUND,
	SOCKET_ACCEPTED,
	SOCKET_CONNECTED };

struct saved_unix_address
{
	struct sockaddr_un address;
	int length;
};

struct saved_unix_socket
{
	int kind;
	int state;
	
	struct saved_unix_socket *peer;
	struct saved_unix_socket *listen;
	
	unsigned int shutdown;
	struct ucred peercred;

	struct saved_unix_address unix_address;
	
	uid_t user;
	gid_t group;
	
	struct list_head sk_buffs;
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
	unsigned short backlog; // listen socket backlog
        struct saved_inet_sock  inet;
	struct saved_tcp_state* tcp;
	struct saved_unix_socket unx;
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

	unsigned char vc_mode;
	unsigned short v_active;
	struct vt_mode vt_mode;
	pid_t vt_pid;
	struct ktermios kterm;
	unsigned char kbdmode :2;

};

//
struct saved_fown_struct
{
	pid_t pid;
	enum pid_type pid_type;
	uid_t uid, euid;
	int signum;
};
//

struct saved_file
{
	unsigned int type;
	char name[PATH_LENGTH];    // original true file name
	long count;
	int flags;
	loff_t pos;

	struct saved_fown_struct owner;

	int temporary;  // true if the file is a temporary file
	unsigned long ino;  // inode number
	struct saved_pipe pipe;
	struct saved_vc_data* vcd;
	struct saved_socket socket;
};

struct saved_page
{
	unsigned long pfn;
	int mapcount;
};

struct shared_resource
{
	void* data;  
	int fd;               // file descriptor if pointing to a shared file
	struct list_head list;
};

struct saved_vm_area
{
	unsigned long begin, end;
	char* filename;
	pgprot_t protection_flags;
	unsigned long vm_flags;
	unsigned long vm_pgoff;

	// true if this vma needs an anon_vma structure
	// for anonymous rmap
	int anon_vma;
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
	struct list_head pages;
	pgd_t pgd[SAVED_PGD_SIZE];  // leave the upper 256 out of 1024 entries unchanged because they are used by the kernel
};

struct saved_files
{
	struct list_head files;
};

struct saved_fs_struct
{
	int umask;
	char pwd[PATH_LENGTH];
	char root[PATH_LENGTH];
};

struct saved_task_struct
{
	struct list_head next;
	
	struct list_head children, sibling;

	int group_leader;
	struct list_head thread_group;
	
	struct saved_mm_struct* mm;

	struct list_head vm_areas;
	struct saved_vm_area* stack;

	char name[16];

	struct pt_regs registers;
	unsigned int gs;                                      // gs registor is not saved automatically
	struct desc_struct tls_array[GDT_ENTRY_TLS_ENTRIES];  // Thread local storage segment descriptors



	char exe_file[PATH_LENGTH];         // name of the executable file
	struct saved_files* open_files;
	struct saved_fs_struct* fs;

	pid_t pid;

	struct saved_sighand sighand;

	uid_t uid,euid,suid,fsuid;
	gid_t gid,egid,sgid,fsgid;
	kernel_cap_t   cap_effective, cap_inheritable, cap_permitted, cap_bset;

	// number of the system call to restart, 0 if returning restarting directly to user space
	int syscall_restart; 
	void* syscall_data;  // what ever data needed to restart a system call

};



struct global_state_info
{
	wait_queue_head_t wq;
	atomic_t processes_left;

	struct completion all_done;
	struct pipe_restore_temp *pipe_restore_head;
	struct pipes_to_close *pipe_close_head;
};

struct map_entry
{
	struct list_head list;
	void* first;
	void* second;
};


#endif
