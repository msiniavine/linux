
#define FASTREBOOT_REGION_SIZE 64 * 1024 * 1024
#define FASTREBOOT_REGION_START (0x1000000 + FASTREBOOT_REGION_SIZE)

#define PATH_LENGTH 256
struct saved_file
{
	char name[PATH_LENGTH];
	unsigned int fd;
	struct saved_file* next;
};

struct saved_page
{
	unsigned long pfn;
	int mapcount;
};

struct shared_resource
{
	void* data;  
	struct list_head list;
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
	struct saved_file* open_files;

	pid_t pid;

	struct saved_sighand sighand;

	uid_t uid,euid,suid,fsuid;
	gid_t gid,egid,sgid,fsgid;
	kernel_cap_t   cap_effective, cap_inheritable, cap_permitted, cap_bset;

};


struct saved_state
{
  struct saved_task_struct* processes;
};

extern int set_stack_state;
extern struct saved_vm_area* saved_stack;

void print_regs(struct pt_regs* regs);
int set_state(struct pt_regs* regs, struct saved_task_struct* state);
void reserve_saved_memory(void);
int is_save_enabled(struct task_struct*);
int was_state_restored(struct task_struct*);
void add_to_restored_list(struct task_struct*);

struct page* alloc_specific_page(unsigned long pfn, int mapcount);

#define STATE_DEBUG 1
#if STATE_DEBUG
#define sprint(format, ...) printk(KERN_EMERG format, ##__VA_ARGS__)
#define csprint(format, ...) if(is_save_enabled(current)) printk(KERN_EMERG format, ##__VA_ARGS__)
#else
#define sprint(format, ...)
#define csprint(format, ...)
#endif

struct map_entry;

struct map_entry* new_map(void);
void delete_map(struct map_entry*);
void insert_entry(struct map_entry* head, void* first, void* second);
void* find_by_first(struct map_entry* head,  void* first);

