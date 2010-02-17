#include <linux/signal.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/syscalls.h>
#include <asm/linkage.h>
#include <linux/set_state.h>
#include <asm/pgtable.h>
#include <linux/bootmem.h>
#include <linux/ioport.h>
#include <asm/e820.h>
#include <linux/fdtable.h>


static int fr_reboot_notifier(struct notifier_block*, unsigned long, void*);
static struct notifier_block fr_notifier = {
  .notifier_call = fr_reboot_notifier,
    .next = NULL,
    .priority=INT_MAX
    };

static unsigned long get_reserved_region(void)
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

/* static void save_page_table(unsigned long address) */
/* { */
/* 	int i; */
/* 	struct page* page = pfn_to_page(address >> PAGE_SHIFT); */
/* 	pte_t* pte = (pte_t*)kmap(page); */
/* 	if(pte == NULL) */
/* 	{ */
/* 		sprint( "Could not map page table at address %08lx\n", address); */
/* 		return; */
/* 	} */
/* 	for(i = 0; i < 1024; i++) */
/* 	{ */
/* 		if(pte_present(pte[i]) && pte[i].pte != 0) */
/* 		{ */
/* 			unsigned long physical_address = (pte[i].pte & 0xfffff000); */
/* 			sprint( "pte %08lx points to %08lx\n", pte[i].pte, physical_address); */
/* 	      		if(reserve_bootmem(physical_address, PAGE_SIZE, BOOTMEM_EXCLUSIVE) < 0) */
/* 			{ */
/* 				sprint( "Failed to reserve page at %08lx\n", physical_address); */
/* 			} */
/* 			else */
/* 			{ */
/* 				sprint( "Reserved page at %08lx\n", physical_address); */
/* 			} */

/* 		} */
/* 	} */
/* 	kunmap(page); */
/* } */
static void reserve_process_memory(struct saved_task_struct* task)
{
	struct shared_resource* elem;
	struct saved_task_struct* child;
	list_for_each_entry(elem, &task->mm->pages->list, list)
	{
		struct saved_page* page = (struct saved_page*)elem->data;
		if(reserve(page->pfn << PAGE_SHIFT, PAGE_SIZE) < 0)
		{
			sprint("Failed to reserve pfn: %ld\n", page->pfn);
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


 /*static void print_page(unsigned long address, struct mm_struct* mm)
{
  struct page* page;
  pgd_t* pgd;
  pmd_t* pmd;
  pte_t* pte;


  pgd = pgd_offset(mm, address);
  if(pgd_none(*pgd) || pgd_bad(*pgd))
    {
      sprint( "%p has an invalid pgd\n", (void*)address);
      return;
    }

  pmd = pmd_offset(pgd, address);
  if(pmd_none(*pmd) || pmd_bad(*pmd))
    {
      sprint( "%p has an invalid pmd\n", (void*)address);
      return;
    }

  pte = pte_offset_map(pmd, address);
  if(!pte)
    {
      sprint( "%p does not have a pte\n", (void*)address);
      return;
    }

  page = pte_page(*pte);
  sprint( "Address %p maps to struct page at %p\n", (void*)address, page);
  sprint( "PFN is: %p physical address is: %p\n", (void*)page_to_pfn(page), (void*)(page_to_pfn(page) << PAGE_SHIFT));
 pte_unmap(pte);

 }*/


static pte_t* get_pte(struct mm_struct* mm, unsigned long virtual_address)
{
  pgd_t* pgd;
  pmd_t* pmd;
  pte_t* pte;


  pgd = pgd_offset(mm, virtual_address);
  if(pgd_none(*pgd) || pgd_bad(*pgd))
    {
	    //sprint( "%p has an invalid pgd\n", (void*)virtual_address);
      return NULL;
    }
  if(!pgd_present(*pgd))
  {
	  //sprint( "%p is not present in pgd\n", (void*)virtual_address);
	  return NULL;
  }

  pmd = pmd_offset(pgd, virtual_address);
  if(pmd_none(*pmd) || pmd_bad(*pmd))
    {
	    //sprint( "%p has an invalid pmd\n", (void*)virtual_address);
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
	sprint( "Address %p maps to struct page at %p\n", (void*)virtual_address, page);
	sprint( "PFN is: %p physical address is: %p\n", (void*)page_to_pfn(page), (void*)(page_to_pfn(page) << PAGE_SHIFT));
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
			continue;
//		sprint( "Saving page at address: %08lx\n", virtual_address);

		//	sprint( "Allocated saved_page at: %p\n", page);
		//sprint( "Physical address was: %08lx\n", physical_address);

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
		if(mm->pages == NULL)
		{
			mm->pages = elem;
		}
		else
		{
			list_add(&elem->list, &mm->pages->list);
		}

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

		if(saved_mm->pages == NULL)
		{
			saved_mm->pages = elem;
		}
		else
		{
			list_add(&elem->list, &saved_mm->pages->list);
		}
		

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

static void get_file_path(struct file* f, char* filename)
{
	struct dentry* cur;
	char* begin, *end;

	cur = f->f_path.dentry;
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
}

static void save_files(struct files_struct* files, struct saved_task_struct* task)
{
	struct fdtable* fdt;
	unsigned int fd;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	
	sprint("max_fds: %d\n", fdt->max_fds);
	for(fd = 3; fd<fdt->max_fds; fd++)  // start with 3 because 0,1,2 are not really files
	{
		struct saved_file* file;
		struct file* f = fcheck_files(files, fd);
		if(f == NULL)
			continue;
		file = (struct saved_file*)alloc(sizeof(*file));
		get_file_path(f, file->name);
		sprint("fd %d points to %s\n", fd, file->name);
		file->fd = fd;
		file->next = task->open_files;
		task->open_files = file;
		
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
	//state->sighand.restart_needed = task->syscall_restart;

	spin_unlock_irq(&sighand->siglock);
}

static void save_creds(struct task_struct* task, struct saved_task_struct* state)
{
	state->uid = task->uid;
	state->euid = task->euid;
	state->suid = task->suid;
	state->fsuid = task->fsuid;

	state->gid = task->gid;
	state->egid = task->egid;
	state->sgid = task->sgid;
	state->fsgid = task->fsgid;

	state->cap_effective = task->cap_effective;
	state->cap_inheritable = task->cap_inheritable;
	state->cap_permitted = task->cap_permitted;
	state->cap_bset = task->cap_bset;
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
	
	get_file_path(task->mm->exe_file, current_task->exe_file); 
	save_files(task->files, current_task);
	
	save_signals(task, current_task);
	save_creds(task, current_task);


	sprint("mm address %p\n", task->mm);
	

	for(area = task->mm->mmap; area != NULL; area = area->vm_next)
	{
		struct saved_vm_area* prev = find_by_first(head, area);
		struct saved_vm_area* cur_area = NULL;
		struct shared_resource* elem = NULL;

		sprint( "Saving area:%08lx-%08lx\n", area->vm_start, area->vm_end);
		sprint( "Current area: %p\n", cur_area);
		sprint( "Current_task %p\n", current_task);

		cur_area = (struct saved_vm_area*)alloc(sizeof(*cur_area));
		elem = (struct shared_resource*)alloc(sizeof(*elem));
		elem->data = cur_area;
		INIT_LIST_HEAD(&elem->list);

		if(current_task->memory == NULL)
		{
			current_task->memory = elem;
		}
		else
		{
			list_add(&elem->list, &current_task->memory->list);
		}

		if(prev == NULL)
		{
			sprint("No previous area found\n");
		}
		else
		{
			sprint("Previous area found at %p\n", prev);
		}
		

		cur_area->begin = area->vm_start;
		cur_area->end = area->vm_end;
		if(area->vm_file)
		{
			cur_area->filename = (char*)alloc(256);
			get_file_path(area->vm_file, cur_area->filename);
		}
		cur_area->protection_flags = area->vm_page_prot;
		cur_area->vm_flags = area->vm_flags;
		cur_area->vm_pgoff = area->vm_pgoff;
		
		if(need_to_save_pages) save_pages(current_task->mm, area, head);
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
	task = find_task_by_vpid(1);
	
	if(task == NULL)
	{
		sprint( "Could not find the init process\n");
		read_unlock(&tasklist_lock);
		return;
	}
	
	head = new_map();
	state = (struct saved_state*)alloc(sizeof(*state));
	state->processes = NULL;

	//sprint( "State is at: %p\n", state);
	//sprint( "Processes are at: %p\n", state->processes);
	
	
	for_each_process(task)
	{
		struct saved_task_struct* current_task = NULL;
	     
		if(!is_save_enabled(task)) continue;
		
		current_task = save_process(task, head);
		current_task->next = state->processes;
		state->processes = current_task;
	}
	
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
	list_for_each_entry(elem, &task->mm->pages->list, list)
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
	sprint( "State is at: %p\n", state);
	for(task=state->processes; task!=NULL; task = task->next)
	{
		print_saved_process(task);
	}
}

static int load_state = 0;
static int fr_reboot_notifier(struct notifier_block* this, unsigned long code, void* x)
{
	save_running_processes();
	sprint( "State saved\n");
	return 0;
}

asmlinkage void sys_save_state(void)
{
	save_running_processes();
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
	struct save_state_permission* p = kmalloc(sizeof(*p), GFP_KERNEL);
	p->pid = pid_vnr(task_pid(current));
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
			sprint("State was restored for process %d\n", task_pid_nr(task));
			return 1;
		}
	}
	sprint("State was not restored for process %d\n", task_pid_nr(task));
	return 0;
}

asmlinkage int sys_was_state_restored(struct pt_regs regs)
{
	return was_state_restored(current);
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

  if(state->processes == NULL)
  {
	  sprint( "No more saved state\n");
	  return -1;
  }
 
  print_saved_processes();
  ret = set_state(&regs, state->processes);
  sprint( "set_state returned %d\n", ret);
/*   if(ret == 0) */
/*   { */
/* 	  state->processes = state->processes->next; */
/* 	  add_to_restored_list(current); */
/*   } */
  return regs.ax;
}
