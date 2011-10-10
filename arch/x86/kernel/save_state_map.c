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

#include <linux/list.h>

#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/skbuff.h>

//#include <linux/set_state.h>

static unsigned long  page_pool[40];
static int page_pool_index = -1;
static int page_offset = PAGE_SIZE;
static int map_count = 0;

struct map_entry
{
	struct list_head list;
	void* first;
	void* second;
};

static void* alloc_map(size_t size)
{
	unsigned long ret;
	if(page_offset + size > PAGE_SIZE)
	{
		page_pool_index++;
		if(page_pool_index >= 40)
		{
			panic("no more memory\n");
		}
		page_offset = 0;
		page_pool[page_pool_index] = __get_free_page(GFP_ATOMIC);
	}
	ret = page_pool[page_pool_index]+page_offset;
	page_offset+=size;
	return (void*)ret;
}

struct map_entry* new_map(void)
{
	struct map_entry* head;
	map_count++;
	head = (struct map_entry*)alloc_map(sizeof(*head));
	if(head == NULL)
	{
		panic("Not enough memory\n");
	}
	INIT_LIST_HEAD(&head->list);
	head->first = head->second = NULL;
	return head;
}

void delete_map(struct map_entry* head)
{
//	sprint("Delete not yet implemented\n");
}

void insert_entry(struct map_entry* head, void* first, void* second)
{
	struct map_entry* new_entry = new_map();
	new_entry->first = first;
	new_entry->second = second;
	list_add_tail(&new_entry->list, &head->list);
}

void* find_by_first(struct map_entry* head, void* first)
{
	struct map_entry* cur;
	list_for_each_entry(cur, &head->list, list)
	{
		if(cur->first == first)
		{
			return cur->second;
		}
	}

	return NULL;
}
