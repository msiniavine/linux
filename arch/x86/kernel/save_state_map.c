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

#include <linux/set_state.h>

static unsigned long  page_pool[100];
static int page_pool_index = -1;
static int page_offset = PAGE_SIZE;
static int map_count = 0;

static void* alloc_map(size_t size)
{
	unsigned long ret;
	if(page_offset + size > PAGE_SIZE)
	{
		page_pool_index++;
		if(page_pool_index >= 100)
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
	
	//sprint( "##### Allocating new \'struct map_entry\'.\n" );
	
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
	sprint("Delete not yet implemented\n");
}

// insert_entry() inserts a map_entry object after the map_entry object pointed to by head.
void insert_entry(struct map_entry* head, void* first, void* second)
{
  	// Creates an initializes a new map_entry and then inserts it into a
  	// doubly-linked list.
	struct map_entry* new_entry = new_map();
	new_entry->first = first;
	new_entry->second = second;
	list_add_tail(&new_entry->list, &head->list);
	//
}
//

// Appears to search through a doubly-linked list of map_entry objects by giving a pointer
// to a "first" object and if that first is found, returns a pointer to the "second".
void* find_by_first(struct map_entry* head, void* first)
{
  	// list_for_each_entry() is a macro that is used create a for loop that
  	// goes through a circular-doubly-linked list.  The pointer cur is set to
  	// point, in this case, a map_entry object in the list?
	struct map_entry* cur;
	list_for_each_entry(cur, &head->list, list)
	{
		if(cur->first == first)
		{
			return cur->second;
		}
	}
	//

	return NULL;
}
//
