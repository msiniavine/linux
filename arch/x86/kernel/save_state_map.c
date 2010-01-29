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

#include <linux/set_state.h>

struct map_entry
{
	struct list_head list;
	void* first;
	void* second;
};


struct map_entry* new_map(void)
{
	struct map_entry* head = (struct map_entry*)kmalloc(sizeof(*head), GFP_KERNEL);
	INIT_LIST_HEAD(&head->list);
	head->first = head->second = NULL;
	return head;
}

void delete_map(struct map_entry* head)
{
	sprint("Delete not yet implemented\n");
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
