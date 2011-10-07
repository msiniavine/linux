#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/un.h>

#include <linux/set_state.h>

static LIST_HEAD(blocked_ports);
static spinlock_t ports_lock = SPIN_LOCK_UNLOCKED;
static int hook_installed = 0;

struct port_entry
{
	u16 port;
	struct list_head lh;
};

// checks if the port is being blocked
// caller mush hold the lock
static int is_blocked(u16 port)
{
	struct port_entry* pe;
	list_for_each_entry(pe, &blocked_ports, lh)
	{
		if(port == pe->port)
			return 1;
	}

	return 0;
}

static unsigned int set_state_tcp_rx_hook(unsigned int hook, struct sk_buff* skb, const struct net_device* in, const struct net_device* out, 
					  int (*okfn)(struct sk_buff*))
{
	struct tcphdr* th;
	struct iphdr* ih;
	u16 port;
	
	if(!skb) return NF_ACCEPT;

	ih = ip_hdr(skb);
	if(!ih) return NF_ACCEPT;
	if(ih->protocol != IPPROTO_TCP)
	{ 
		return NF_ACCEPT;
	}

	th = (struct tcphdr*)((u32*)ih + ih->ihl);
	port = ntohs(th->dest);

	if(is_blocked(port))
	{
		sprint("BLOCK: seq %u ack %u port %u\n", ntohl(th->seq), ntohl(th->ack), port);
		return NF_DROP;
	
	}
	return NF_ACCEPT;
}

static struct nf_hook_ops set_state_ops = 
{
	.hook = set_state_tcp_rx_hook,
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_RAW
};

void block_port(u16 port)
{
	struct port_entry* pe;
	sprint("BLOCK: Blocking port %u\n", port);
	pe = kmalloc(sizeof(*pe), GFP_KERNEL);
	if(!pe)
	{
		return; 
	}
	pe->port = port;
	list_add_tail(&pe->lh, &blocked_ports);
}

void unblock_port(u16 port)
{
	struct port_entry* pe = NULL;
	list_for_each_entry(pe, &blocked_ports, lh)
	{
		if(pe->port == port)
		{
			list_del(&pe->lh);
			break;
		}
	}
	kfree(pe);

	sprint("BLOCK: unblock %u\n", port);
}

int blocking_ports(void)
{
	int empty;
	empty = list_empty(&blocked_ports);
	return !empty;
}

static void find_blocked_ports_tsk(struct saved_task_struct* tsk)
{
	struct shared_resource* file_iter;
	struct saved_task_struct* child;

	sprint("BLOCK: blocking ports for task %s[%d]\n", tsk->name, tsk->pid);
	list_for_each_entry(file_iter, &tsk->open_files->files, list)
	{
		struct saved_file* file;
		struct saved_socket* socket;
		struct saved_tcp_state* tcp;

		file = file_iter->data;

		if(file->type != SOCKET) continue;

		socket = &file->socket;
		tcp = socket->tcp;

		if(tcp == NULL) continue;
		if(is_blocked(tcp->sport)) continue;

		block_port(tcp->sport);

	}

	list_for_each_entry(child, &tsk->children, sibling)
	{
		find_blocked_ports_tsk(child);
	}
}

static void find_blocked_ports(void)
{
	struct saved_state* state;
	struct saved_task_struct* tsk;

	state = (struct saved_state*)get_reserved_region();

	if(list_empty(&state->processes)) return;

	list_for_each_entry(tsk, &state->processes, next)
	{
		find_blocked_ports_tsk(tsk);
	}
}

void set_state_tcp_hook(void)
{
	int err;
	find_blocked_ports();
	if(!blocking_ports()) return;

	err = nf_register_hook(&set_state_ops);
	hook_installed = 1;
	if(err < 0)
	{
		panic("set_state nf_register_hook failed\n");
	}
	sprint("BLOCK: Registered set_state netfilter hook\n");
}

void unregister_set_state_hook(void)
{
	struct port_entry* pe, *n;
	sprint("BLOCK unregistering hook\n");
	if(!blocking_ports()) return;
	if(!hook_installed) return;

	sprint("BLOCK unregistering hook 2\n");

	nf_unregister_hook(&set_state_ops);
	hook_installed = 0;

	list_for_each_entry_safe(pe, n, &blocked_ports, lh)
	{
		sprint("BLOCK pe %p n %p blocked_ports %p next %p\n", pe, n, &blocked_ports, pe->lh.next);
		list_del(&pe->lh);
		kfree(pe);
	}
	
	sprint("BLOCK: Un registered set_state netfilter hook\n");
}
