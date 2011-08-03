#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>

#include <linux/set_state.h>

static LIST_HEAD(blocked_ports);
struct port_entry
{
	u16 port;
	struct list_head next;
};

static unsigned int set_state_tcp_rx_hook(unsigned int hook, struct sk_buff* skb, const struct net_device* in, const struct net_device* out, 
					  int (*okfn)(struct sk_buff*))
{
	struct tcphdr* th;
	struct iphdr* ih;
	u16 port;
	struct port_entry* pe;
	
	if(!skb) return NF_ACCEPT;

	ih = ip_hdr(skb);
	if(!ih) return NF_ACCEPT;
	if(ih->protocol != IPPROTO_TCP)
	{ 
		return NF_ACCEPT;
	}

	th = (struct tcphdr*)((u32*)ih + ih->ihl);
	port = ntohs(th->dest);

	list_for_each_entry(pe, &blocked_ports, next)
	{
		if(pe->port == port)
		{
			return NF_DROP;
		}
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


static void find_blocked_ports_tsk(struct saved_task_struct* tsk)
{
	struct saved_task_struct* child;
	struct saved_file* file;

	sprint("blocking ports for task %s[%d]\n", tsk->name, tsk->pid);
	list_for_each_entry(file, &tsk->open_files, next)
	{
		struct saved_socket* socket;
		struct saved_tcp_state* tcp;
		struct port_entry* pe;

		if(file->type != SOCKET) continue;

		socket = &file->socket;
		tcp = socket->tcp;

		if(tcp == NULL) continue;

		sprint("Blocking port %d\n", tcp->sport);
		pe = kmalloc(sizeof(*pe), GFP_KERNEL);
		if(!pe)
		{
			sprint("Out of memory when setting up set_state hook\n");
			return;
		}
		
		pe->port = tcp->sport;
		list_add_tail(&pe->next, &blocked_ports);

	}

	list_for_each_entry(child, &tsk->children, sibling)
	{
		find_blocked_ports_tsk(tsk);
	}
}

static void find_blocked_ports(void)
{
	struct saved_state* state;
	struct saved_task_struct* tsk;

	state = (struct saved_state*)get_reserved_region();

	if(state->processes == NULL) return;

	for(tsk = state->processes; tsk != NULL; tsk=tsk->next)
	{
		find_blocked_ports_tsk(tsk);
	}
}

void set_state_tcp_hook(void)
{
	int err;
	find_blocked_ports();
	if(list_empty(&blocked_ports)) return;

	err = nf_register_hook(&set_state_ops);
	if(err < 0)
	{
		panic("set_state nf_register_hook failed\n");
	}
	sprint("Registered set_state netfilter hook\n");
}

void unregister_set_state_hook(void)
{
	struct port_entry* pe, *n;
	if(list_empty(&blocked_ports)) return;
	nf_unregister_hook(&set_state_ops);

	list_for_each_entry_safe(pe, n, &blocked_ports, next)
	{
		list_del(&pe->next);
		kfree(pe);
	}
	
	sprint("Un registered set_state netfilter hook\n");
}
