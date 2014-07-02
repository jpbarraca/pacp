/*
 * This is a module which is used for queueing IPv6 packets and
 * communicating with userspace via netlink.
 *
 * (C) 2001 Fernando Anton, this code is GPL.
 *     IPv64 Project - Work based in IPv64 draft by Arturo Azcorra.
 *     Universidad Carlos III de Madrid - Leganes (Madrid) - Spain
 *     Universidad Politecnica de Alcala de Henares - Alcala de H. (Madrid) - Spain
 *     email: fanton@it.uc3m.es
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * 2004-11-30: Modified to support multiple peers at once.
 *             Hugo Santos <hsantos@av.it.pt>
 *             João Paulo Barraca <jpbarraca@av.it.pt>
 *             Instituto de Telecomunicações - polo Aveiro - Portugal
 *             http://www.av.it.pt
 * 
 * 2001-11-06: First try. Working with ip_queue.c for IPv4 and trying
 *             to adapt it to IPv6
 *             HEAVILY based in ipqueue.c by James Morris. It's just
 *             a little modified version of it, so he's nearly the
 *             real coder of this.
 *             Few changes needed, mainly the hard_routing code and
 *             the netlink socket protocol (we're NETLINK_IP6_FW).
 * 2002-06-25: Code cleanup. [JM: ported cleanup over from ip_queue.c]
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/ipv6.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <net/sock.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>

//#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9) 
//#include "ip_queue_64.h"
//#else
#include <linux/netfilter_ipv4/ip_queue.h>
//#endif



#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#define IPQ_QMAX_DEFAULT 1024
#define IPQ_PROC_FS_NAME "ip6_mqueue"
#define NET_IPQ_QMAX 2088
#define NET_IPQ_QMAX_NAME "ip6_mqueue_maxlen"

struct ipq_rt_info {
	struct in6_addr daddr;
	struct in6_addr saddr;
};

struct ipq_queue_entry {
	struct list_head list;
	struct nf_info *info;
	struct sk_buff *skb;
	struct ipq_rt_info rt_info;
	struct list_head *curr;
};

typedef int (*ipq_cmpfn)(struct ipq_queue_entry *, unsigned long);

struct peerid {
	struct list_head head;
	int pid;
	unsigned char copy_mode; // = IPQ_COPY_NONE;
	unsigned int copy_range; // Copy Range

	rwlock_t lock;
};

static rwlock_t queue_lock = RW_LOCK_UNLOCKED;

static LIST_HEAD(peers);

unsigned int queue_maxlen = IPQ_QMAX_DEFAULT;
static unsigned int queue_total;
static struct sock *ipqnl;		//IPQ SOCKET
static LIST_HEAD(queue_list);
static DECLARE_MUTEX(ipqnl_sem);

static struct sk_buff *
ipq_build_packet_message(struct peerid *pid, struct ipq_queue_entry *entry, int *errp);

static void
__ipq_dequeue_entry(struct ipq_queue_entry *entry);

static int
ipq_build_and_send_packet(struct peerid *pid, struct ipq_queue_entry *entry) {
	int status = 0;
	struct sk_buff *nskb;

	read_lock_bh(&pid->lock);
	
	nskb = ipq_build_packet_message(pid, entry, &status);
	if (!nskb){			
		read_unlock_bh(&pid->lock);
		return status;
	}

	status = netlink_unicast(ipqnl, nskb, pid->pid, MSG_DONTWAIT);

	read_unlock_bh(&pid->lock);

	//if (status < 0)
	//	kfree_skb(nskb);

	return status;
}

static void
ipq_issue_verdict(struct peerid *pid, struct ipq_queue_entry *entry, int verdict, int flush)
{
	int _free = 0;
	
	//write_lock_bh(&queue_lock);

	if (pid) {
		if (!flush) {
			entry->curr = entry->curr->next;
		} else {
			if (entry->curr == &pid->head) {
				entry->curr = entry->curr->next;
			} else {
//				goto out_unlock;
				return;
			}
		}

		if (entry->curr == &peers || verdict != NF_ACCEPT) {
			// we've reached here? issue the verdict
			nf_reinject(entry->skb, entry->info, verdict);

			_free = 1;
		} else {
			// send next one
			if (ipq_build_and_send_packet((struct peerid *)entry->curr, entry) < 0) {
				_free = 1;
			}
		}
	} else {
		_free = 1;
	}

	if (_free) {
		__ipq_dequeue_entry(entry);
		kfree(entry);
	}

//out_unlock:
//	write_unlock_bh(&queue_lock);

}

static int
__ipq_enqueue_entry(struct ipq_queue_entry *entry)
{
	if (queue_total >= queue_maxlen) {
		if (net_ratelimit())
			printk(KERN_WARNING "ip6_mqueue: full at %d entries, "
			       "dropping packet(s).\n", queue_total);
		return -ENOSPC;
	}
	list_add(&entry->list, &queue_list);
	queue_total++;
	return 0;
}

/*
 * Find and return a queued entry matched by cmpfn, or return the last
 * entry if cmpfn is NULL.
 */
static struct ipq_queue_entry *
__ipq_find_entry(ipq_cmpfn cmpfn, unsigned long data)
{
	struct list_head *p;

	list_for_each_prev(p, &queue_list) {
		struct ipq_queue_entry *entry = (struct ipq_queue_entry *)p;

		if (!cmpfn || cmpfn(entry, data))
			return entry;
	}
	return NULL;
}

static void
__ipq_dequeue_entry(struct ipq_queue_entry *entry)
{
	list_del(&entry->list);
	queue_total--;
}

static struct ipq_queue_entry *
__ipq_find_dequeue_entry(ipq_cmpfn cmpfn, unsigned long data)
{
	struct ipq_queue_entry *entry;

	entry = __ipq_find_entry(cmpfn, data);
	if (entry == NULL)
		return NULL;

	__ipq_dequeue_entry(entry);
	return entry;
}


static void
__ipq_flush(struct peerid *pid, int verdict)
{
	struct ipq_queue_entry *entry;
	
	while ((entry = __ipq_find_entry(NULL, 0))){
		ipq_issue_verdict(pid, entry, verdict, 1);
	}
}

static int
__ipq_set_mode(struct peerid *pid, unsigned char mode, unsigned int range)
{
	int status = 0;

	switch(mode) {
	case IPQ_COPY_NONE:
	case IPQ_COPY_META:
		pid->copy_mode = mode;
		pid->copy_range = 0;
		break;

	case IPQ_COPY_PACKET:
		pid->copy_mode = mode;
		pid->copy_range = range;
		if (pid->copy_range > 0xFFFF)
			pid->copy_range = 0xFFFF;
		break;

	default:
		status = -EINVAL;

	}
	return status;
}

static struct peerid *__getpeer(int pid) {
	struct list_head *p;

	list_for_each (p, &peers) {
		if (((struct peerid *)p)->pid == pid) {
			struct peerid *peer = (struct peerid *)p;
			write_lock_bh(&peer->lock);
			return peer;
		}
	}

	return 0;
}

static void
__ipq_reset(struct peerid *pid)
{
	if (!pid)
		return;

	list_del(&pid->head);
	
	if(list_empty(&peers)){
			__ipq_flush(pid, NF_DROP);	//No more peers. Just flush
	}
	else{	
		//List is not empty. Proceed with packets
	}
	
	write_unlock_bh(&pid->lock);
	kfree(pid);
}

static struct ipq_queue_entry *
ipq_find_dequeue_entry(ipq_cmpfn cmpfn, unsigned long data)
{
	struct ipq_queue_entry *entry;

	write_lock_bh(&queue_lock);
	entry = __ipq_find_dequeue_entry(cmpfn, data);
	write_unlock_bh(&queue_lock);
	return entry;
}

static void
ipq_flush(struct peerid *pid, int verdict)
{
	write_lock_bh(&queue_lock);
	__ipq_flush(pid, verdict);
	write_unlock_bh(&queue_lock);
}

static struct sk_buff *
ipq_build_packet_message(struct peerid *pid, struct ipq_queue_entry *entry, int *errp)
{
	unsigned char *old_tail;
	size_t size = 0;
	size_t data_len = 0;
	struct sk_buff *skb;
	struct ipq_packet_msg *pmsg;
	struct nlmsghdr *nlh;

	read_lock_bh(&queue_lock);

	switch (pid->copy_mode) {
	case IPQ_COPY_META:
	case IPQ_COPY_NONE:
		size = NLMSG_SPACE(sizeof(*pmsg));
		data_len = 0;
		break;

	case IPQ_COPY_PACKET:
		if (pid->copy_range == 0 || pid->copy_range > entry->skb->len)
			data_len = entry->skb->len;
		else
			data_len = pid->copy_range;

		size = NLMSG_SPACE(sizeof(*pmsg) + data_len);
		break;

	default:
		*errp = -EINVAL;
		read_unlock_bh(&queue_lock);
		return NULL;
	}

	read_unlock_bh(&queue_lock);

	skb = alloc_skb(size, GFP_ATOMIC);
	if (!skb)
		goto nlmsg_failure;

	old_tail= skb->tail;
	nlh = NLMSG_PUT(skb, 0, 0, IPQM_PACKET, size - sizeof(*nlh));
	pmsg = NLMSG_DATA(nlh);
	memset(pmsg, 0, sizeof(*pmsg));

	pmsg->packet_id       = (unsigned long )entry;
	pmsg->data_len        = data_len;
	pmsg->timestamp_sec   = entry->skb->stamp.tv_sec;
	pmsg->timestamp_usec  = entry->skb->stamp.tv_usec;
	pmsg->mark            = entry->skb->nfmark;
	pmsg->hook            = entry->info->hook;
	pmsg->hw_protocol     = entry->skb->protocol;
	
	if (entry->info->indev)
		strcpy(pmsg->indev_name, entry->info->indev->name);
	else
		pmsg->indev_name[0] = '\0';

	if (entry->info->outdev)
		strcpy(pmsg->outdev_name, entry->info->outdev->name);
	else
		pmsg->outdev_name[0] = '\0';

	if (entry->info->indev && entry->skb->dev) {
		pmsg->hw_type = entry->skb->dev->type;
		if (entry->skb->dev->hard_header_parse)
			pmsg->hw_addrlen =
			    entry->skb->dev->hard_header_parse(entry->skb,
			                                       pmsg->hw_addr);
	}

	if (data_len)
		memcpy(pmsg->payload, entry->skb->data, data_len);

	nlh->nlmsg_len = skb->tail - old_tail;
	return skb;

nlmsg_failure:
	if (skb)
		kfree_skb(skb);
	*errp = -EINVAL;
	printk(KERN_ERR "ip6_mqueue: error creating packet message\n");
	return NULL;
}

static int
ipq_enqueue_packet(struct sk_buff *skb, struct nf_info *info, void *data)
{
	int status = -EINVAL;
	struct ipq_queue_entry *entry;

	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (entry == NULL) {
		printk(KERN_ERR "ip6_mqueue: OOM in ipq_enqueue_packet()\n");
		return -ENOMEM;
	}
	
	//Not really accurate but will help
	if(!skb->stamp.tv_sec) {
		do_gettimeofday(&skb->stamp);
	}
	
	entry->info = info;
	entry->skb = skb;

	if (entry->info->hook == NF_IP_LOCAL_OUT) {
		struct ipv6hdr *iph = skb->nh.ipv6h;

		entry->rt_info.daddr = iph->daddr;
		entry->rt_info.saddr = iph->saddr;
	}

	write_lock_bh(&queue_lock);

	entry->curr = peers.next;

	if (entry->curr != &peers) {
		status = ipq_build_and_send_packet((struct peerid *)entry->curr, entry);
		if (status < 0)
			goto err_out_unlock;
		status = __ipq_enqueue_entry(entry);
	} else {
		status = -EAGAIN;
	}

	if (status < 0)
		goto err_out_unlock;

	write_unlock_bh(&queue_lock);
	return status;

err_out_unlock:
	write_unlock_bh(&queue_lock);

	kfree(entry);
	return status;
}

static int
ipq_mangle_ipv6(ipq_verdict_msg_t *v, struct ipq_queue_entry *e)
{
	int diff;
	struct ipv6hdr *user_iph = (struct ipv6hdr *)v->payload;

	if (v->data_len < sizeof(*user_iph)){
		printk(KERN_WARNING "ip6_mqueue: error in size of iph");
		return 0;
	}
	diff = v->data_len - e->skb->len;
	if (diff < 0)
		skb_trim(e->skb, v->data_len);
	else if (diff > 0) {
		if (v->data_len > 0xFFFF)
			return -EINVAL;
		if (diff > skb_tailroom(e->skb)) {
			struct sk_buff *newskb;

			newskb = skb_copy_expand(e->skb,
			                         skb_headroom(e->skb),
			                         diff,
			                         GFP_ATOMIC);
			if (newskb == NULL) {
				printk(KERN_WARNING "ip6_mqueue: OOM "
				       "in mangle, dropping packet\n");
				return -ENOMEM;
			}
			if (e->skb->sk)
				skb_set_owner_w(newskb, e->skb->sk);
			kfree_skb(e->skb);
			e->skb = newskb;
		}
		skb_put(e->skb, diff);
	}
	memcpy(e->skb->data, v->payload, v->data_len);
	e->skb->nfcache |= NFC_ALTERED;

	/*
	 * Extra routing may needed on local out, as the QUEUE target never
	 * returns control to the table.
	        * Not a nice way to cmp, but works
	 */
	if (e->info->hook == NF_IP_LOCAL_OUT) {
		struct ipv6hdr *iph = e->skb->nh.ipv6h;
		if (ipv6_addr_cmp(&iph->daddr, &e->rt_info.daddr) ||
		        ipv6_addr_cmp(&iph->saddr, &e->rt_info.saddr))
			return ip6_route_me_harder(e->skb);
	}
	return 0;
}

static int
id_cmp(struct ipq_queue_entry *e, unsigned long id)
{
	return (id == (unsigned long )e);
}

static int
ipq_set_verdict(struct peerid *pid, struct ipq_verdict_msg *vmsg, unsigned int len)
{
	struct ipq_queue_entry *entry;

	if (vmsg->value > NF_MAX_VERDICT)
		return -EINVAL;
	
	read_lock_bh(&queue_lock);
	
	entry = __ipq_find_entry(id_cmp, vmsg->id);
	if (entry == NULL){
		read_unlock_bh(&queue_lock);
		printk(KERN_WARNING "ip6_mqueue: entry not found\n");
		return -ENOENT;
	}
	else {
		int verdict = vmsg->value;

		if (vmsg->data_len){
			if(vmsg->data_len == len){
				if (ipq_mangle_ipv6(vmsg, entry) < 0){
					verdict = NF_DROP;
					printk(KERN_WARNING "ip6_mqueue: ipq_mangle_ipv6 failed on peer payload\n");
				}
			}else
#ifdef	IPQ_64BIT
				printk(KERN_INFO "ip6_mqueue: user payload but len mismatch. data_len:%llu len:%u\n",vmsg->data_len,len);
#else
				printk(KERN_INFO "ip6_mqueue: user payload but len mismatch. data_len:%u len:%u\n",vmsg->data_len,len);
#endif
		}

		read_unlock_bh(&queue_lock);
		write_lock_bh(&queue_lock);
		ipq_issue_verdict(pid, entry, verdict, 0);
		write_unlock_bh(&queue_lock);
		return 0;
	}
}

static int
ipq_set_mode(struct peerid *pid, unsigned char mode, unsigned int range)
{
	int status;

	write_lock_bh(&queue_lock);
	status = __ipq_set_mode(pid, mode, range);
	write_unlock_bh(&queue_lock);
	return status;
}

static int
ipq_receive_peer(struct peerid *pid, struct ipq_peer_msg *pmsg,
                 unsigned char type, unsigned int len)
{
	int status = 0;

	if (len < sizeof(*pmsg))
		return -EINVAL;

	switch (type) {
	case IPQM_MODE:
		status = ipq_set_mode(pid, pmsg->msg.mode.value,
		                      pmsg->msg.mode.range);
		break;

	case IPQM_VERDICT:
		if (pmsg->msg.verdict.value > NF_MAX_VERDICT)
			status = -EINVAL;
		else
			status = ipq_set_verdict(pid, &pmsg->msg.verdict,
			                         len - sizeof(*pmsg));
		break;
	default:
		status = -EINVAL;
	}
	return status;
}

static int
dev_cmp(struct ipq_queue_entry *entry, unsigned long ifindex)
{
	if (entry->info->indev)
		if (entry->info->indev->ifindex == ifindex)
			return 1;

	if (entry->info->outdev)
		if (entry->info->outdev->ifindex == ifindex)
			return 1;

	return 0;
}

static void
ipq_dev_drop(int ifindex)
{
	struct ipq_queue_entry *entry;

	while ((entry = ipq_find_dequeue_entry(dev_cmp, ifindex)) != NULL)
		{
			write_lock_bh(&queue_lock);
			ipq_issue_verdict(0, entry, NF_DROP, 1);
			write_unlock_bh(&queue_lock);
		}
}

static struct peerid *__allocpeer(int pid) {
	struct peerid *peer = (struct peerid *)kmalloc(sizeof(struct peerid), GFP_KERNEL);

	if (peer) {
		peer->pid = pid;
		peer->copy_mode = IPQ_COPY_NONE;
		peer->lock = RW_LOCK_UNLOCKED;
		list_add_tail(&peer->head, &peers);
	}

	return peer;
}


#define RCV_SKB_FAIL(err) do { netlink_ack(skb, nlh, (err)); return; } while (0)

static void
ipq_rcv_skb(struct sk_buff *skb)
{
	int status = 0, type, pid, flags, nlmsglen, skblen;
	struct nlmsghdr *nlh;
	struct peerid *peer;

	skblen = skb->len;
	if (skblen < sizeof(*nlh))
		return;

	nlh = (struct nlmsghdr *)skb->data;
	nlmsglen = nlh->nlmsg_len;
	if (nlmsglen < sizeof(*nlh) || skblen < nlmsglen)
		return;

	pid = nlh->nlmsg_pid;
	flags = nlh->nlmsg_flags;

	if(pid <= 0 || !(flags & NLM_F_REQUEST) || flags & NLM_F_MULTI)
		RCV_SKB_FAIL(-EINVAL);

	if (flags & MSG_TRUNC)
		RCV_SKB_FAIL(-ECOMM);

	type = nlh->nlmsg_type;
	if (type < NLMSG_NOOP || type >= IPQM_MAX)
		RCV_SKB_FAIL(-EINVAL);

	if (type <= IPQM_BASE)
		return;

	if (security_netlink_recv(skb))
		RCV_SKB_FAIL(-EPERM);

	write_lock_bh(&queue_lock);

	peer = __getpeer(pid);
	if (!peer) {
		peer = __allocpeer(pid);
		if (peer) {
			write_lock_bh(&peer->lock);
		}
	}

	write_unlock_bh(&queue_lock);

	if (peer) {
		status = ipq_receive_peer(peer, NLMSG_DATA(nlh), type,
		                          skblen - NLMSG_LENGTH(0));

		write_unlock_bh(&peer->lock);
	}
	
	if (status < 0)
		RCV_SKB_FAIL(status);

	if (flags & NLM_F_ACK)
		netlink_ack(skb, nlh, 0);
	return;
}

//IPQ SOCKET
static void
ipq_rcv_sk(struct sock *sk, int len)
{
	do {
		struct sk_buff *skb;

		if (down_trylock(&ipqnl_sem))
			return;

		while ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL) {
			ipq_rcv_skb(skb);
			kfree_skb(skb);
		}

		up(&ipqnl_sem);

	} while (sk && ipqnl->sk_receive_queue.qlen);
}

static int
ipq_rcv_dev_event(struct notifier_block *this,
                  unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;

	/* Drop any packets associated with the downed device */
	if (event == NETDEV_DOWN)
		ipq_dev_drop(dev->ifindex);
	return NOTIFY_DONE;
}

static struct notifier_block ipq_dev_notifier = {
	        .notifier_call	= ipq_rcv_dev_event,
                         };

static int
ipq_rcv_nl_event(struct notifier_block *this,
                 unsigned long event, void *ptr)
{
	struct netlink_notify *n = ptr;

	if (event == NETLINK_URELEASE &&
	        (n->protocol == NETLINK_IP6_FW) && n->pid) {
		write_lock_bh(&queue_lock);
		__ipq_reset(__getpeer(n->pid));
		write_unlock_bh(&queue_lock);
	}
	return NOTIFY_DONE;
}

static struct notifier_block ipq_nl_notifier = {
	        .notifier_call	= ipq_rcv_nl_event,
                         };

static struct ctl_table_header *ipq_sysctl_header;

static ctl_table ipq_table[] = {
                                   {
                                       .ctl_name	= NET_IPQ_QMAX,
                                       .procname	= NET_IPQ_QMAX_NAME,
                                       .data		= &queue_maxlen,
                                       .maxlen		= sizeof(queue_maxlen),
                                       .mode		= 0644,
                                       .proc_handler	= proc_dointvec
                                   },
                                   { .ctl_name = 0 }
                               };

static ctl_table ipq_dir_table[] = {
                                       {
                                           .ctl_name	= NET_IPV6,
                                           .procname	= "ipv6",
                                           .mode		= 0555,
                                           .child		= ipq_table
                                       },
                                       { .ctl_name = 0 }
                                   };

static ctl_table ipq_root_table[] = {
                                        {
                                            .ctl_name	= CTL_NET,
                                            .procname	= "net",
                                            .mode		= 0555,
                                            .child		= ipq_dir_table
                                        },
                                        { .ctl_name = 0 }
                                    };

static int
ipq_get_info(char *buffer, char **start, off_t offset, int length)
{
	int len;
	struct list_head *p;

	read_lock_bh(&queue_lock);

	len = sprintf(buffer,"QueueLength:  %u  QueueMaxLength: %u\n", queue_total, queue_maxlen);
	list_for_each (p, &peers) {
		read_lock_bh(&((struct peerid *)p)->lock);
		len += sprintf(buffer + len, "Peer PID: %d  CopyMode: %hu  CopyRange: %u\n",
		               ((struct peerid *)p)->pid,
		               ((struct peerid *)p)->copy_mode,
		               ((struct peerid *)p)->copy_range);
		read_unlock_bh(&((struct peerid *)p)->lock);
	}

	read_unlock_bh(&queue_lock);

	*start = buffer + offset;
	len -= offset;
	if (len > length)
		len = length;
	else if (len < 0)
		len = 0;
	return len;
}

static int
init_or_cleanup(int init)
{
	int status = -ENOMEM;
	struct proc_dir_entry *proc;


	if (!init)
		goto cleanup;

	printk(KERN_INFO "ip6_mqueue: Loading IP6 Queue with Multipeer support. pmsg=%u vmsg=%u\n",sizeof(struct ipq_packet_msg),sizeof(struct ipq_verdict_msg));

	netlink_register_notifier(&ipq_nl_notifier);
	ipqnl = netlink_kernel_create(NETLINK_IP6_FW, ipq_rcv_sk);
	if (ipqnl == NULL) {
		printk(KERN_ERR "ip6_mqueue: failed to create netlink socket \n");
		goto cleanup_netlink_notifier;
	}
	
	proc = proc_net_create(IPQ_PROC_FS_NAME, 0, ipq_get_info);
	if (proc)
		proc->owner = THIS_MODULE;
	else {
		printk(KERN_ERR "ip6_mqueue: failed to create proc entry\n");
		goto cleanup_ipqnl;
	}

	register_netdevice_notifier(&ipq_dev_notifier);
	ipq_sysctl_header = register_sysctl_table(ipq_root_table, 0);

	status = nf_register_queue_handler(PF_INET6, ipq_enqueue_packet, NULL);
	if (status < 0) {
		printk(KERN_ERR "ip6_mqueue: failed to register queue handler\n");
		goto cleanup_sysctl;
	}
	return status;

cleanup:
	nf_unregister_queue_handler(PF_INET6);
	synchronize_net();
	ipq_flush(0, NF_DROP);

cleanup_sysctl:
	unregister_sysctl_table(ipq_sysctl_header);
	unregister_netdevice_notifier(&ipq_dev_notifier);
	proc_net_remove(IPQ_PROC_FS_NAME);

cleanup_ipqnl:
	sock_release(ipqnl->sk_socket);
	down(&ipqnl_sem);
	up(&ipqnl_sem);

cleanup_netlink_notifier:
	netlink_unregister_notifier(&ipq_nl_notifier);
	return status;
}

static int __init init(void)
{

	return init_or_cleanup(1);
}

static void __exit fini(void)
{
	init_or_cleanup(0);
}

MODULE_DESCRIPTION("IPv6 packet queue handler with Multipeer");
MODULE_LICENSE("GPL");

module_init(init);
module_exit(fini);
