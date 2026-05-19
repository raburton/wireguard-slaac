// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "allowedips.h"
#include "peer.h"
#include "device.h"
#include "queueing.h"

enum { MAX_ALLOWEDIPS_DEPTH = 129 };

void wg_allowedips_learn_worker(struct work_struct *work);
void wg_allowedips_gc_worker(struct work_struct *work);

static struct kmem_cache *node_cache;

void swap_endian(u8 *dst, const u8 *src, u8 bits)
{
	if (bits == 32) {
		*(u32 *)dst = be32_to_cpu(*(const __be32 *)src);
	} else if (bits == 128) {
		((u64 *)dst)[0] = get_unaligned_be64(src);
		((u64 *)dst)[1] = get_unaligned_be64(src + 8);
	}
}

static void copy_and_assign_cidr(struct allowedips_node *node, const u8 *src,
				 u8 cidr, u8 bits)
{
	node->cidr = cidr;
	node->bit_at_a = cidr / 8U;
#ifdef __LITTLE_ENDIAN
	node->bit_at_a ^= (bits / 8U - 1U) % 8U;
#endif
	node->bit_at_b = 7U - (cidr % 8U);
	node->bitlen = bits;
	memcpy(node->bits, src, bits / 8U);
}

static inline u8 choose(struct allowedips_node *node, const u8 *key)
{
	return (key[node->bit_at_a] >> node->bit_at_b) & 1;
}

static void push_rcu(struct allowedips_node **stack,
		     struct allowedips_node __rcu *p, unsigned int *len)
{
	if (rcu_access_pointer(p)) {
		if (WARN_ON(IS_ENABLED(DEBUG) && *len >= MAX_ALLOWEDIPS_DEPTH))
			return;
		stack[(*len)++] = rcu_dereference_raw(p);
	}
}

static void node_free_rcu(struct rcu_head *rcu)
{
	kmem_cache_free(node_cache, container_of(rcu, struct allowedips_node, rcu));
}

static void root_free_rcu(struct rcu_head *rcu)
{
	struct allowedips_node *node, *stack[MAX_ALLOWEDIPS_DEPTH] = {
		container_of(rcu, struct allowedips_node, rcu) };
	unsigned int len = 1;

	while (len > 0 && (node = stack[--len])) {
		push_rcu(stack, node->bit[0], &len);
		push_rcu(stack, node->bit[1], &len);
		kmem_cache_free(node_cache, node);
	}
}

static void root_remove_peer_lists(struct allowedips_node *root)
{
	struct allowedips_node *node, *stack[MAX_ALLOWEDIPS_DEPTH] = { root };
	unsigned int len = 1;

	while (len > 0 && (node = stack[--len])) {
		push_rcu(stack, node->bit[0], &len);
		push_rcu(stack, node->bit[1], &len);
		if (rcu_access_pointer(node->peer))
			list_del(&node->peer_list);
	}
}

static unsigned int fls128(u64 a, u64 b)
{
	return a ? fls64(a) + 64U : fls64(b);
}

static u8 common_bits(const struct allowedips_node *node, const u8 *key,
		      u8 bits)
{
	if (bits == 32)
		return 32U - fls(*(const u32 *)node->bits ^ *(const u32 *)key);
	else if (bits == 128)
		return 128U - fls128(
			*(const u64 *)&node->bits[0] ^ *(const u64 *)&key[0],
			*(const u64 *)&node->bits[8] ^ *(const u64 *)&key[8]);
	return 0;
}

static bool prefix_matches(const struct allowedips_node *node, const u8 *key,
			   u8 bits)
{
	/* This could be much faster if it actually just compared the common
	 * bits properly, by precomputing a mask bswap(~0 << (32 - cidr)), and
	 * the rest, but it turns out that common_bits is already super fast on
	 * modern processors, even taking into account the unfortunate bswap.
	 * So, we just inline it like this instead.
	 */
	return common_bits(node, key, bits) >= node->cidr;
}

static struct allowedips_node *find_node(struct allowedips_node *trie, u8 bits,
					 const u8 *key)
{
	struct allowedips_node *node = trie, *found = NULL;

	while (node && prefix_matches(node, key, bits)) {
		if (rcu_access_pointer(node->peer)) {
			found = node;
			WRITE_ONCE(found->last_used, jiffies);
		}
		if (node->cidr == bits)
			break;
		node = rcu_dereference_bh(node->bit[choose(node, key)]);
	}
	return found;
}

/* Returns a strong reference to a peer */
static struct wg_peer *lookup(struct allowedips_node __rcu *root, u8 bits,
			      const void *be_ip)
{
	/* Aligned so it can be passed to fls/fls64 */
	u8 ip[16] __aligned(__alignof(u64));
	struct allowedips_node *node;
	struct wg_peer *peer = NULL;

	swap_endian(ip, be_ip, bits);

	rcu_read_lock_bh();
retry:
	node = find_node(rcu_dereference_bh(root), bits, ip);
	if (node) {
		peer = wg_peer_get_maybe_zero(rcu_dereference_bh(node->peer));
		if (!peer)
			goto retry;
	}
	rcu_read_unlock_bh();
	return peer;
}

static bool node_placement(struct allowedips_node __rcu *trie, const u8 *key,
			   u8 cidr, u8 bits, struct allowedips_node **rnode,
			   struct mutex *lock)
{
	struct allowedips_node *node = rcu_dereference_protected(trie, lockdep_is_held(lock));
	struct allowedips_node *parent = NULL;
	bool exact = false;

	while (node && node->cidr <= cidr && prefix_matches(node, key, bits)) {
		parent = node;
		if (parent->cidr == cidr) {
			exact = true;
			break;
		}
		node = rcu_dereference_protected(parent->bit[choose(parent, key)], lockdep_is_held(lock));
	}
	*rnode = parent;
	return exact;
}

static inline void connect_node(struct allowedips_node __rcu **parent, u8 bit, struct allowedips_node *node)
{
	node->parent_bit_packed = (unsigned long)parent | bit;
	rcu_assign_pointer(*parent, node);
}

static inline void choose_and_connect_node(struct allowedips_node *parent, struct allowedips_node *node)
{
	u8 bit = choose(parent, node->bits);
	connect_node(&parent->bit[bit], bit, node);
}

int add(struct allowedips_node __rcu **trie, u8 bits, const u8 *key,
	       u8 cidr, struct wg_peer *peer, struct list_head *peer_list, bool learned, struct mutex *lock)
{
	struct allowedips_node *node, *parent, *down, *newnode;

	if (unlikely(cidr > bits || !peer))
		return -EINVAL;

	if (!rcu_access_pointer(*trie)) {
		node = kmem_cache_zalloc(node_cache, GFP_KERNEL);
		if (unlikely(!node))
			return -ENOMEM;
		RCU_INIT_POINTER(node->peer, peer);
		node->is_learned = learned;
		if (learned)
			atomic_inc(&peer->learned_ip_count);
		list_add_tail(&node->peer_list, peer_list);
		copy_and_assign_cidr(node, key, cidr, bits);
		node->last_used = jiffies;
		connect_node(trie, 2, node);
		return 0;
	}
	if (node_placement(*trie, key, cidr, bits, &node, lock)) {
		struct wg_peer *old_peer = rcu_dereference_protected(node->peer, lockdep_is_held(lock));

		if (learned && old_peer) {
			if (old_peer != peer || !node->is_learned)
				return 0;
		}
		if (node->is_learned && old_peer)
			atomic_dec(&old_peer->learned_ip_count);
		rcu_assign_pointer(node->peer, peer);
		node->is_learned = learned;
		if (learned)
			atomic_inc(&peer->learned_ip_count);
		list_move_tail(&node->peer_list, peer_list);
		return 0;
	}

	newnode = kmem_cache_zalloc(node_cache, GFP_KERNEL);
	if (unlikely(!newnode))
		return -ENOMEM;
	RCU_INIT_POINTER(newnode->peer, peer);
	newnode->is_learned = learned;
	if (learned)
		atomic_inc(&peer->learned_ip_count);
	list_add_tail(&newnode->peer_list, peer_list);
	copy_and_assign_cidr(newnode, key, cidr, bits);
	newnode->last_used = jiffies;

	if (!node) {
		down = rcu_dereference_protected(*trie, lockdep_is_held(lock));
	} else {
		const u8 bit = choose(node, key);
		down = rcu_dereference_protected(node->bit[bit], lockdep_is_held(lock));
		if (!down) {
			connect_node(&node->bit[bit], bit, newnode);
			return 0;
		}
	}
	cidr = min(cidr, common_bits(down, key, bits));
	parent = node;

	if (newnode->cidr == cidr) {
		choose_and_connect_node(newnode, down);
		if (!parent)
			connect_node(trie, 2, newnode);
		else
			choose_and_connect_node(parent, newnode);
		return 0;
	}

	node = kmem_cache_zalloc(node_cache, GFP_KERNEL);
	if (unlikely(!node)) {
		if (newnode->is_learned)
			atomic_dec(&peer->learned_ip_count);
		list_del(&newnode->peer_list);
		kmem_cache_free(node_cache, newnode);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&node->peer_list);
	copy_and_assign_cidr(node, newnode->bits, cidr, bits);

	choose_and_connect_node(node, down);
	choose_and_connect_node(node, newnode);
	if (!parent)
		connect_node(trie, 2, node);
	else
		choose_and_connect_node(parent, node);
	return 0;
}

static void __wg_allowedips_remove_node(struct allowedips *table,
					struct allowedips_node *node,
					struct mutex *lock)
{
	struct allowedips_node *child, **parent_bit, *parent;
	struct wg_peer *peer;
	bool free_parent;

	peer = rcu_dereference_protected(node->peer, lockdep_is_held(lock));
	if (node->is_learned && peer)
		atomic_dec(&peer->learned_ip_count);

	list_del_init(&node->peer_list);
	RCU_INIT_POINTER(node->peer, NULL);
	if (node->bit[0] && node->bit[1])
		return;
	child = rcu_dereference_protected(node->bit[!rcu_access_pointer(node->bit[0])],
					  lockdep_is_held(lock));
	if (child)
		child->parent_bit_packed = node->parent_bit_packed;
	parent_bit = (struct allowedips_node **)(node->parent_bit_packed & ~3UL);
	*parent_bit = child;
	parent = (void *)parent_bit -
			offsetof(struct allowedips_node, bit[node->parent_bit_packed & 1]);
	free_parent = !rcu_access_pointer(node->bit[0]) && !rcu_access_pointer(node->bit[1]) &&
			(node->parent_bit_packed & 3) <= 1 &&
			!rcu_access_pointer(parent->peer);
	call_rcu(&node->rcu, node_free_rcu);
	if (!free_parent)
		return;
	if (child)
		child->parent_bit_packed = parent->parent_bit_packed;
	*(struct allowedips_node **)(parent->parent_bit_packed & ~3UL) = child;
	call_rcu(&parent->rcu, node_free_rcu);
}

static int remove(struct allowedips *table, struct allowedips_node __rcu **trie,
		  u8 bits, const u8 *key, u8 cidr, struct wg_peer *peer,
		  struct mutex *lock)
{
	struct allowedips_node *node;

	if (unlikely(cidr > bits))
		return -EINVAL;
	if (!rcu_access_pointer(*trie) || !node_placement(*trie, key, cidr, bits, &node, lock) ||
	    peer != rcu_access_pointer(node->peer))
		return 0;
	++table->seq; /* Increment seq for removal */
	__wg_allowedips_remove_node(table, node, lock);
	return 0;
}

void wg_allowedips_init(struct allowedips *table)
{
	table->root4 = table->root6 = NULL;
	table->seq = 1;
}

void wg_allowedips_free(struct allowedips *table, struct mutex *lock)
{
	struct allowedips_node __rcu *old4 = table->root4, *old6 = table->root6;

	++table->seq;
	RCU_INIT_POINTER(table->root4, NULL);
	RCU_INIT_POINTER(table->root6, NULL);
	if (rcu_access_pointer(old4)) {
		struct allowedips_node *node = rcu_dereference_protected(old4,
							lockdep_is_held(lock));

		root_remove_peer_lists(node);
		call_rcu(&node->rcu, root_free_rcu);
	}
	if (rcu_access_pointer(old6)) {
		struct allowedips_node *node = rcu_dereference_protected(old6,
							lockdep_is_held(lock));

		root_remove_peer_lists(node);
		call_rcu(&node->rcu, root_free_rcu);
	}
}

int wg_allowedips_insert_v4(struct allowedips *table, const struct in_addr *ip,
			    u8 cidr, struct wg_peer *peer, struct mutex *lock)
{
	/* Aligned so it can be passed to fls */
	u8 key[4] __aligned(__alignof(u32));

	++table->seq;
	swap_endian(key, (const u8 *)ip, 32);
	return add(&table->root4, 32, key, cidr, peer, &peer->allowedips_list, false, lock);
}

int wg_allowedips_insert_v6(struct allowedips *table, const struct in6_addr *ip,
			    u8 cidr, struct wg_peer *peer, struct mutex *lock)
{
	/* Aligned so it can be passed to fls64 */
	u8 key[16] __aligned(__alignof(u64));

	++table->seq;
	swap_endian(key, (const u8 *)ip, 128);
	return add(&table->root6, 128, key, cidr, peer, &peer->allowedips_list, false, lock);
}

int wg_allowedips_remove_v4(struct allowedips *table, const struct in_addr *ip,
			    u8 cidr, struct wg_peer *peer, struct mutex *lock)
{
	/* Aligned so it can be passed to fls */
	u8 key[4] __aligned(__alignof(u32));

	++table->seq;
	swap_endian(key, (const u8 *)ip, 32);
	return remove(table, &table->root4, 32, key, cidr, peer, lock);
}

int wg_allowedips_remove_v6(struct allowedips *table, const struct in6_addr *ip,
			    u8 cidr, struct wg_peer *peer, struct mutex *lock)
{
	/* Aligned so it can be passed to fls64 */
	u8 key[16] __aligned(__alignof(u64));

	++table->seq;
	swap_endian(key, (const u8 *)ip, 128);
	return remove(table, &table->root6, 128, key, cidr, peer, lock);
}

void wg_allowedips_remove_by_peer(struct allowedips *table,
				  struct wg_peer *peer, struct mutex *lock)
{
	struct allowedips_node *node, *tmp;

	if (list_empty(&peer->allowedips_list))
		return;
	++table->seq;
	list_for_each_entry_safe(node, tmp, &peer->allowedips_list, peer_list)
		__wg_allowedips_remove_node(table, node, lock);
}

void wg_allowedips_gc_worker(struct work_struct *work)
{
	struct wg_device *wg = container_of(work, struct wg_device, allowedips_gc_work.work);
	struct wg_peer *peer;
	struct allowedips_node *node, *tmp;
	const unsigned long timeout = 24 * 60 * 60 * HZ;

	mutex_lock(&wg->device_update_lock);
	++wg->peer_allowedips.seq;
	list_for_each_entry(peer, &wg->peer_list, peer_list) {
		list_for_each_entry_safe(node, tmp, &peer->allowedips_list, peer_list) {
			if (node->is_learned &&
			    time_is_before_jiffies(node->last_used + timeout)) {
				pr_debug("%s: Expiring stale IP %pI6 from peer %llu\n",
					 wg->dev->name, node->bits, peer->internal_id);
				__wg_allowedips_remove_node(&wg->peer_allowedips, node, &wg->device_update_lock);
			}
		}
	}
	mutex_unlock(&wg->device_update_lock);
	schedule_delayed_work(&wg->allowedips_gc_work, 3600 * HZ);
}

void wg_allowedips_learn_worker(struct work_struct *work)
{
	struct wg_peer *peer = container_of(work, struct wg_peer, learn_ip_work);
	struct wg_device *wg = peer->device;
	struct in6_addr ip6;
	u8 key[16] __aligned(__alignof(u64));

	for (;;) {
		if (unlikely(READ_ONCE(peer->is_dead)))
			break;

		spin_lock_bh(&peer->learned_ip_queue_lock);
		if (peer->learned_ip_queue_head == peer->learned_ip_queue_tail) {
			spin_unlock_bh(&peer->learned_ip_queue_lock);
			break;
		}
		ip6 = peer->learned_ip_queue[peer->learned_ip_queue_tail];
		peer->learned_ip_queue_tail = (peer->learned_ip_queue_tail + 1) % ARRAY_SIZE(peer->learned_ip_queue);
		spin_unlock_bh(&peer->learned_ip_queue_lock);

		mutex_lock(&wg->device_update_lock);

		if (unlikely(READ_ONCE(peer->is_dead))) {
			mutex_unlock(&wg->device_update_lock);
			break;
		}

		if (atomic_read(&peer->learned_ip_count) >= 16) {
			struct allowedips_node *node, *victim = NULL;
			unsigned long oldest = jiffies;

			list_for_each_entry(node, &peer->allowedips_list, peer_list) {
				if (node->is_learned && (!victim || time_before(node->last_used, oldest))) {
					oldest = node->last_used;
					victim = node;
				}
			}
			if (victim) {
				++wg->peer_allowedips.seq;
				__wg_allowedips_remove_node(&wg->peer_allowedips, victim, &wg->device_update_lock);
			}
		}

		swap_endian(key, ip6.s6_addr, 128);
		if (add(&wg->peer_allowedips.root6, 128, key, 128, peer, &peer->allowedips_list, true, &wg->device_update_lock) == 0)
			++wg->peer_allowedips.seq;
		mutex_unlock(&wg->device_update_lock);
	}

	wg_peer_put(peer);
}

static void wg_allowedips_learn(struct allowedips *table, struct wg_peer *peer,
				struct sk_buff *skb)
{
	struct wg_peer *learnable_range_peer = NULL;
	unsigned int next_head;

	if (skb->protocol == htons(ETH_P_IPV6)) {
		/* Check if the source IPv6 address is within any of the peer's LearnableIPs ranges.
		 * The 'lookup' function returns a strong reference, so we must put it if found.
		 */
		learnable_range_peer = lookup(peer->learnable_ips.root6, 128, &ipv6_hdr(skb)->saddr);

		if (!learnable_range_peer)
			return;

		/* The IP is within a learnable range. Release the reference acquired by lookup. */
		wg_peer_put(learnable_range_peer);

		spin_lock_bh(&peer->learned_ip_queue_lock);
		next_head = (peer->learned_ip_queue_head + 1) % ARRAY_SIZE(peer->learned_ip_queue);
		if (next_head != peer->learned_ip_queue_tail) {
			peer->learned_ip_queue[peer->learned_ip_queue_head] = ipv6_hdr(skb)->saddr;
			peer->learned_ip_queue_head = next_head;
			pr_debug_ratelimited("%s: Queued new source IPv6 for peer %llu\n",
					     peer->device->dev->name, peer->internal_id);

			wg_peer_get(peer);
			if (!queue_work(peer->device->handshake_send_wq, &peer->learn_ip_work))
				wg_peer_put(peer);
		}
		spin_unlock_bh(&peer->learned_ip_queue_lock);
	}
}

int wg_allowedips_read_node(struct allowedips_node *node, u8 ip[16], u8 *cidr)
{
	const unsigned int cidr_bytes = DIV_ROUND_UP(node->cidr, 8U);
	swap_endian(ip, node->bits, node->bitlen);
	memset(ip + cidr_bytes, 0, node->bitlen / 8U - cidr_bytes);
	if (node->cidr)
		ip[cidr_bytes - 1U] &= ~0U << (-node->cidr % 8U);

	*cidr = node->cidr;
	return node->bitlen == 32 ? AF_INET : AF_INET6;
}

/* Returns a strong reference to a peer */
struct wg_peer *wg_allowedips_lookup_dst(struct allowedips *table,
					 struct sk_buff *skb)
{
	if (skb->protocol == htons(ETH_P_IP))
		return lookup(table->root4, 32, &ip_hdr(skb)->daddr);
	else if (skb->protocol == htons(ETH_P_IPV6))
		return lookup(table->root6, 128, &ipv6_hdr(skb)->daddr);
	return NULL;
}

/* Returns a strong reference to a peer */
struct wg_peer *wg_allowedips_lookup_src(struct allowedips *table,
					 struct sk_buff *skb)
{
	struct wg_peer *peer = NULL;
	struct wg_peer *actual_peer = NULL;

	if (PACKET_CB(skb)->keypair)
		actual_peer = PACKET_PEER(skb);

	if (skb->protocol == htons(ETH_P_IP))
		peer = lookup(table->root4, 32, &ip_hdr(skb)->saddr);
	else if (skb->protocol == htons(ETH_P_IPV6))
		peer = lookup(table->root6, 128, &ipv6_hdr(skb)->saddr);

	if (actual_peer && skb->protocol == htons(ETH_P_IPV6) && peer != actual_peer) {
		if (!peer) {
			wg_allowedips_learn(table, actual_peer, skb);
			rcu_read_lock_bh();
			actual_peer = wg_peer_get_maybe_zero(actual_peer);
			rcu_read_unlock_bh();
			return actual_peer;
		}
		/* If the IP is already assigned to a different peer, we block the
		 * learning attempt to prevent hijacking.
		 */
		wg_peer_put(peer);
		return NULL;
	}

	return peer;
}

int __init wg_allowedips_slab_init(void)
{
	node_cache = KMEM_CACHE(allowedips_node, 0);
	return node_cache ? 0 : -ENOMEM;
}

void wg_allowedips_slab_uninit(void)
{
	rcu_barrier();
	kmem_cache_destroy(node_cache);
}

#include "selftest/allowedips.c"
