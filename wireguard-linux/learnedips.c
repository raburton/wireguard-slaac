// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "learnedips.h"
#include "peer.h"
#include "device.h"
#include "allowedips.h"

#include <linux/jhash.h>
#include <linux/ipv6.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>

static struct kmem_cache *learned_cache;

static void learned_entry_free_rcu(struct rcu_head *rcu)
{
	kmem_cache_free(learned_cache,
			container_of(rcu, struct wg_learned_entry, rcu));
}

/* Hash an IPv6 address to a u32 key for use with the kernel hashtable API. */
static inline u32 addr_key(const struct in6_addr *addr)
{
	return jhash2((const u32 *)addr->s6_addr32, 4, 0);
}

int __init wg_learnedips_slab_init(void)
{
	learned_cache = KMEM_CACHE(wg_learned_entry, 0);
	return learned_cache ? 0 : -ENOMEM;
}

void wg_learnedips_slab_uninit(void)
{
	rcu_barrier();
	kmem_cache_destroy(learned_cache);
}

void wg_learnedips_table_init(struct wg_learned_table *tbl)
{
	hash_init(tbl->table);
	spin_lock_init(&tbl->lock);
}

static void learnedips_gc_worker(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct wg_device *wg = container_of(dwork, struct wg_device, learned_gc_work);
	struct wg_learned_table *tbl = &wg->learned_table;
	struct wg_learned_entry *entry;
	struct hlist_node *tmp;
	int bkt;
	unsigned long cutoff = jiffies - WG_LEARNED_MAX_AGE;

	spin_lock_bh(&tbl->lock);
	hash_for_each_safe(tbl->table, bkt, tmp, entry, hash_node) {
		if (time_before(entry->last_used, cutoff)) {
			struct wg_peer *owner = rcu_dereference_protected(entry->peer,
											   lockdep_is_held(&tbl->lock));
			hash_del_rcu(&entry->hash_node);
			list_del(&entry->peer_list);
			if (owner)
				--owner->learned_count;
			call_rcu(&entry->rcu, learned_entry_free_rcu);
		}
	}
	spin_unlock_bh(&tbl->lock);

	/* Reschedule for next interval */
	schedule_delayed_work(&wg->learned_gc_work, WG_LEARNED_GC_INTERVAL);
}

void wg_learnedips_start_gc(struct wg_device *wg)
{
	INIT_DELAYED_WORK(&wg->learned_gc_work, learnedips_gc_worker);
	schedule_delayed_work(&wg->learned_gc_work, WG_LEARNED_GC_INTERVAL);
}

void wg_learnedips_stop_gc(struct wg_device *wg)
{
	cancel_delayed_work_sync(&wg->learned_gc_work);
}

/**
 * wg_learnedips_table_free() - release all remaining entries in the table.
 *
 * Called during device teardown after wg_peer_remove_all().  Under normal
 * operation the table will already be empty at this point because
 * wg_learnedips_remove_by_peer() is called for every peer during removal.
 * This function acts as a safety net for any entries that might have been
 * missed.  Peer-list backlinks are NOT touched here because peer memory may
 * already have been freed.
 */
void wg_learnedips_table_free(struct wg_learned_table *tbl)
{
	struct wg_learned_entry *entry;
	struct hlist_node *tmp;
	int bkt;

	spin_lock_bh(&tbl->lock);
	hash_for_each_safe(tbl->table, bkt, tmp, entry, hash_node) {
		hash_del_rcu(&entry->hash_node);
		call_rcu(&entry->rcu, learned_entry_free_rcu);
	}
	spin_unlock_bh(&tbl->lock);
}

/**
 * wg_learnedips_learn() - learn an IPv6 source address from an authenticated
 * packet.
 *
 * Locking model
 * -------------
 * Fast path: address already in table
 *   A lockless RCU read-side lookup is performed first.  If the address is
 *   found for the correct peer, last_used is updated with WRITE_ONCE and we
 *   return immediately without taking the write lock.
 *
 * Slow path: new address
 *   The entry is allocated with GFP_ATOMIC (safe in softirq/NAPI context).
 *   The write lock (tbl->lock) is then taken and the hash is rechecked to
 *   guard against races with a concurrent inserter.  Per-peer accounting
 *   (learned_list, learned_count) is also protected by tbl->lock so that
 *   both the global hash and the per-peer list stay in sync under a single
 *   lock acquisition.
 *
 * Eviction
 *   When the per-peer limit (WG_MAX_LEARNED_PER_PEER) is reached, the
 *   oldest entry is found by scanning the peer's learned_list (O(n) where
 *   n ≤ WG_MAX_LEARNED_PER_PEER) and evicted before the new entry is
 *   inserted.
 */
bool wg_learnedips_learn(struct wg_device *wg, struct wg_peer *peer,
			 const struct in6_addr *addr)
{
	struct wg_learned_table *tbl = &wg->learned_table;
	struct wg_learned_entry *entry, *new_entry;
	struct wg_peer *existing_peer;
	u32 key = addr_key(addr);

	/* Only learn addresses that match the peer's configured learnable-IP
	 * prefixes. If no matching prefix is found (including the case where
	 * the learnable list is empty), do not learn the address. */
	if (!wg_allowedips_contains_v6(&peer->learnable_ips, addr))
		return false;

	/*
	 * Fast path: address already recorded — check under RCU without taking
	 * the write lock.
	 */
	rcu_read_lock_bh();
	hash_for_each_possible_rcu(tbl->table, entry, hash_node, key) {
		if (!ipv6_addr_equal(&entry->addr, addr))
			continue;
		existing_peer = rcu_dereference_bh(entry->peer);
		if (existing_peer == peer) {
			/* Refresh the timestamp for LRU eviction. */
			WRITE_ONCE(entry->last_used, jiffies);
			rcu_read_unlock_bh();
			return true;
		}
		/* Address already claimed by a different peer — anti-hijack. */
		rcu_read_unlock_bh();
		return false;
	}
	rcu_read_unlock_bh();

	/*
	 * Slow path: the address is not yet in the table.
	 * Allocate a new entry before taking the write lock to minimise lock
	 * hold time.  GFP_ATOMIC is required in NAPI / softirq context.
	 */
	new_entry = kmem_cache_alloc(learned_cache, GFP_ATOMIC);
	if (unlikely(!new_entry))
		/*
		 * Fail-open: the packet has already passed cryptographic
		 * authentication, so prefer delivering it over silently
		 * dropping it.  The address will be re-learned on the next
		 * packet from this peer.
		 */
		return true;

	new_entry->addr      = *addr;
	new_entry->last_used = jiffies;
	INIT_LIST_HEAD(&new_entry->peer_list);
	RCU_INIT_POINTER(new_entry->peer, peer);

	spin_lock_bh(&tbl->lock);

	/*
	 * Recheck under the write lock: another CPU may have inserted an entry
	 * for the same address between the RCU lookup and the lock acquisition.
	 */
	hash_for_each_possible(tbl->table, entry, hash_node, key) {
		if (!ipv6_addr_equal(&entry->addr, addr))
			continue;
		existing_peer = rcu_dereference_protected(entry->peer,
				lockdep_is_held(&tbl->lock));
		spin_unlock_bh(&tbl->lock);
		kmem_cache_free(learned_cache, new_entry);
		return existing_peer == peer;
	}

	/*
	 * Evict the oldest learned entry for this peer when the per-peer limit
	 * is reached.  The scan is bounded by WG_MAX_LEARNED_PER_PEER.
	 */
	if (peer->learned_count >= WG_MAX_LEARNED_PER_PEER) {
		struct wg_learned_entry *victim = NULL, *le;
		unsigned long oldest = jiffies;

		list_for_each_entry(le, &peer->learned_list, peer_list) {
			unsigned long t = READ_ONCE(le->last_used);

			if (!victim || time_before(t, oldest)) {
				oldest = t;
				victim = le;
			}
		}
		if (victim) {
			hash_del_rcu(&victim->hash_node);
			list_del(&victim->peer_list);
			--peer->learned_count;
			call_rcu(&victim->rcu, learned_entry_free_rcu);
		}
	}

	hash_add_rcu(tbl->table, &new_entry->hash_node, key);
	list_add_tail(&new_entry->peer_list, &peer->learned_list);
	++peer->learned_count;

	spin_unlock_bh(&tbl->lock);

	pr_debug_ratelimited("%s: Learned IPv6 source %pI6c for peer %llu\n",
			     wg->dev->name, addr, peer->internal_id);
	return true;
}

/* Returns a strong reference to a peer on exact learned IPv6 match. */
struct wg_peer *wg_learnedips_lookup(struct wg_device *wg,
				     const struct in6_addr *addr)
{
	struct wg_learned_table *tbl = &wg->learned_table;
	struct wg_learned_entry *entry;
	struct wg_peer *peer = NULL;
	u32 key = addr_key(addr);

	rcu_read_lock_bh();
	hash_for_each_possible_rcu(tbl->table, entry, hash_node, key) {
		if (!ipv6_addr_equal(&entry->addr, addr))
			continue;
		peer = wg_peer_get_maybe_zero(rcu_dereference_bh(entry->peer));
		if (peer)
			WRITE_ONCE(entry->last_used, jiffies);
		break;
	}
	rcu_read_unlock_bh();

	return peer;
}

/**
 * wg_learnedips_remove_by_peer() - remove all learned entries for @peer.
 *
 * Called from peer_remove_after_dead() after napi_disable() has ensured
 * that no further NAPI callbacks can add new entries for this peer.
 *
 * Takes tbl->lock, removes each entry from the global hash and from the
 * per-peer list, then schedules deferred RCU freeing.
 */
void wg_learnedips_remove_by_peer(struct wg_device *wg, struct wg_peer *peer)
{
	struct wg_learned_table *tbl = &wg->learned_table;
	struct wg_learned_entry *entry, *tmp;

	spin_lock_bh(&tbl->lock);
	list_for_each_entry_safe(entry, tmp, &peer->learned_list, peer_list) {
		hash_del_rcu(&entry->hash_node);
		list_del(&entry->peer_list);
		--peer->learned_count;
		call_rcu(&entry->rcu, learned_entry_free_rcu);
	}
	spin_unlock_bh(&tbl->lock);
}
