/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_LEARNEDIPS_H
#define _WG_LEARNEDIPS_H

#include <linux/hashtable.h>
#include <linux/in6.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>

enum {
	WG_MAX_LEARNED_PER_PEER = 16,
	/* Run GC once per hour (in jiffies) */
	WG_LEARNED_GC_INTERVAL = HZ * 3600,
	/* Consider entries unused if not seen for 24 hours (in jiffies) */
	WG_LEARNED_MAX_AGE = HZ * 24 * 3600,
};

struct wg_peer;
struct wg_device;

/**
 * struct wg_learned_entry - a single dynamically-learned IPv6 /128 address.
 *
 * The same object is referenced from both the per-device global hash table
 * (via @hash_node) and the owning peer's per-peer list (via @peer_list).
 * All write access is serialised by wg_learned_table.lock; reads use RCU.
 */
struct wg_learned_entry {
	struct rcu_head      rcu;        /* deferred-free hook */
	struct hlist_node    hash_node;  /* global hash-table linkage */
	struct list_head     peer_list;  /* per-peer list linkage */
	struct in6_addr      addr;       /* the learned IPv6 address */
	struct wg_peer __rcu *peer;      /* owning peer */
	unsigned long        last_used;  /* jiffies timestamp */
};

/**
 * struct wg_learned_table - per-device exact-match table for learned IPv6
 * addresses.
 *
 * Write operations (insert, evict, remove) are serialised by @lock.
 * Lookups on the packet hot-path use RCU (rcu_read_lock_bh) and do not
 * take the lock.
 */
struct wg_learned_table {
	DECLARE_HASHTABLE(table, 8); /* 256 buckets */
	spinlock_t lock;
};

/* Module-level slab cache — must be called once from wg_mod_init(). */
int  wg_learnedips_slab_init(void);
void wg_learnedips_slab_uninit(void);

/* Per-device table lifecycle. */
void wg_learnedips_table_init(struct wg_learned_table *tbl);
void wg_learnedips_table_free(struct wg_learned_table *tbl);

/**
 * wg_learnedips_learn() - record the IPv6 source address seen from a peer.
 *
 * Called from the authenticated-packet receive path (softirq / NAPI context).
 * Allocates with GFP_ATOMIC.
 *
 * If @addr is not yet in the table it is associated with @peer (subject to the
 * WG_MAX_LEARNED_PER_PEER limit; the oldest entry is evicted when the limit is
 * reached).  If @addr is already associated with @peer the last_used timestamp
 * is refreshed.
 *
 * Anti-hijack: if @addr is already associated with a *different* peer the
 * function returns false and the packet must be dropped.
 *
 * On allocation failure the function returns true (fail-open: the packet has
 * already been authenticated, so it is better to deliver it than to silently
 * drop it; the address will be re-learned on the next packet).
 *
 * Returns true  if @addr is now (or was already) associated with @peer.
 * Returns false if @addr is claimed by a different peer.
 */
bool wg_learnedips_learn(struct wg_device *wg, struct wg_peer *peer,
			 const struct in6_addr *addr);

/* Returns a strong reference to a peer on exact IPv6 learned match. */
struct wg_peer *wg_learnedips_lookup(struct wg_device *wg,
				     const struct in6_addr *addr);

/**
 * wg_learnedips_remove_by_peer() - remove all learned entries for @peer.
 *
 * Must be called after napi_disable() has guaranteed that the NAPI receive
 * path can no longer add new entries for this peer.
 */
void wg_learnedips_remove_by_peer(struct wg_device *wg, struct wg_peer *peer);

/* Start/stop periodic GC for a device's learned table. */
void wg_learnedips_start_gc(struct wg_device *wg);
void wg_learnedips_stop_gc(struct wg_device *wg);

#endif /* _WG_LEARNEDIPS_H */
