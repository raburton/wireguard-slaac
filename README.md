# wireguard-slaac v1

## Intro
- A modified version of wireguard that supports automatic learning of peer IPv6 addresses. Run this on your server, and unmodified clients can use SLAAC (+ privacy extensions) to assign themselves IP addresses from your supplied prefix.
- Largely created by AI (specifically Gemini 3 Flash and GPT5-mini), but with a lot of hand holding by me.

## Building
On debian:
```
make
```
## Config
- Add `LearnableIPs = ::/0` to each peer in your config file. This is all you need if you trust your peers, or to get testing.
- Ideally you'd limit this to link local and your real prefix e.g. `LearnableIPs = fe80::/64, 2a0a:1234:1234:1234/64`.
- You need a /64 prefix if you want SLAAC to work.
- You should add link local (fe80::) because even if you manually assign one to the client with wireguard config, some devices still expect to be able to use SLAAC for this. You need link local to work in order to get router annoucements (RA) advertising your prefix.
- Public prefixes for SLAAC use are not passed by wireguard (unlike a static address assignment), you need to run something that will provide this (over the link local address), such as `radvd` in unicast mode. e.g.
```
interface wg0
{
        AdvSendAdvert on;
        IgnoreIfMissing on;
        UnicastOnly on;
        prefix 2a0a:1234:1234:1234::/64
        {
                AdvOnLink on;
                AdvAutonomous on;
        };
};
```

## Running
```
rmmod wireguard
insmod wireguard-linux/wireguard.ko
export PATH=$PWD/wireguard-tools/src:$PATH
wg-quick up wg0 (or whichever)
```

## AI generated explanation

Status
- Implementation where learned IPv6 source addresses are inserted into the same AllowedIPs trie used for configured prefixes.
- Learning is deferred via a per-peer queue + workqueue to avoid expensive mutations in packet receive (NAPI/softirq) contexts.

Overview / purpose
- Automatically learn IPv6 source addresses seen on authenticated packets so peers can be matched by those addresses without explicit AllowedIPs configuration.
- Keep packet-to-peer resolution using a single prefix trie data structure.

Design summary
- Single primary data structure: the AllowedIPs prefix trie.
  - Configured prefixes and learned exact addresses both live in the trie.
  - Trie nodes carry metadata (peer pointer, is_learned flag, last_used timestamp).
- Per-peer learning queue + worker:
  - Each peer maintains a small ring buffer (learned_ip_queue[]) protected by a spinlock.
  - When a packet qualifies for learning, its source IPv6 is enqueued and a per-peer work item (learn_ip_work) is scheduled.
  - The worker drains the queue and inserts entries into the AllowedIPs trie under the device update mutex.
- Learning insertion semantics:
  - Worker inserts exact /128 nodes into the trie with `is_learned = true`.
  - Per-node bookkeeping increments the peer’s learned count.
  - When the per-peer cap is reached, the worker selects the oldest learned node for eviction and removes it from the trie.
- Eviction and GC:
  - Per-peer learned limit enforced via atomic learned count; eviction chooses the oldest learned node for that peer.
  - A periodic GC worker walks learned nodes and removes stale nodes by `last_used` (timeout-based expiry).
- Lookups:
  - Packet lookups (source/destination) are performed via the trie. Learned addresses are visible via the same lookup path as configured prefixes.
  - Trie reader paths use RCU to allow lockless reads.
- Locking & concurrency:
  - Fast-path reads use RCU (rcu_read_lock_bh / rcu_read_unlock_bh).
  - Structural changes to the trie (insertion/removal) are performed under a global mutex (device_update_lock).
  - The per-peer queue uses a spinlock for quick enqueue/dequeue in packet context.
  - The worker performs heavy work under the device_update_lock to keep trie state consistent.
- Anti-hijack behavior:
  - Learning is prevented if the address is already assigned to another peer.
  - If an authenticated packet belongs to a given peer and the address is unassigned, the packet triggers queueing and the worker will insert it (subject to per-peer limits and GC).

Advantages
- Single canonical structure for both configured prefixes and learned entries, simplifying lookup logic: a single trie lookup resolves either case.
- Deferred insertion avoids doing trie mutations in softirq context.
- Reuses existing prefix machinery and serialization already present for AllowedIPs management.

Limitations / considerations
- Mixing configured prefixes and learned entries adds complexity to trie code (extra flags, last_used, learned counters).
- Global device_update_lock guards trie updates; heavy learning activity can increase contention on this mutex.
- Exact-match learned-address operations (e.g., frequent insert/remove) happen in a trie optimized for prefixes, which may be less efficient than a dedicated exact-key structure.
- Learning visibility is deferred by the queue/worker model — there is a small delay between packet reception and learned entry becoming visible.

Key implementation points (where to look)
- Primary file: `wireguard-linux/allowedips.c`
  - Worker: `wg_allowedips_learn_worker`
  - Trie insertion: `add(...)` with `learned = true`
  - Trie eviction / removal: `__wg_allowedips_remove_node`, `wg_allowedips_gc_worker`
- Peer structure and queue: `wireguard-linux/peer.h`
  - Per-peer ring: `learned_ip_queue[]`, `learn_ip_work`, `learned_ip_queue_lock`, `learned_ip_count`
- Netlink / userspace reporting: `wireguard-linux/netlink.c` and `wireguard-tools` (dumps include AllowedIPs entries)

