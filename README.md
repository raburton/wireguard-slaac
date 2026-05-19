# wireguard-slaac v2

## Intro
- A modified version of wireguard that supports automatic learning of peer IPv6 addresses. Run this on your server, and unmodified clients can use SLAAC (+ privacy extensions) to assign themselves IP addresses from your supplied prefix.
- Largely created by AI (specifically Gemini 3 Flash and GPT5-mini), but with a lot of hand holding by me.
- This second version uses a separate list for learned IPs, not adding them to the existing AllowedIPs list. More efficient as they are all /128, so simple lookup, easier to keep track of a per-peer list, and no need for device level locking on learns (which resulted in far fewer deadlocks to debug).

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
- Implementation where learned IPv6 source addresses are stored in a dedicated learned-IPs subsystem (hash table + per-peer lists), separate from the AllowedIPs prefix trie.
- Fast-path reads use RCU; writes use a localized spinlock for the learned table.

Overview / purpose
- Automatically record exact IPv6 source addresses seen on authenticated packets (within configured LearnableIPs prefixes) and provide efficient exact-address lookups for packet-to-peer resolution.
- Maintain configured prefix matching in the AllowedIPs trie while storing dynamic exact learned addresses in a separate, purpose-built structure.

Design summary
- Distinct data stores:
  - AllowedIPs trie: holds configured prefixes only.
  - Learned table (wg_learned_table): a kernel hashtable keyed by exact IPv6 address with per-peer linked lists and metadata.
- Learning flow:
  - The source IPv6 address is checked to ensure it matches one of the peer’s LearnableIPs prefixes.
  - `wg_learnedips_learn()` implements learning:
    - Fast-path (RCU): checks if an entry already exists for the address; if so, refreshes `last_used` and returns.
    - Slow-path: allocate a new learned entry (GFP_ATOMIC), take `tbl->lock` (spinlock), recheck for races, evict the oldest per-peer entry if the per-peer cap is reached, and insert the new entry into the hash and the peer’s list.
- Lookups:
  - Configured prefix lookups remain trie-based.
  - Exact learned-address lookups are handled by `wg_learnedips_lookup()` which uses the hash table with an RCU fast-path.
  - Packet handling should consult the appropriate lookup (configured prefix vs learned exact) depending on needed semantics.
- Eviction and GC:
  - Per-peer learned cap enforced via `peer->learned_count` and `peer->learned_list`; when the cap is reached, the oldest per-peer entry is evicted.
  - A periodic GC worker (`learnedips_gc_worker`) scans the hash and removes stale entries older than a configured timeout.
- Locking & concurrency:
  - Fast-path lookups are RCU-protected and lockless for existing entries.
  - Learned-table updates use a local spinlock (`tbl->lock`), minimizing contention compared to global device locks.
  - The design localizes learned churn to the learned subsystem so other parts of the system are less affected.
- Anti-hijack behavior:
  - If an address is already recorded for a different peer, learning is refused to prevent address hijacking.
  - If the address is unclaimed and the packet is authenticated for the peer, learning proceeds (subject to checks and caps).

Advantages
- Efficient exact-address storage and lookup (hash table) optimized for /128 matches (average O(1)).
- Localized locking (spinlock on learned table) reduces contention and improves scalability for high-rate learning activity.
- Clear separation of responsibilities between configured prefixes (trie) and dynamic learned addresses makes each subsystem simpler and easier to optimize.
- RCU fast-path for reads yields low overhead once an address is learned.

Limitations / considerations
- Separate structure to maintain increases implementation surface area (additional code, GC, and bookkeeping).
- Packet handling must coordinate lookups across two places (configured trie and learned table) as appropriate.
- Must ensure correct RCU handling and proper cleanup during device teardown to avoid leaks or races.

Key implementation points (where to look)
- New learned subsystem file: `wireguard-linux/learnedips.c`
  - Learning function: `wg_learnedips_learn()`
  - Exact lookup: `wg_learnedips_lookup()`
  - GC and eviction: `learnedips_gc_worker`, `wg_learnedips_table_init`, `wg_learnedips_remove_by_peer`
- Per-peer fields: `wireguard-linux/peer.h`
  - `learned_list`, `learned_count`, and per-peer list bookkeeping
- AllowedIPs utilities still used to validate configured learnable prefixes: `wg_allowedips_contains_v6(...)` in `allowedips.c`
- Netlink / userspace hooks: extend as needed to expose learned entries if external visibility is required.

