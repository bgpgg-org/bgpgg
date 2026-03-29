# RPKI-RTR Client (RFC 8210) + Origin Validation (RFC 6811)

Module: `core/src/rpki/`

## Applicable RFCs

| RFC | Title | Status | Impact |
|-----|-------|--------|--------|
| 6811 | BGP Prefix Origin Validation | Must implement | Validation procedure, policy integration, re-evaluation on VRP change |
| 8210 | RPKI-to-Router Protocol v1 | Must implement | Wire protocol for cache communication |
| 8481 | Clarifications to Origin Validation | Must implement | Updates 6811: validate ALL prefixes, never apply default policy |
| 8893 | RPKI Origin Validation for BGP Export | Must implement | Updates 6811: validate at export too, using effective origin AS |
| 8097 | Origin Validation State Extended Community | Done | Non-transitive ext community to carry validation state over iBGP |
| 6810 | RPKI-to-Router Protocol v0 | Skip | Superseded by 8210 |
| 9319 | Use of maxLength in RPKI | Skip | Guidance for ROA creators, not routers |
| 8210bis | RPKI-to-Router Protocol v2 (draft) | Skip | Still a draft, adds ASPA -- revisit when published |

## Design Decisions

### Component Architecture

```
                 +---------------------------------------------+
                 |              RtrManager Task                 |
                 |  - Per-cache VRP storage                     |
                 |  - Spawns/manages CacheSession sub-tasks     |
                 |  - Diffs VRP sets on End-of-Data             |
                 |  - Sends VRP diffs to Server via ServerOp    |
                 +----------------------+----------------------+
                                        |
                          spawns N      | ServerOp::VrpUpdate
                    +-------+-------+   |   { added, removed }
                    v       v       v   |
              +-------+ +-------+ +-------+
              |Cache 1| |Cache 2| |Cache 3|   (CacheSession sub-tasks)
              |TCP/SSH| |TCP/SSH| |TCP/SSH|   (one per configured cache)
              +-------+ +-------+ +-------+
                    |       |       |
                    +---+---+---+---+
                        |       |
                        v       v
                    VrpBatch channel
                    (back to RtrManager)
                                        |
                                        v
                 +---------------------------------------------+
                 |                  Server                      |
                 |  - Owns VRP trie (no shared state, no locks) |
                 |  - Owns rib trie (in LocRib)                 |
                 |  - Validates routes on receive               |
                 |  - On VrpUpdate: rib trie -> affected routes |
                 |    -> re-validate -> best path -> propagate  |
                 +---------------------------------------------+
```

### CacheSession lifecycle

CacheSessions are long-lived like peer tasks -- they reconnect on failure
and only exit when RtrManager explicitly shuts them down.

RtrManager owns `HashMap<SocketAddr, CacheSessionHandle>`:
```rust
struct CacheSessionHandle {
    config: RtrCacheConfig,
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}
```

Add/remove via gRPC:
1. gRPC AddRpkiCache -> Server sends `RpkiOp::AddCache(config)` to RtrManager
2. RtrManager spawns CacheSession, stores handle
3. gRPC RemoveRpkiCache -> Server sends `RpkiOp::RemoveCache(addr)`
4. RtrManager signals shutdown, removes per-cache VRP storage, diffs merged
   VRP set, sends `ServerOp::VrpUpdate` to Server

On server shutdown: server drops `rpki_tx`, RtrManager's receive loop ends,
it shuts down all CacheSessions.

### Why messages route through RtrManager (not direct to Server)

CacheSessions send VRP batches to RtrManager, not directly to Server.
RtrManager must see each batch first because it maintains per-cache VRP
storage and computes the diff against the merged view. A CacheSession
can't compute the diff -- it doesn't know what the other caches have.

This is not a hot path. End-of-Data arrives once per refresh interval
(default 3600s full, 300-600s incremental). One extra channel send of
a small diff is negligible.

### VRP updates sent immediately (no batching/coalescing)

RtrManager sends `ServerOp::VrpUpdate` to Server immediately when a cache
completes a sync (End-of-Data). No startup delay or coalescing needed.

During startup with N caches, this produces N messages:
1. Cache 1 full sync -> ~400k VRPs added -> one big VrpUpdate, full rib
   re-validation (unavoidable -- need to validate everything once)
2. Cache 2 full sync -> mostly duplicates of cache 1, small diff -> tiny update
3. Cache 3 -> same as cache 2

After startup, incremental updates are a handful of VRPs every few minutes.

### Server owns VrpTable instance -- no shared state

VRP logic (trie, validation algorithm) lives in `core/src/rpki/vrp.rs` as
`VrpTable`. Server owns an instance of it, like it owns LocRib. No locks --
server is single-threaded.

RtrManager sends VRP diffs via `ServerOp::VrpUpdate { added, removed }`.
Server calls `vrp_table.add()`/`remove()` for each entry, then re-validates
affected routes. Same pattern as LocRib: the module defines the type and
logic, server owns the instance and calls the API.

```rust
// core/src/rpki/vrp.rs -- defined in RPKI module
impl VrpTable {
    pub fn add(&mut self, vrps: &[Vrp])
    pub fn remove(&mut self, vrps: &[Vrp])
    pub fn validate(&self, prefix: IpNetwork, origin_as: u32) -> RpkiValidation
    fn covering_vrps(&self, prefix: IpNetwork) -> Vec<Vrp>  // private, promote when needed
}
```

### RtrManager never touches the RIB or VrpTable

RtrManager only knows about per-cache VRP storage and RTR sessions. On
End-of-Data it computes the VRP diff (filtering out duplicates covered by
other caches) and sends it to Server. Server applies the diff to VrpTable,
uses its rib trie to find affected prefixes, re-validates, re-runs best
path selection. Clean separation: RPKI module defines VRP types and logic,
RtrManager manages cache sessions, server owns the instances and ties them
together.

### Validation state lives on Path (not PathAttrs)

RPKI validation state is local metadata -- not a BGP wire attribute.
It must never be serialized into UPDATE messages. The `Path` struct already
holds local-only fields (`local_path_id`, `remote_path_id`, `stale`).
Add `rpki_state: RpkiValidation` there. Policy reads it from Path directly.

```rust
pub enum RpkiValidation {
    Valid,
    Invalid,
    NotFound,
}

pub struct Path {
    pub local_path_id: Option<u32>,
    pub remote_path_id: Option<u32>,
    pub attrs: PathAttrs,
    pub stale: bool,
    pub rpki_state: RpkiValidation,  // local metadata, never serialized
}
```

### Two trie structures, different purposes

1. **Rib trie** (owned by LocRib) -- given a VRP prefix, find all stored
   routes that are subnets of it. Used during VRP re-evaluation:
   "VRP for 10.0.0.0/8 changed, which routes in the rib fall under it?"
   Query: `subtree(10.0.0.0/8)` -> returns 10.1.0.0/16, 10.2.3.0/24, etc.

2. **VrpTable** (defined in `core/src/rpki/vrp.rs`, instance owned by Server)
   -- given a route prefix + origin AS, find covering VRPs to determine
   validation state. Server calls `vrp_table.validate(prefix, origin_as)`.
   Internally: `covering_vrps(10.1.2.0/24)` -> VRP(10.0.0.0/8, max /24, AS 65001).
   Then check: does route prefix length <= max_length AND origin AS match?

Both are prefix tries. The rib trie indexes route prefixes; the VrpTable
indexes VRP prefixes. Lookups go in opposite directions (descendants vs
ancestors).

### Channel pattern (follows BMP precedent)

```rust
// Server -> RtrManager (commands)
// No Shutdown variant -- when server drops rpki_tx, RtrManager's receive
// loop ends and it cleans up. RTR has no graceful shutdown PDU.
enum RpkiOp {
    AddCache(RtrCacheConfig),
    RemoveCache(SocketAddr),
}

// RtrManager -> Server (via existing ServerOp channel)
enum ServerOp {
    // ... existing variants ...
    VrpUpdate {
        added: Vec<Vrp>,
        removed: Vec<Vrp>,
    },
}

struct Vrp {
    prefix: IpNetwork,
    max_length: u8,
    origin_as: u32,
}
```

Server holds `rpki_tx: Option<mpsc::UnboundedSender<RpkiOp>>`.
RtrManager holds a clone of `server_op_tx` (same channel peers use).

### Validation is policy input only (RFC 6811 + RFC 8481)

Server sets rpki_state on each path but never auto-rejects. Filtering is
done by policy: user configures import/export policy to match on rpki_state
and accept/reject accordingly. "Set state, don't act."

Two key requirements from RFC 8481:
1. Validate ALL prefixes, not just those with covering ROAs. If no VRP
   covers a prefix, state is NotFound (not "skip validation").
2. Never apply default policy on validation state. Only act when the
   operator explicitly configures it. No built-in "reject invalid" rule.
   Policy engine extension is in Phase 6 (new match condition on rpki_state).

### Export validation uses effective origin AS (RFC 8893)

Validation at export time must use the "effective origin AS" -- the origin
AS after local modifications like private AS stripping, confederation
handling, etc. This may differ from the origin AS stored in the path's
AS_PATH. The validation function takes an explicit origin_as argument
rather than always extracting from the path.

Example: route arrives with AS_PATH [65001, 65002, 65003], origin AS = 65003.
On export, policy strips private ASes -> AS_PATH becomes [65001], effective
origin is now 65001. Export-time validation must check 65001 against VrpTable,
not the original 65003.

NOTE: bgpgg has no AS_PATH modification today (no prepend, no private AS
stripping). So effective origin AS always equals stored origin AS for now.
The API shape (`validate(prefix, origin_as)`) already handles it when
AS_PATH modification is added later. No extra work needed now.


### VRP re-evaluation flow

```
1. CacheSession: receives End-of-Data, sends completed batch to RtrManager
   (batch is already a delta: announces/withdrawals from RTR prefix PDUs)
2. RtrManager: apply delta to this cache's VRP set (insert/remove)
3. RtrManager: for each VRP in delta, check other caches:
   - VRP added to cache X, no other cache has it -> include in server diff as added
   - VRP removed from cache X, no other cache has it -> include as removed
   - Otherwise -> duplicate, skip
4. RtrManager: send ServerOp::VrpUpdate { added, removed } to Server
5. Server: vrp_table.apply_diff(added, removed)
6. Server: for each changed Vrp, query rib trie for affected route prefixes
7. Server: for each affected prefix, for each peer's adj-rib-in path:
   a. Recompute rpki_state via vrp_table.validate(prefix, origin_as)
   b. Re-run full import policy on the pre-policy path
   c. Update loc-rib with the result -> RouteDelta
8. Server: propagate_routes(delta, None) -- same existing call as peer updates
```

Server handler sketch:
```rust
ServerOp::VrpUpdate { added, removed } => {
    self.vrp_table.add(&added);
    self.vrp_table.remove(&removed);
    let affected = self.find_affected_prefixes(&added, &removed); // rib trie
    // Collect affected prefixes first, then iterate each peer's adj-rib-in
    // once -- filter against affected set. First sync is full-table scan
    // (unavoidable), subsequent incremental updates are small.
    let delta = self.revalidate_affected(&affected); // re-feed from adj-rib-in
    self.propagate_routes(delta, None).await;
}
```

### Adj-rib-in moves to server (prerequisite for RPKI)

Re-evaluation requires re-running import policy on pre-policy paths when
rpki_state changes. This means the server needs access to adj-rib-in.

**Decision: move adj-rib-in from peer task to PeerInfo in server.**

Adj-rib-out is already on PeerInfo in server. Moving adj-rib-in there
makes it consistent -- both ribs in the server, peer task is purely
the protocol/connection handler.

Trade-off considered:

Option A (chosen): Adj-rib-in in PeerInfo on server.
- Re-evaluation is a synchronous loop: read adj-rib-in, stamp rpki_state,
  re-run import policy, update loc-rib. No async, no fragile assumptions.
- Correct regardless of future policy changes (AS_PATH modification, etc.)
- gRPC GetAdjRibIn becomes a direct read instead of async channel request.
- Cost: peer task's max-prefix check and BMP adj-rib-in count move to
  server. Peer task keeps parse/validate/loop-detect, just doesn't store.

Option B (rejected): Keep adj-rib-in in peer task, batch-request on VRP change.
- Minimal structural change.
- But: async round-trip per peer on every VRP change. On startup first sync,
  hits every peer with thousands of affected prefixes. Server blocks waiting.
  Also needs reverse-mapping (prefix -> which peers have it) that doesn't
  exist today.

What moves to server:
- `PeerInfo` gains `adj_rib_in: AdjRibIn`
- `ServerOp::PeerUpdate` handler stores in adj-rib-in before import policy
- `PeerOp::GetAdjRibIn` removed (direct read on PeerInfo)
- Peer task drops `rib_in` field, stops storing routes
- Max-prefix enforcement moves to server
- BMP adj-rib-in count reads from PeerInfo

What stays in peer task:
- UPDATE parsing, path attribute construction
- AS_PATH loop detection, route reflector loop detection
- Sending parsed routes to server via ServerOp::PeerUpdate (unchanged)

### Per-cache VRP storage and cache failover

RtrManager keeps `HashMap<SocketAddr, HashSet<Vrp>>` -- one set per cache
(RFC 8210 Section 10 MUST). Per-cache deltas are filtered against other
caches to produce net diffs sent to server. On cache disconnect, its VRPs
are retained until another cache is
fully synced (RFC 8210 Section 10). On reconnect, incremental Serial Query
picks up where it left off; if session is stale, Cache Reset + full re-sync.

---

## Implementation Phases

### Phase 0: Rib Trie (prerequisite) -- COMPLETE

Custom Patricia trie at `core/src/table.rs` with arena allocation and
implicit path compression. Shared by LocRib (prefix index) and future
VrpTable.

LocRib uses dual structure: HashMap for hot-path reads/writes,
PrefixTrie<K, ()> as secondary index for subtree/covering queries.
Trie synced inside LocRib's private helpers -- callers don't see it.

Operations:
- `insert` / `remove` / `get` / `get_mut` -- exact prefix
- `subtree(prefix)` -- all stored prefixes that are subnets of prefix
- `covering(prefix)` -- all stored prefixes that contain prefix
- `iter()` -- all entries

Two separate tries per AFI (IPv4 and IPv6), matching LocRib's existing
per-AFI storage pattern.

Useful beyond RPKI: longer-prefixes/shorter-prefixes CLI queries.

### Phase 1: RTR Codec (`core/src/rpki/rtr.rs`) -- COMPLETE

PDU types (RFC 8210):
- Serial Notify, Serial Query, Reset Query
- Cache Response, IPv4 Prefix, IPv6 Prefix, End of Data
- Cache Reset, Error Report, Router Key (v1)

Protocol version 1 only. Parse from bytes, serialize to bytes.
If a cache responds with v0 PDUs, send Error Report code 4 ("Unsupported
Protocol Version") and terminate (RFC 8210 Section 7). No v0 downgrade.

Router Key PDUs (type 9) are parsed but silently discarded -- bgpgg does
not implement BGPsec. CacheSession logs receipt and drops the data.

Tests: round-trip encode/decode for each PDU type.

### Phase 2: VrpTable (`core/src/rpki/vrp.rs`) -- COMPLETE

`VrpTable` -- per-AFI `PrefixTrie<Vec<Vrp>>` storing VRP tuples. Multiple
VRPs can share the same prefix (different max_length or origin_as), so
each trie node stores a list. Defined in the RPKI module, instance owned
by Server.

API:
- `add(vrps: &[Vrp])` / `remove(vrps: &[Vrp])` -- batch insert/remove with dedup
- `validate(prefix, origin_as) -> RpkiValidation` -- RFC 6811 Section 2
- `Vrp::covers(route_prefix_len, origin_as) -> bool` -- single VRP match check

`covering_vrps()` is private for now; will be promoted to pub when gRPC
diagnostics need it.

Validation logic (RFC 6811 Section 2):
- Find all VRPs whose prefix covers route_prefix
- For each covering VRP: `Vrp::covers()` checks route prefix length
  <= max_length AND origin_as matches AND origin_as != 0
- If any match: Valid
- If covering VRPs exist but none match: Invalid
- If no covering VRPs at all: NotFound

Edge cases (RFC 6811 Section 2):
- VRP with ASN 0 can never produce a Match (contributes to "covered"
  but never "matched" -- treated as covering-only for Invalid detection)
- Route with origin AS "NONE" (final segment is AS_SET) cannot be
  Matched by any VRP
- origin_as == 0 passed to validate() -> always NotFound (short-circuit)

### Phase 3: RtrManager + CacheSession (`core/src/rpki/task.rs`)

**RtrManager** -- single tokio task:
- Receives RpkiOp from Server (add/remove cache)
- Spawns/manages CacheSession sub-tasks
- Receives VRP batches from CacheSessions via channel
- Maintains per-cache VRP storage
- Computes VRP diffs, sends ServerOp::VrpUpdate to Server
- Manages preference tiers (see below)

**VRP batches -- no flooding by design.** The RTR protocol has built-in
batching: a cache sends Cache Response, then N prefix PDUs, then End of
Data. CacheSession collects all prefix PDUs into a local Vec and sends
one `VrpBatch` to RtrManager only on End of Data. One batch per sync
cycle -- once per refresh interval (default 3600s full, 300-600s
incremental).

```rust
struct VrpBatch {
    cache_addr: SocketAddr,
    session_id: u16,
    serial: u32,
    announced: Vec<Vrp>,   // prefix PDUs with flags=1
    withdrawn: Vec<Vrp>,   // prefix PDUs with flags=0
}
```

**CacheSession** -- one per cache, spawned by RtrManager:
- Connects to cache via TCP (default RTR port 323). PDU read/write is
  generic over `AsyncRead + AsyncWrite` -- when SSH is added (Phase 8),
  make CacheSession generic over the stream type, no other changes needed.
- RTR protocol exchange: Reset Query or Serial Query
- Collects VRP announcements/withdrawals within a Cache Response..End of Data
- Sends completed batch to RtrManager
- Handles retry/refresh/expire timers
- Reconnects with exponential backoff on failure (1s -> 2s -> ... -> 30s cap,
  reset on successful connect). Same pattern as BMP (`bmp/destination.rs`).
- On Cache Reset or No Data errors, RtrManager tries more-preferred caches
  first (RFC 8210 Section 8.3/8.4)

**Preference tiers (RFC 8210 Section 4, 10).** Caches with the same
preference value form a tier.

> The router MUST choose the most preferred, by configuration, cache
> or set of caches so that the operator may control load on their
> caches and the Global RPKI. (RFC 8210 Section 4)

Three events from CacheSessions:

```rust
enum CacheEvent {
    Batch(VrpBatch),           // successful sync (End of Data)
    Disconnected(SocketAddr),  // TCP lost -- spawn trigger (preemptive)
    Expired(SocketAddr),       // expire_interval hit -- data trigger
}
```

Disconnect and expire are separate concerns:
- **Disconnected** triggers preemptive spawn of next preference level
  (so it's already syncing before data expires). No data change.
- **Expired** triggers VRP removal from `per_cache_vrps` and diff to
  Server (RFC 8210 Section 6: "The router MUST NOT retain the data
  past the time indicated by [Expire Interval]").

**Spawn/kill model.** Only spawn CacheSessions for preference levels
that need to be active. CacheSession is either running or doesn't exist.

RtrManager state:
- `per_cache_vrps: HashMap<SocketAddr, HashSet<Vrp>>` -- caches with data
- `sessions: HashMap<SocketAddr, CacheSessionHandle>` -- running sessions
- `all_configs: Vec<RtrCacheConfig>` -- all configured caches

Active preference derived from caches that have data:
```rust
fn lowest_active_preference(&self) -> Option<u8> {
    self.per_cache_vrps.keys()
        .filter_map(|addr| self.sessions.get(addr))
        .map(|s| s.config.preference)
        .min()
}
```

**Normal operation:**
1. Startup: spawn sessions for lowest configured preference only.
2. Sessions sync, send VrpBatch to RtrManager.
3. RtrManager stores in `per_cache_vrps`, merges all caches with data,
   diffs to Server.

**Preemptive failover** (on Disconnected, before data expires):
1. Cache A (pref=1) disconnects. Data stays in `per_cache_vrps` (still
   valid until expire).
2. RtrManager checks: any other pref=1 cache still connected? If no,
   spawn next preference level (e.g., pref=10) preemptively.
   RFC 8210 Section 8.4: "the router SHOULD attempt to connect to any
   other caches in its cache list, in preference order."
3. Fallback cache connects and syncs before A's data expires. Zero gap.

**Data expiry** (on Expired):
1. Remove cache's VRPs from `per_cache_vrps`, diff to Server.
2. Fallback cache already has data — routes stay validated.

**Recovery:**
1. Failed cache retries, reconnects, syncs. VrpBatch arrives.
2. If its preference < `lowest_active_preference()`: kill less-preferred
   sessions (one preferred-tier cache synced is enough), drop their data
   from `per_cache_vrps`, diff to Server.
   RFC 8210 Section 10: "When a more-preferred cache becomes available,
   if resources allow, it would be prudent for the client to start
   fetching from that cache." / "A client MAY drop the data from a
   particular cache when it is fully in sync with one or more other
   caches."

**Merge:** data from all caches in `per_cache_vrps` merged for
validation regardless of preference. RFC 8210 Section 10:
"implementations MUST NOT distinguish between data sources when
performing validation of BGP announcements."

`RtrCacheConfig`:
```rust
struct RtrCacheConfig {
    address: SocketAddr,
    preference: u8,  // lower = more preferred, non-unique (same value = same tier)
    retry_interval: Option<u64>,    // override, default from End-of-Data
    refresh_interval: Option<u64>,  // override, default from End-of-Data
    expire_interval: Option<u64>,   // override, default from End-of-Data
}
```

Session state per cache:
- session_id: Option<u16>
- serial_number: Option<u32>
- refresh_interval, retry_interval, expire_interval (from End of Data)

**Session ID mismatch (RFC 8210 Section 5.1).** When CacheSession
receives a Cache Response, it compares session_id against its stored
value. If stored session_id is Some and doesn't match, the cache has
restarted: send Error Report code 0 ("Corrupt Data"), flush all data
learned from this cache (remove from `per_cache_vrps`), and reconnect
with Reset Query. On first connect (stored session_id is None), accept
whatever the cache sends.

**Serial number wrap-around (RFC 8210 Section 4, RFC 1982).** Serial
number comparison MUST use RFC 1982 arithmetic: given two serials s1
and s2, s1 < s2 iff `(s1 != s2) && ((s2 - s1) as i32 > 0)`. This
handles the u32 wrap-around case correctly. Used when deciding whether
a Serial Notify indicates new data.

**Error code handling (RFC 8210 Section 12).** On receiving an Error
Report PDU, CacheSession checks the error code:
- Code 2 (No Data Available): non-fatal. Report to RtrManager via
  CacheEvent, RtrManager tries other caches (RFC 8210 Section 8.4).
  CacheSession retries after retry_interval.
- All other codes (0,1,3,4,5,6,7,8): fatal. Log the error text (if
  present, UTF-8), terminate the TCP session, reconnect with backoff.
- Code 4 (Unsupported Protocol Version): fatal. We only support v1,
  no downgrade.
- MUST NOT send an Error Report in response to an Error Report PDU.
  If a received Error Report is itself malformed, drop the session
  silently (RFC 8210 Section 5.11).

**Duplicate announcement detection (RFC 8210 Section 5.6).** During
a Cache Response..End of Data sequence, CacheSession tracks the set of
announced VRP tuples {prefix, len, max_len, ASN}. If a duplicate is
received (same tuple announced twice without intervening withdrawal),
SHOULD send Error Report code 7 ("Duplicate Announcement Received")
and terminate the session.

**Withdrawal of unknown record (RFC 8210 Section 5.11).** During an
incremental update (Serial Query response), if a withdrawal (flags=0)
arrives for a VRP tuple that doesn't exist in CacheSession's local
set for this cache, send Error Report code 6 ("Withdrawal of Unknown
Record") and terminate the session. CacheSession already tracks its
VRP set for per-cache storage -- check withdrawals against it.

**Timer bounds validation (RFC 8210 Section 6).** On receiving End of
Data, validate timer values from the PDU before storing them:
- Refresh: 1 - 86,400 seconds (default 3,600)
- Retry: 1 - 7,200 seconds (default 600)
- Expire: 600 - 172,800 seconds (default 7,200)
- Expire MUST be > max(Refresh, Retry)
If values are out of range, use the defaults and log a warning.
Timer countdowns start on End of Data receipt.

**Reset Query response validation (RFC 8210 Section 5.5).** When
CacheSession sent a Reset Query, all payload PDUs in the Cache
Response..End of Data sequence MUST have flags=1 (announce). If a
withdrawal (flags=0) is received during a full sync, send Error Report
code 0 ("Corrupt Data") and terminate -- this is a protocol violation.

**TCP keep-alives (RFC 8210 Section 9).** CacheSession SHOULD enable
TCP keep-alives on the socket after connecting:
> "The client and server SHOULD enable TCP keepalive on each
> transport session."
Use `setsockopt(SO_KEEPALIVE)` with OS defaults.

### Phase 4: Move adj-rib-in to server (done)

Prerequisite for RPKI re-evaluation (see design decision above).
`AdjRibIn` already exists at `core/src/rib/rib_in.rs` (per-AFI
`HashMap<prefix, Route>`) — currently owned by peer task. Move it.

- Add `adj_rib_in: AdjRibIn` to `PeerInfo`
- `ServerOp::PeerUpdate` handler stores in adj-rib-in before import policy
- Remove `PeerOp::GetAdjRibIn` (direct read on PeerInfo)
- Peer task drops `rib_in` field
- Move max-prefix enforcement to server
- Move BMP adj-rib-in count to read from PeerInfo
- Tests: verify adj-rib-in contents match what peer sent (pre-policy)

### Phase 4.1: Move UPDATE validation to server (done)

Clean responsibility split: peer task handles wire protocol only
(parse, build Path, extract NLRI), server handles all routing
decisions (validation, adj-rib-in, policy, loc-rib, propagation).

Functional behavior: loc-rib contents and wire protocol behavior
are identical. adj-rib-in now stores pre-validation routes per
RFC 4271 3.2 ("unprocessed routing information"), so gRPC adj-rib-in
queries may return routes that fail validation (e.g. AS-looped).

Changes:
- Peer `incoming.rs` stripped to deserialization only
- Validation in `server/ops.rs`: AFI/SAFI, first-AS, AS loop,
  RR loop, nexthop-self, eBGP attr scrubbing, GRACEFUL_SHUTDOWN
- `disabled_afi_safi` moved from Peer to PeerInfo
- `ClearPeerAfiSafi` ServerOp removed (inline in server)
- AS_TRANS skip in first-AS check (OLD speaker)
- Server package restructured: `server/{mod,ops,ops_mgmt,helpers}.rs`

### Phase 5: Server Integration (done)

`BgpServer` owns `VrpTable` instance. Shared `apply_import()` helper stamps
`rpki_state` on Path and runs import policies -- used by both
`handle_peer_update` (new routes) and `handle_vrp_update` (re-evaluation).

VRP re-evaluation reuses `apply_peer_update` -- no separate re-evaluation
method. `affected_prefixes()` on LocRib finds route prefixes covered by
changed VRPs, `affected_routes()` collects adj-rib-in paths,
`reevaluate_routes()` feeds them back through `apply_peer_update`.

`rpki_state` lives on Path (not PathAttrs). `upsert_path` compares attrs
only, so rpki_state-only changes preserve Arc identity -> no propagation.
If policy changes attrs based on rpki_state (e.g. LOCAL_PREF), attrs differ
-> Arc replaced -> propagation.

`Path::origin_as()` extracts origin from AS_PATH per RFC 6811 Section 2.

Proto `RpkiValidation` enum + `rpki_validation` field on proto Path message
already wired in gRPC service (pulled forward from Phase 9).

FakeCache test helper at `core/tests/utils/rtr.rs`. Phase 10 test case 1
(basic validation: Valid/Invalid/NotFound) implemented in Phase 5.

Validation on export (RFC 8893): not yet implemented. `apply_import` only
runs on import. Export-time validation to be added when AS_PATH modification
is implemented (no effective origin AS differs from stored origin AS today).

### Phase 6: Policy Integration (done)

`Condition::RpkiValidation` in `core/src/policy/statement.rs` matches on
`path.rpki_state`. Config uses `Option<String>` ("valid", "invalid",
"not-found") parsed in `add_conditions()`, same pattern as `route_type`.

YAML config:
```yaml
conditions:
  rpki-validation: "invalid"
actions:
  reject: true
```

Proto: `optional RpkiValidation rpki_validation = 9` on `ConditionsConfig`
message, using existing proto enum. Conversion in `proto_policy.rs`.

No set actions needed -- existing actions (reject, set local-pref,
set community, etc.) combine with the new match condition.

This is user-configured, not built-in behavior (RFC 8481). Absent
explicit operator configuration, policy MUST NOT be applied based on
validation state (RFC 8481 Section 5).

Available in import and export policies. Redistribution policies
(RFC 8893 Section 3) not applicable -- bgpgg does not support
redistribution today.

NOTE: `SetLocalPref` with `force: false` (the only mode exposed via
gRPC proto) cannot override the default local-pref 100 set by
`apply_import()`. To boost local-pref for Valid routes via policy,
either use YAML config with `force: true`, or use community tagging
as a workaround. Consider adding `force` to the proto in Phase 9.

Test: `core/tests/policy.rs::test_import_policy_rpki_validation` --
explicit match on all three states (Invalid->reject, Valid->tag
community 65001:1, NotFound->tag community 65001:2).

### Phase 7: Origin Validation State Extended Community (RFC 8097) -- COMPLETE

When validation state influences best path selection via a non-propagated
attribute (e.g., LOCAL_PREF), iBGP peers may not have the same validation
state and could select different best paths -> routing loops.

RFC 8097 defines a non-transitive opaque extended community:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      0x43     |      0x00     |           Reserved            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Reserved                     |validation_state|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Type high octet: 0x43 (non-transitive opaque)
- Sub-type: 0x00
- 5 bytes reserved (MUST be 0 on send, ignored on receive)
- 1 byte validation state: 0 = Valid, 1 = NotFound, 2 = Invalid
- String format: `rpki:valid`, `rpki:not-found`, `rpki:invalid`

#### Send side

Per-peer `send_rpki_community: bool` (default false). When true,
`compute_export_path()` attaches the RPKI state extended community based on
the path's current `rpki_state`.

- Remove any existing RPKI state communities first, then attach new one.
  The path may already carry an RPKI state community from a previous hop
  (e.g., upstream iBGP peer). RFC 8097 says SHOULD NOT send more
  than one instance, and receivers use the greatest (most pessimistic)
  value when multiple are present -- so we strip and replace with
  our own fresh validation result.
- Default false; typically enabled on iBGP peers. Operator can enable
  on eBGP peers if warranted but SHOULD NOT by default (RFC 8097).

#### Receive side (policy-based)

No special receive flag. The operator uses existing policy to match the
RPKI state extended community and set rpki_state via a new `SetRpkiState`
action. This keeps the receive side explicit and composable with other
policy logic.

Example import policy:
```yaml
- name: rpki-from-rr
  statements:
    - conditions:
        match_ext_community_set: "rpki-valid"   # rpki:valid
      actions:
        set_rpki_state: valid
        result: accept
    - conditions:
        match_ext_community_set: "rpki-invalid"  # rpki:invalid
      actions:
        set_rpki_state: invalid
        result: reject
```

This means routers that validate locally ignore the community (no
policy to consume it), while routers that rely on an upstream
validator opt in explicitly via import policy.

#### eBGP stripping

Non-transitive extended communities (type high bit 0x40) MUST be
stripped at eBGP boundaries. On export: `build_export_attrs()` strips
non-transitive ext communities for eBGP peers. On import from eBGP:
strip RPKI state communities before policy evaluation.

#### Implementation

1. `ext_community.rs`: Add `SUBTYPE_ORIGIN_VALIDATION: u8 = 0x00`,
   `from_rpki_state_community(state: u8) -> u64`, `is_rpki_state_community(extcomm)`,
   `rpki_state_community_value(extcomm) -> Option<u8>`. Parse/format `rpki:valid`,
   `rpki:not-found`, `rpki:invalid`.

2. `PeerConfig`: Add `send_rpki_community: bool`.

3. `PeerExportContext`: Carry `send_rpki_community`.

4. `compute_export_path()`: After export policy, if `send_rpki_community`,
   strip existing RPKI state communities and attach new one from rpki_state.

5. `Action::SetRpkiState(RpkiValidation)`: New policy action that sets
   `path.rpki_state`. Wire through gRPC/config parsing.

6. `build_export_attrs()`: Strip non-transitive ext communities for
   eBGP peers. Strip RPKI state on eBGP import in `apply_import()` or earlier.

#### Tests

1. **Send**: Two iBGP peers, `send_rpki_community: true` on exporter.
   Verify RPKI state ext community appears with correct validation state.
2. **Receive via policy**: Import policy matches `rpki:valid`, action
   sets rpki_state. Verify path gets correct state.
3. **eBGP strip**: RPKI state community from eBGP peer is stripped.
4. **Dedup**: Path with existing RPKI state community -- only one sent.
5. **ovs parse/format roundtrip**: `rpki:valid`, `rpki:not-found`,
   `rpki:invalid` all roundtrip through parse/format.

### Phase 8: SSH Transport (RFC 8210 Section 10) -- COMPLETE

SSH transport via `russh` crate. CacheSession connects over SSH,
authenticates with a private key, and requests the `rpki-rtr`
subsystem (RFC 8210 Section 10). Data flows over the SSH channel's
`ChannelStream` which implements `AsyncRead + AsyncWrite` -- same
interface as TCP, so `run_session()` is unchanged.

Transport selection:
- `RtrTransport` enum in `manager.rs`: `Tcp` or `Ssh(SshTransport)`
- `TransportType` enum in `config.rs` for YAML: `tcp` (default) or `ssh`
- `RpkiCacheConfig::to_rtr_transport()` validates and converts

SSH connection flow (`session.rs::connect_ssh()`):
1. Load private key from file (`russh::keys::load_secret_key`)
2. SSH handshake (`russh::client::connect`) with `SshHandler` for
   host key verification (known_hosts file or accept-all with warning)
3. Authenticate (`handle.authenticate_publickey`)
4. Open session channel, request `rpki-rtr` subsystem
5. `channel.into_stream()` -> split into reader/writer for `run_session()`
6. SSH `Handle` kept alive alongside stream (dropped on disconnect)

`run()` dispatches on `config.transport`: TCP calls `connect_tcp()`,
SSH calls `connect_ssh()`. Both feed into the same `run_session()`.

YAML config:
```yaml
rpki-caches:
  - address: "10.0.0.2:22"
    transport: ssh
    ssh-username: rpki
    ssh-private-key-file: /etc/bgp/rpki_ssh.key
    ssh-known-hosts-file: /etc/bgp/rpki_known_hosts  # optional
```

Test: `FakeSshCache` in `tests/utils/rtr.rs` -- SSH server using
`russh::server` that accepts any auth and the `rpki-rtr` subsystem.
`FakeCache<S>` generic struct holds shared RTR protocol logic.
`verify_basic_validation()` helper runs the same validation test
across both TCP and SSH transports.

Bug fix during SSH work: `upsert_path` in `rib_loc.rs` was not
updating `rpki_state` when attrs were unchanged (Arc identity
preservation). VRP re-evaluation after routes arrived was silently
dropped. Fixed by mutating `rpki_state` in place via `Arc::make_mut`
on the existing path, preserving Arc identity for ADD-PATH.

### Phase 9: gRPC/Config Integration

- AddRpkiCache / RemoveRpkiCache gRPC calls
- Config file `[[rpki_caches]]` section
- GetRpkiState for diagnostics (cache status, VRP count, last sync time)
- GetRpkiValidation for per-prefix validation state lookup
- Proto Path message `rpki_validation` field: done in Phase 5.
  Satisfies RFC 8893 SHOULD: "An implementation SHOULD be able to
  list announcements that were not sent to a peer, e.g., because they
  were marked Invalid."

### Phase 10: Integration Tests (`core/tests/rpki.rs`)

**FakeCache** (`core/tests/utils/rtr.rs`) -- test helper that speaks
RTR protocol, same pattern as FakePeer. Listens on a TCP port, server's
CacheSession connects to it. Basic implementation done in Phase 5.

```rust
struct FakeCache {
    listener: TcpListener,
    stream: Option<TcpStream>,
    session_id: u16,
    serial: u32,
}
```

Implemented methods:
- `listen() -> Self` -- bind to random port
- `accept()` -- accept CacheSession connection
- `read_message()` -- read any RTR PDU from client
- `read_reset_query()` -- read and assert Reset Query
- `send_vrps(vrps: &[Vrp])` -- send Cache Response + prefix PDUs + End
  of Data as one batch

Methods to add for remaining test cases:
- `read_serial_query()` -- read Serial Query from client
- `send_cache_reset()` -- force client to do full re-sync
- `send_error(code)` -- simulate cache error (No Data Available, etc.)
- `send_notify()` -- Serial Notify to trigger immediate client query
- `disconnect()` -- drop TCP connection

Test cases (table-driven where possible):

1. **Basic validation state (done in Phase 5).** Start server + FakeCache.
   Inject VRPs via FakeCache. Announce routes from peers. Verify rpki_state
   on received routes (Valid/Invalid/NotFound) via poll_rib with
   rpki_validation field.

2. **VRP update re-evaluation.** Announce routes, verify NotFound. Then
   inject covering VRPs via FakeCache. Verify routes transition to
   Valid/Invalid. Then withdraw VRPs. Verify routes go back to NotFound.

3. **Tier failover.** Configure two FakeCaches with different preferences.
   Preferred cache syncs, verify routes validated. Disconnect preferred
   cache, let expire_interval hit. Verify fallback cache activates and
   routes stay validated.

4. **Tier recovery.** After failover to less-preferred cache, reconnect
   preferred cache. Verify preferred tier reactivates, less-preferred
   sessions killed.

5. **Multi-cache merge.** Two FakeCaches same preference. Each provides
   different VRPs. Verify both VRP sets merged for validation. Kill one
   cache, verify its VRPs removed but other cache's VRPs still work.
   Verify via `poll_rib()` -- proto Path already has `rpki_validation`
   field (done in Phase 5), checked in routes_match() comparison.

6. **Cache reset.** FakeCache sends Cache Reset mid-session. Verify
   CacheSession does full re-sync (Reset Query) and VRPs are correct
   after re-sync.

7. **Import policy on rpki_state (done in Phase 6).** Three-statement
   policy: reject Invalid, tag Valid with community 65001:1, tag NotFound
   with 65001:2. Verifies all three match conditions and absence of
   rejected route. Test: `core/tests/policy.rs::test_import_policy_rpki_validation`.

8. **RPKI state extended community send (RFC 8097).** Two servers, iBGP peered.
   Configure send_rpki_community on exporting peer. Verify receiving
   peer gets the `rpki:valid` / `rpki:invalid` / `rpki:not-found` ext
   community.

9. **RPKI state receive via policy.** Import policy matches RPKI state ext community
   and sets rpki_state via SetRpkiState action. Verify path gets the
   correct rpki_state on the receiving router.

10. **eBGP RPKI state stripping.** eBGP peer sends RPKI state community. Verify it
    is stripped before policy evaluation.

### Performance: Dual HashMap + PrefixTrie

Trie-only LocRib was 68% slower (24.7s vs 14.7s for 1M routes). Profiling
(flamegraph at `../perf/trie/summary.md`) showed trie lookups added ~9.4%
CPU, spread across millions of O(depth) calls vs HashMap O(1). The
bottleneck was `get_best_path` (3.74%) and `PrefixTrie::get` (3.61%),
not insert.

FRR uses a dual structure (trie + hashmap on same nodes). BIRD uses
hashmap only. GoBGP uses hashmap + ephemeral trie.

Solution: HashMap for all hot-path reads/writes, PrefixTrie as secondary
index storing `()` for subtree/covering queries only. Trie is synced
inside LocRib's private helpers -- callers don't know about it.

| Version | Route processing (1M routes) |
|---------|------------------------------|
| HashMap only (master) | 14.73s |
| Trie only | 24.72s (+68%) |
| **Dual (HashMap + trie)** | **15.05s (+2%)** |

