# LLGR Implementation Plan (RFC 9494)

## RFC 9494 Quick Reference

**Capability Code: 71**

Per-AFI tuple (7 bytes — RFC 9494 Section 3):
```
AFI (2 bytes) | SAFI (1 byte) | Flags (1 byte, F-bit = MSB) | Long-Lived Stale Time (3 bytes, big-endian seconds)
```

- LLGR_STALE community: `0xFFFF0006`
- LLST = Long-Lived Stale Time (per-AFI/SAFI, no global value, no suggested default)
- LLGR requires GR capability also be present

**LLGR_TUPLE_LEN = 7**: AFI(2) + SAFI(1) + Flags(1) + StaleTime(3).
Analogous to existing `GR_AFI_SAFI_TUPLE_LEN = 4`.

## Lifecycle Overview

```
Session drops
     |
     v
GR phase: routes stale (stale=true), no withdrawals
     |
     | GR restart_time expires
     v
 +---+------------------------------+
 |                                  |
 | LLGR negotiated for AFI/SAFI?    |
 |                                  |
 v (no)                             v (yes)
Sweep immediately               Tag routes with LLGR_STALE community
(current GR behavior)           Withdraw from non-LLGR peers
                                Start LLGR timer (LLST seconds)
                                     |
                                     | LLST expires OR EOR received
                                     v
                                Sweep stale routes
                                Propagate withdrawals
```

---

## Phase 1: Capability Advertisement and Negotiation

### `core/src/bgp/msg_open_types.rs`
- Add `LlgrRestart = 71` to `BgpCapabiltyCode` enum and its `From<u8>`/`as_u8()` match arms
- Add constants:
  ```rust
  const LLGR_TUPLE_LEN: usize = 7;  // AFI(2) + SAFI(1) + Flags(1) + StaleTime(3)
  const LLGR_F_FLAG: u8 = 0x80;     // F bit (MSB): forwarding state preserved
  ```
- Add struct:
  ```rust
  pub struct LlgrCapability {
      // (afi_safi, f_bit, stale_time_secs)
      pub(crate) entries: Vec<(AfiSafi, bool, u32)>,
  }
  ```
- Add `Capability::new_llgr(entries: &[(AfiSafi, bool, u32)]) -> Self`
  - Encode each 7-byte tuple: AFI(2) + SAFI(1) + flags(1) + stale_time(3 big-endian)
  - No assert needed — stale_time is validated at the boundary (see config.rs below)


- Add `Capability::as_llgr(&self) -> Option<LlgrCapability>`
  - Parse 7-byte tuples, skip unknown AFI/SAFI (same pattern as `as_graceful_restart`)

### `core/src/config.rs`
- Add structs:
  ```rust
  pub struct LlgrAfiSafiConfig {
      pub afi_safi: AfiSafi,
      pub stale_time: u32,  // seconds, 24-bit max (16777215)
  }

  pub struct LlgrConfig {
      pub entries: Vec<LlgrAfiSafiConfig>,  // empty = LLGR disabled
  }
  ```
  `Default`: `entries: vec![]`
- Add `llgr: LlgrConfig` to `PeerConfig` with `#[serde(default)]`
- Guard at config boundary: `LlgrAfiSafiConfig::new(afi_safi, stale_time) -> Self` validates
  stale_time, logging a warning and clamping if > 0xFFFFFF. Both TOML deserialization
  (via a custom `Deserialize` impl or a `#[serde(deserialize_with)]` helper) and
  `proto_to_peer_config()` go through this constructor. The encoder then trusts the value.

### `core/src/peer/mod.rs`
- Add `llgr: Option<LlgrCapability>` to `PeerCapabilities`

### `core/src/peer/messages.rs`
**`build_optional_params()`**: after GR capability block:
```rust
// RFC 9494: LLGR requires GR capability to also be present
if config.graceful_restart.enabled && !config.llgr.entries.is_empty() {
    let entries: Vec<_> = config.llgr.entries
        .iter()
        .map(|e| (e.afi_safi, false, e.stale_time))
        // false = F-bit: "forwarding state preserved across restart"
        // We never preserve forwarding state (software router, no hardware dataplane).
        // Same reasoning as in build_optional_params() for standard GR.
        .collect();
    optional_params.push(OptionalParam::new_capability(Capability::new_llgr(&entries)));
}
```

**`extract_capabilities()`**: add match arm:
```rust
BgpCapabiltyCode::LlgrRestart => {
    capabilities.llgr = cap.as_llgr();
}
```

**`enter_open_confirm()`**: include `llgr: peer_capabilities.llgr` in `self.capabilities`, add to `info!()` log.

### `proto/bgp.proto`
```protobuf
message LlgrAfiSafiConfig {
    optional uint32 afi = 1;
    optional uint32 safi = 2;
    optional uint32 stale_time_secs = 3;  // 24-bit max (16777215)
}
message LlgrConfig {
    repeated LlgrAfiSafiConfig entries = 1;
}
```
Add to `SessionConfig`: `optional LlgrConfig llgr = 19;`

### `core/src/grpc/service.rs`
In `proto_to_peer_config()`:
```rust
llgr: proto_session.llgr.map(|llgr| LlgrConfig {
    entries: llgr.entries.into_iter().filter_map(|e| {
        let afi = Afi::try_from(e.afi? as u16).ok()?;
        let safi = Safi::try_from(e.safi? as u8).ok()?;
        Some(LlgrAfiSafiConfig {
            afi_safi: AfiSafi::new(afi, safi),
            stale_time: e.stale_time_secs.unwrap_or(0).min(0xFFFFFF),
        })
    }).collect(),
}).unwrap_or_default(),
```

### Tests (Phase 1)
In `core/src/bgp/msg_open_types.rs`:
- `test_llgr_capability_roundtrip`: encode → decode, single and multi-AFI
- `test_llgr_capability_f_bit`: F-bit encoding/decoding

In `core/src/peer/messages.rs`:
- `test_llgr_capability_advertised`: non-empty entries + GR enabled → OPEN contains cap 71
- `test_llgr_not_advertised_without_gr`: GR disabled → no cap 71 even if entries set

---

## Phase 2: LLGR_STALE and NO_LLGR Communities

### `core/src/bgp/community.rs`
Add constants:
```rust
pub const LLGR_STALE: u32 = 0xFFFF0006;
pub const NO_LLGR: u32 = 0xFFFF0007;  // RFC 9494: do not retain this route during LLGR
```

### `core/src/rib/rib_loc.rs`
Add function `mark_peer_routes_llgr_stale(peer_ip, afi_safi) -> RouteDelta`:
- Finds all paths from `peer_ip` where `stale = true` in the given AFI/SAFI table
- **Skip paths that have `NO_LLGR` community** — these are swept immediately (not retained)
- Adds `LLGR_STALE` community to remaining stale paths via `Arc::make_mut()`
- Recomputes best path per prefix (LLGR_STALE routes are now least-preferred per Phase 3)
- Returns RouteDelta: `best_changed` for prefixes where best flipped, `changed` for all tagged prefixes

The function returns two deltas conceptually — one for swept (NO_LLGR) routes and one for
tagged (LLGR_STALE) routes — but can be combined into a single RouteDelta since both result
in propagation.

Modify `upsert_path()` (used when peer re-sends routes):
- No change needed: when peer re-sends the same route without LLGR_STALE, `attrs != stored_attrs`
  (stored path has LLGR_STALE, incoming doesn't) → path is replaced, community is gone. Already correct.

---

## Phase 3: Route Selection (least-preferred)

### `core/src/rib/path.rs` — `best_path_cmp()`
Add as the first comparison step:
```rust
// RFC 9494: LLGR_STALE routes are least preferred
let a_llgr = self.attrs.communities.contains(&LLGR_STALE);
let b_llgr = other.attrs.communities.contains(&LLGR_STALE);
if a_llgr != b_llgr {
    // prefer non-stale (self wins if b is stale)
    return if b_llgr { Ordering::Greater } else { Ordering::Less };
}
```

---

## Phase 4: Propagation Filtering

### `core/src/peer/outgoing.rs` — `should_filter_by_community()`
Add after existing community checks:
```rust
// RFC 9494 Section 4.2: "MUST NOT advertise LLGR_STALE routes to a peer that has not
// negotiated the LLGR capability." — filter the route entirely, not strip the community.
if attrs.communities.contains(&community::LLGR_STALE)
    && peer_ctx.capabilities.llgr.is_none()
{
    return true;
}
```

This naturally causes:
- Non-LLGR peers: receive withdrawals when propagation runs after LLGR_STALE is tagged
- LLGR peers: receive re-advertisement with updated path (LLGR_STALE community present)

**LLGR_STALE must not be stripped**: the community passes through unchanged to LLGR-capable
peers. RFC 9494 Section 4.3: "MUST NOT be removed when the route is further advertised."
No stripping logic should be added to the export path for this community.

`PeerExportContext` already carries `capabilities: &PeerCapabilities` so no struct changes needed.

---

## Phase 5: LLGR Timer and GR Expiry Handling

### Where LLGR expiry state lives

LLGR expiry belongs in `PeerInfo` (not `Peer` task, not a top-level `BgpServer` field):

```rust
pub struct PeerInfo {
    ...
    pub llgr_expiry: HashMap<AfiSafi, Instant>,  // non-empty = in LLGR phase
}
```

**Why not `Peer` task?** LLGR expiry triggers RIB operations (`remove_peer_routes_stale`,
`propagate_routes`) which are server-owned. The peer task has no RIB access — it would
need to send a `ServerOp` anyway, negating any benefit of ownership there.

**Why not a top-level `BgpServer` field?** Per-peer state already lives in `PeerInfo`.
A separate `HashMap<IpAddr, HashMap<AfiSafi, Instant>>` on `BgpServer` duplicates the
peer key. Keeping it in `PeerInfo` means cancellation on reconnect is
`peer_info.llgr_expiry.clear()`, and `on_tick` scans `self.peers` which it already
iterates for other purposes.

---

### Approach A: Spawned tasks per AFI/SAFI (GoBGP style)

GoBGP uses this approach: one goroutine per AFI/SAFI with a channel for cancellation.

```rust
// PeerInfo carries JoinHandles instead of Instants
pub llgr_timers: HashMap<AfiSafi, JoinHandle<()>>,
```

On GR expiry, for each LLGR AFI/SAFI:
```rust
let handle = tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(llst)).await;
    let _ = server_tx.send(ServerOp::LlgrTimerExpired { peer_ip, afi_safi });
});
peer_info.llgr_timers.insert(afi_safi, handle);
```

New `ServerOp::LlgrTimerExpired` handler sweeps stale routes directly.

Cancellation:
```rust
peer_info.llgr_timers.drain().for_each(|(_, h)| h.abort());
```

**Tradeoffs:**
- Timer fires precisely at LLST seconds
- But the `ServerOp` still sits in `op_rx` queue behind any convergence burst — so
  processing is delayed under load regardless
- Requires `ServerOp::LlgrTimerExpired` variant, `JoinHandle` storage, `abort()` calls
- Scattered: timer lifecycle spread across spawn site, handler, and cancellation sites

---

### Approach B: Central `on_tick` in server loop (chosen)

A 1-second server_tick arm in `run()` checks `PeerInfo.llgr_expiry` for expired entries and
handles them directly — no `ServerOp` round-trip needed since `on_tick` already has
`&mut self`.

```rust
// In run():
let mut server_tick = tokio::time::interval(Duration::from_secs(1));
server_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

loop {
    tokio::select! {
        Ok((stream, _)) = listener.accept() => { self.accept_peer(stream).await; }
        Some(req) = self.mgmt_rx.recv() => { self.handle_mgmt_op(req, bind_addr).await; }
        Some(op) = self.op_rx.recv() => { self.handle_server_op(op).await; }
        _ = server_tick.tick() => {
            self.on_tick().await;
        }
    }
}
```

```rust
async fn on_tick(&mut self) {
    self.check_llgr_expiry().await;
    // future: self.check_mrai_expiry().await;
}

async fn check_llgr_expiry(&mut self) {
    let now = Instant::now();
    let expired: Vec<(IpAddr, AfiSafi)> = self.peers.iter()
        .flat_map(|(ip, p)| p.llgr_expiry.iter()
            .filter(|(_, exp)| now >= **exp)
            .map(move |(as_, _)| (*ip, *as_)))
        .collect();

    for (peer_ip, afi_safi) in expired {
        self.peers.get_mut(&peer_ip).unwrap().llgr_expiry.remove(&afi_safi);
        info!(%peer_ip, %afi_safi, "LLGR stale timer expired");
        let delta = self.loc_rib.remove_peer_routes_stale(peer_ip, &[afi_safi]);
        self.propagate_routes(delta, Some(peer_ip)).await;
    }
}
```

**Tradeoffs vs Approach A:**
- Up to 1s jitter on expiry — irrelevant for stale times in minutes/hours
- Wakeup every second when LLGR is active — negligible cost
- Under heavy convergence load, `on_tick` is delayed — but Approach A has the same
  problem (the `ServerOp` queues behind the same burst)
- No `ServerOp` variant, no `JoinHandle`, no `abort()` — simpler lifecycle
- Centralised: all periodic server-side work in `on_tick`, easy to extend
- Direct `&mut self` access: calls `loc_rib` and `propagate_routes` without a channel

---

### F-bit on re-establishment (`core/src/peer/messages.rs` — `enter_open_confirm()`)
When the peer reconnects and sends a new OPEN, check the LLGR F-bit per AFI/SAFI.
If F-bit=0 for an AFI/SAFI that is in LLGR phase, sweep stale routes for it immediately
(do not wait for the LLGR timer). Cancel its `llgr_expiry` entry.

In practice: after `enter_open_confirm()` stores `peer_capabilities.llgr`, the server
checks `PeerHandshakeComplete` and can inspect the new capability F-bits against any
active `llgr_expiry` entries to decide which to clear immediately.

### LLST local cap (`core/src/config.rs` and `core/src/server_ops.rs`)
Following FRR: received LLST from peer capability MAY be reduced by local config.
Add optional `max_llgr_stale_time: Option<u32>` to the server-level `Config` (not per-peer).
When scheduling expiry: `let llst = peer_llst.min(config.max_llgr_stale_time.unwrap_or(u32::MAX))`.
Add to `proto/bgp.proto` server config if needed.

### Consecutive restart behavior
If the peer drops again during LLGR (before `llgr_expiry` fires), the original timer
must not be reset. This is handled by a single rule:

In `GracefulRestartTimerExpired`, use `entry().or_insert()` when scheduling expiry:
```rust
peer_info.llgr_expiry
    .entry(*afi_safi)
    .or_insert(Instant::now() + Duration::from_secs(*llst as u64));
```

Only sets expiry if not already running. `mark_peer_routes_llgr_stale()` is a no-op for
routes already tagged. `PeerDisconnected` does not touch `llgr_expiry`. Only
`PeerHandshakeComplete` (successful re-establishment) clears it.

### `core/src/peer/mod.rs` — `start_gr_restart_timer()`
Capture LLGR info from `self.capabilities.llgr` when spawning the GR timer:
```rust
let llgr_afi_safis: Vec<(AfiSafi, u32)> = self.capabilities.llgr
    .as_ref()
    .map(|cap| cap.entries.iter().map(|(as_, _, st)| (*as_, *st)).collect())
    .unwrap_or_default();

let timer = tokio::spawn(async move {
    tokio::time::sleep(...).await;
    let _ = server_tx.send(ServerOp::GracefulRestartTimerExpired {
        peer_ip,
        llgr_afi_safis,
    });
});
```

### `core/src/server_ops.rs` — `GracefulRestartTimerExpired`
Update variant:
```rust
GracefulRestartTimerExpired {
    peer_ip: IpAddr,
    llgr_afi_safis: Vec<(AfiSafi, u32)>,  // (afi_safi, llst_secs) from peer capability
}
```

Handler:
```rust
ServerOp::GracefulRestartTimerExpired { peer_ip, llgr_afi_safis } => {
    let stale_afi_safis = self.loc_rib.stale_afi_safis(peer_ip);
    let llgr_map: HashMap<AfiSafi, u32> = llgr_afi_safis.into_iter().collect();

    // Non-LLGR AFI/SAFIs: sweep immediately (existing behavior)
    let non_llgr: Vec<_> = stale_afi_safis.iter()
        .filter(|as_| !llgr_map.contains_key(as_))
        .copied().collect();
    let delta = self.loc_rib.remove_peer_routes_stale(peer_ip, &non_llgr);
    self.propagate_routes(delta, Some(peer_ip)).await;

    // LLGR AFI/SAFIs: tag with community, schedule expiry in PeerInfo
    let mut llgr_delta = RouteDelta::default();
    if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
        for (afi_safi, llst) in &llgr_map {
            let delta = self.loc_rib.mark_peer_routes_llgr_stale(peer_ip, *afi_safi);
            llgr_delta.merge(delta);
            peer_info.llgr_expiry.insert(*afi_safi,
                Instant::now() + Duration::from_secs(*llst as u64));
        }
    }
    self.propagate_routes(llgr_delta, Some(peer_ip)).await;
}
```

### `core/src/server_ops.rs` — `GracefulRestartComplete` (EOR received)
```rust
ServerOp::GracefulRestartComplete { peer_ip, afi_safi } => {
    // Cancel LLGR expiry (peer recovered before timer fired)
    if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
        peer_info.llgr_expiry.remove(&afi_safi);
    }
    let delta = self.loc_rib.remove_peer_routes_stale(peer_ip, &[afi_safi]);
    self.propagate_routes(delta, Some(peer_ip)).await;
}
```

### `core/src/server_ops.rs` — `PeerHandshakeComplete`
```rust
// Cancel all LLGR expiry on reconnect
if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
    peer_info.llgr_expiry.clear();
}
```

---

## Summary of File Changes

| File | Changes |
|------|---------|
| `core/src/bgp/msg_open_types.rs` | LlgrCapability struct, cap 71 encode/decode |
| `core/src/bgp/community.rs` | LLGR_STALE (0xFFFF0006) and NO_LLGR (0xFFFF0007) constants |
| `core/src/config.rs` | LlgrAfiSafiConfig, LlgrConfig, PeerConfig.llgr |
| `core/src/peer/mod.rs` | PeerCapabilities.llgr, capture LLGR info in GR timer |
| `core/src/peer/messages.rs` | Advertise + parse LLGR capability; F-bit=0 sweep on re-establishment |
| `core/src/peer/outgoing.rs` | Filter LLGR_STALE routes for non-LLGR peers; preserve community |
| `core/src/rib/path.rs` | LLGR_STALE deprioritization in best_path_cmp() |
| `core/src/rib/rib_loc.rs` | mark_peer_routes_llgr_stale() — skips NO_LLGR routes |
| `core/src/server.rs` | on_tick() arm in run(), check_llgr_expiry() |
| `core/src/server_ops.rs` | GR expiry splits LLGR/non-LLGR, GracefulRestartComplete cancels expiry |
| `core/src/server.rs` (`PeerInfo`) | llgr_expiry: HashMap<AfiSafi, Instant> |
| `proto/bgp.proto` | LlgrAfiSafiConfig, LlgrConfig messages |
| `core/src/grpc/service.rs` | proto_to_peer_config() LLGR mapping |
| `core/src/config.rs` (`Config`) | max_llgr_stale_time: Option<u32> server-level LLST cap |

## Verification
```
make test
```
Integration test: two servers with LLGR configured, peer drops, GR timer elapses, verify:
1. Routes tagged with LLGR_STALE community
2. Routes with NO_LLGR community swept immediately (not retained)
3. LLGR_STALE routes not advertised to third peer without LLGR
4. LLGR_STALE community preserved unchanged when advertised to LLGR-capable peer
5. LLGR timer elapses → routes withdrawn
6. Peer reconnects before LLGR timer → routes restored, community removed
7. Peer reconnects with F-bit=0 → stale routes swept immediately for that AFI/SAFI
8. Peer drops again during LLGR → original timer continues, not reset
