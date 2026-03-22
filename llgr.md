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

After setting all capabilities, enforce RFC 9494 Section 4.5:
```rust
// RFC 9494 Section 4.5: LLGR without GR MUST be ignored
if capabilities.graceful_restart.is_none() {
    capabilities.llgr = None;
}
```

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

In `core/tests/llgr.rs` (integration):
- `test_llgr_ignored_without_gr`: FakePeer sends OPEN with LLGR cap (code 71) but no GR cap
  (code 64) → server must ignore LLGR; after FakePeer drops, route is swept immediately (no
  LLGR_STALE tag, no LLGR timer). Use `poll_route_withdrawal()` to confirm route gone within
  GR sweep window, not retained.

---

## Phase 2: LLGR_STALE and NO_LLGR Communities

### `core/src/bgp/community.rs`
Add constants:
```rust
pub const LLGR_STALE: u32 = 0xFFFF0006;
pub const NO_LLGR: u32 = 0xFFFF0007;  // RFC 9494: do not retain this route during LLGR
```

### `core/src/rib/rib_loc.rs`
Add function `apply_llgr(peer_ip, afi_safi) -> RouteDelta`:
- Finds all paths from `peer_ip` where `stale = true` in the given AFI/SAFI table
- **Removes paths that have `NO_LLGR` community** immediately (not retained during LLGR)
- Adds `LLGR_STALE` community to remaining stale paths via `Arc::make_mut()`
- Recomputes best path per prefix (LLGR_STALE routes are now least-preferred per Phase 3)
- Returns a single RouteDelta covering both removed (NO_LLGR) and tagged (LLGR_STALE) prefixes

**NO_LLGR from import policy**: RFC 9494 Section 4.2 says routes must be removed if they carry
NO_LLGR "either as sent by the peer or as the result of a configured policy." Import policies in
bgpgg take `path: &mut Path` and run before `upsert_path()` — they can attach NO_LLGR to the
stored path. Since `apply_llgr()` checks the stored community on the path
regardless of source, policy-set NO_LLGR is covered transparently. No additional code is needed;
this is worth an explicit integration test (see `test_llgr_no_llgr_from_policy` below).

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

### `core/src/peer/outgoing.rs` — `PeerExportContext` and `should_filter_by_community()`

Add `llgr_capable: bool` to `PeerExportContext` (a simple bool is enough — we only need
to know whether the peer negotiated LLGR, not the full capability struct). This avoids
threading `&PeerCapabilities` through, which would require lifetime gymnastics.

**Call sites to update** (2 production, 5+ test):
- `core/src/server.rs:1054` — `propagate_routes()` loop. `conn.capabilities` has the
  LLGR info; set `llgr_capable: conn.capabilities.as_ref().and_then(|c| c.llgr.as_ref()).is_some()`
- `core/src/server_ops.rs:994` — `export_all_routes_to_peer()` in `handle_peer_established()`.
  Same pattern via `conn.capabilities`.
- Test helpers: `make_peer_export_ctx()` in `outgoing.rs:808` — add `llgr_capable: false`
  default. Inline test constructions at lines 1605, 1870, 1956, 1960 — add field.

Then either update
`should_filter_by_community()` to accept and check it, or perform the LLGR_STALE check at
the call site before invoking `should_filter_by_community()`.

Add LLGR_STALE filter:
```rust
// RFC 9494 Section 4.3: LLGR_STALE routes SHOULD NOT be advertised to a peer from which
// LLGR capability was not received. Filter the route entirely, not strip the community.
if attrs.communities.contains(&community::LLGR_STALE) && !peer_ctx.llgr_capable {
    return true;
}
```

This naturally causes:
- Non-LLGR peers: receive withdrawals when propagation runs after LLGR_STALE is tagged
- LLGR peers: receive re-advertisement with updated path (LLGR_STALE community present)

**LLGR_STALE must not be stripped**: the community passes through unchanged to LLGR-capable
peers. RFC 9494 Section 4.3: "MUST NOT be removed when the route is further advertised."
No stripping logic should be added to the export path for this community.

**Incoming LLGR_STALE routes from LLGR peers**: RFC 9494 Section 4.3 applies equally when we
*receive* a route that already carries LLGR_STALE (e.g., from a route reflector that tagged it
upstream). No extra code is needed — the existing filter (`peer_ctx.capabilities.llgr.is_none()`)
and `best_path_cmp()` operate on the stored community value regardless of who set it. The path
is deprioritized in selection and suppressed from non-LLGR peers automatically. Covered by
`test_llgr_stale_received_from_peer` below.

---

## Phase 5: LLGR Timer and GR Expiry Handling

### Where LLGR timer state lives

LLGR timer handles live in `PeerInfo`:

```rust
pub struct PeerInfo {
    ...
    pub llgr_timers: HashMap<AfiSafi, JoinHandle<()>>,
}
```

**Why not `Peer` task?** The timer fires a `ServerOp` which triggers RIB operations
(`remove_peer_routes_stale`, `propagate_routes`) — server-owned. The peer task has no
RIB access, so it would need to send a `ServerOp` anyway.

**Why not a top-level `BgpServer` field?** Per-peer state already lives in `PeerInfo`.
Cancellation on EoR is `peer_info.llgr_timers.remove(&afi_safi).map(|h| h.abort())`.

---

### Spawned tasks per AFI/SAFI (chosen)

One task per AFI/SAFI with `JoinHandle` for cancellation. Fires `ServerOp::LlgrTimerExpired`
on expiry. Clean lifecycle: spawn on GR expiry, abort on EoR.

```rust
// In GracefulRestartTimerExpired handler, for each LLGR AFI/SAFI:
let handle = tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(llst as u64)).await;
    let _ = server_tx.send(ServerOp::LlgrTimerExpired { peer_ip, afi_safi });
});
peer_info.llgr_timers.insert(afi_safi, handle);
```

Cancellation (EoR received for an AFI/SAFI):
```rust
peer_info.llgr_timers.remove(&afi_safi).map(|h| h.abort());
```

### `core/src/server_ops.rs` — `LlgrTimerExpired`
```rust
ServerOp::LlgrTimerExpired { peer_ip, afi_safi } => {
    info!(%peer_ip, %afi_safi, "LLGR stale timer expired");
    let delta = self.loc_rib.remove_peer_routes_stale(peer_ip, &[afi_safi]);
    self.propagate_routes(delta, Some(peer_ip)).await;
}
```

---

### F-bit on re-establishment (`core/src/server_ops.rs` — `handle_peer_established()`)

RFC 9494 Section 4.2: "once the LLGR Period begins, the Helper MUST immediately remove all
the stale routes from the peer that it is retaining for that address family if any of the
following occur: the F bit for a specific address family is not set in the newly received
LLGR Capability, or a specific address family is not included in the newly received LLGR
Capability, or the LLGR and accompanying GR Capability are not received in the re-established
session at all."

"Newly received" means the OPEN from the reconnecting peer. `handle_peer_established()`
already does the equivalent for GR stale routes (lines 565-578): it reads the new session's
capabilities and sweeps stale routes where F-bit=0. LLGR timer handling belongs in the same
function for the same reason — it's where the new capabilities are available.

After the existing GR stale-clear block, add:
```rust
// RFC 9494 Section 4.2: if LLGR period is active for this peer, check the new LLGR cap.
// Sweep and abort timer for any AFI/SAFI where: F-bit=0, not in new cap, or no LLGR+GR cap.
if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
    let llgr_cap = capabilities.as_ref().and_then(|c| c.llgr.as_ref());
    let to_sweep: Vec<AfiSafi> = peer_info.llgr_timers.keys().copied()
        .filter(|afi_safi| {
            match llgr_cap {
                None => true,  // no LLGR cap in new OPEN
                Some(cap) => cap.should_clear_stale(*afi_safi),  // F-bit=0 or absent
            }
        })
        .collect();
    for afi_safi in &to_sweep {
        peer_info.llgr_timers.remove(afi_safi).map(|h| h.abort());
    }
    if !to_sweep.is_empty() {
        let delta = self.loc_rib.remove_peer_routes_stale(peer_ip, &to_sweep);
        self.propagate_routes(delta, Some(peer_ip)).await;
    }
}
```

`LlgrCapability` needs a `should_clear_stale(afi_safi) -> bool` method mirroring
`GrCapability::should_clear_stale`: returns `true` if the AFI/SAFI is absent from entries
or if its F-bit is `false`.

### LLST local cap (`core/src/config.rs` and `core/src/server_ops.rs`)
Following FRR: received LLST from peer capability MAY be reduced by local config.
Add optional `max_llgr_stale_time: Option<u32>` to the server-level `Config` (not per-peer).
When scheduling expiry: `let llst = peer_llst.min(config.max_llgr_stale_time.unwrap_or(u32::MAX))`.
Add to `proto/bgp.proto` server config if needed.

### Consecutive restart behavior
RFC 9494: "The timer MUST NOT be updated until the peer has established and synchronized
a new session." If the peer drops again during LLGR (before `llgr_expiry` fires), the
original timer must not be reset. This is handled by a single rule:

In `GracefulRestartTimerExpired`, only spawn a timer if one is not already running:
```rust
peer_info.llgr_timers.entry(*afi_safi).or_insert_with(|| {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(llst as u64)).await;
        let _ = server_tx.send(ServerOp::LlgrTimerExpired { peer_ip, afi_safi });
    })
});
```

Only spawns if not already running. `apply_llgr()` is a no-op for
routes already tagged. `PeerDisconnected` does not touch `llgr_timers`. Only
`GracefulRestartComplete` (EoR received) aborts and removes the handle.

### "Session resets prior to becoming synchronized" (RFC 9494 Section 4.2)

RFC 9494: "If the timer expires during synchronization with the peer, any stale routes
that the peer has not refreshed are removed. If the session subsequently resets prior to
becoming synchronized, any remaining routes (for the AFI/SAFI whose LLST timer expired)
MUST be removed immediately."

"Remaining routes" = routes still tagged LLGR_STALE at the time of the second disconnect
(i.e. routes the peer never refreshed before the session dropped again). These are exactly
the routes `on_tick` would sweep when the logically-expired timer is processed — no special
handling in `PeerDisconnected` is needed. Within at most 1 second, `check_llgr_expiry()`
fires and removes them. The `or_insert` rule ensures the timer is not restarted, so the
sweep happens regardless of how many times the session drops.

### `core/src/peer/mod.rs` — `start_gr_restart_timer()`

**Gap**: the existing implementation returns early when `restart_time == 0`, which means
`GracefulRestartTimerExpired` never fires. Per RFC 9494 Section 4.2, if the GR Restart Time
is zero but LLST is nonzero, the LLGR phase still applies (GR phase duration is zero, LLGR
phase begins immediately). Fix: when restart_time=0 but there are LLGR entries with nonzero
LLST, send `GracefulRestartTimerExpired` immediately with a 0-second sleep (or skip the timer
and send directly):

```rust
if restart_time == 0 {
    if !llgr_afi_safis.is_empty() {
        let _ = server_tx.send(ServerOp::GracefulRestartTimerExpired {
            peer_ip,
            llgr_afi_safis,
        });
    }
    return;
}
```

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
    // RFC 9494 Section 4.2: LLST=0 means no LLGR phase for that AFI/SAFI.
    // Those fall through to the immediate non-LLGR sweep path below.
    let llgr_map: HashMap<AfiSafi, u32> = llgr_afi_safis.into_iter()
        .filter(|(_, llst)| *llst > 0)
        .collect();

    // Non-LLGR AFI/SAFIs: sweep immediately (existing behavior)
    let non_llgr: Vec<_> = stale_afi_safis.iter()
        .filter(|as_| !llgr_map.contains_key(as_))
        .copied().collect();
    let delta = self.loc_rib.remove_peer_routes_stale(peer_ip, &non_llgr);
    self.propagate_routes(delta, Some(peer_ip)).await;

    // LLGR AFI/SAFIs: tag with community, schedule expiry in PeerInfo
    let llgr_afi_safis: Vec<AfiSafi> = llgr_map.keys().copied().collect();
    let llgr_delta = self.loc_rib.apply_llgr(peer_ip, &llgr_afi_safis);

    if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
        for (afi_safi, llst) in &llgr_map {
            let llst = *llst;
            let afi_safi = *afi_safi;
            peer_info.llgr_timers.entry(afi_safi).or_insert_with(|| {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(llst as u64)).await;
                    let _ = server_tx.send(ServerOp::LlgrTimerExpired { peer_ip, afi_safi });
                })
            });
        }
    }
    self.propagate_routes(llgr_delta, Some(peer_ip)).await;
}
```

### `core/src/server_ops.rs` — `GracefulRestartComplete` (EOR received)
```rust
ServerOp::GracefulRestartComplete { peer_ip, afi_safi } => {
    // EoR received = session synchronized. Cancel LLGR timer and sweep remaining stale routes.
    // If LLST already fired before EoR, abort() is a no-op and remove_peer_routes_stale() finds nothing.
    if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
        peer_info.llgr_timers.remove(&afi_safi).map(|h| h.abort());
    }
    let delta = self.loc_rib.remove_peer_routes_stale(peer_ip, &[afi_safi]);
    self.propagate_routes(delta, Some(peer_ip)).await;
}
```

### Selection_Deferral_Timer

RFC 9494 Section 4.2 defines two alternative synchronization signals for the Helper:

> "The session is termed 'synchronized' for a given AFI/SAFI once the EoR for that AFI/SAFI
> has been received from the peer **or** once the Selection_Deferral_Timer discussed in
> [RFC4724] expires."

**Not applicable to bgpgg.** The Selection_Deferral_Timer is defined in RFC 4724 Section 4.1
as a Restarting Speaker obligation. bgpgg never acts as a Restarting Speaker — the R bit is
hardcoded to `false` in `messages.rs`. bgpgg is a Helper only. No implementation needed.

### LLGR timer cleanup on peer removal (`core/src/server_ops.rs` — `handle_remove_peer()`)

When a peer is removed, `self.peers.remove(&peer_ip)` drops `PeerInfo`. Dropping a
`JoinHandle` **detaches** the task (does not abort it). The orphaned LLGR timer would
fire `LlgrTimerExpired` for a non-existent peer. Abort all LLGR timers before removing:

```rust
// Abort any running LLGR timers before removing the peer
if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
    for (_, handle) in peer_info.llgr_timers.drain() {
        handle.abort();
    }
}
```

Insert this block just before `self.peers.remove(&peer_ip)` at line 721.

---

### Timer lifecycle across reconnect

RFC 9494: "The timer continues to run once the session has re-established. The timer is
neither stopped nor updated until the EoR marker is received."

The LLST timer keeps running across reconnect **unless** the F-bit/cap check in
`handle_peer_established()` above triggers a sweep (which also aborts the timer). For
AFI/SAFIs that pass that check (F-bit=1, still in new LLGR cap), the timer runs undisturbed.
Cancellation for the normal case (session recovered) happens only in `GracefulRestartComplete`
(EoR received).

---

## Summary of File Changes

| File | Changes |
|------|---------|
| `core/src/bgp/msg_open_types.rs` | LlgrCapability struct, cap 71 encode/decode, should_clear_stale() |
| `core/src/bgp/community.rs` | LLGR_STALE (0xFFFF0006) and NO_LLGR (0xFFFF0007) constants |
| `core/src/config.rs` | LlgrAfiSafiConfig, LlgrConfig, PeerConfig.llgr |
| `core/src/peer/mod.rs` | PeerCapabilities.llgr, capture LLGR info in GR timer; handle restart_time=0 with nonzero LLST |
| `core/src/peer/messages.rs` | Advertise + parse LLGR capability |
| `core/src/peer/outgoing.rs` | Add `llgr_capable: bool` to `PeerExportContext`; filter LLGR_STALE routes for non-LLGR peers; preserve community |
| `core/src/rib/path.rs` | LLGR_STALE deprioritization in best_path_cmp() |
| `core/src/rib/rib_loc.rs` | `StaleStrategy` enum (Sweep/TransitionToLlgr), `handle_stale_routes()`, `apply_llgr(&[AfiSafi])` |
| `core/src/server_ops.rs` | GR expiry splits LLGR/non-LLGR, `LlgrTimerExpired` handler, GracefulRestartComplete aborts timers, handle_peer_established() sweeps on F-bit=0/cap-absent, handle_remove_peer() aborts LLGR timers |
| `core/src/server.rs` (`PeerInfo`) | `llgr_timers: HashMap<AfiSafi, JoinHandle<()>>` |
| `proto/bgp.proto` | LlgrAfiSafiConfig, LlgrConfig messages |
| `core/src/grpc/service.rs` | proto_to_peer_config() LLGR mapping |
| `core/src/config.rs` (`Config`) | max_llgr_stale_time: Option<u32> server-level LLST cap |

## Verification
```
make test
```

Integration tests live in `core/tests/llgr.rs`. All use `FakePeer` for precise control
over capability negotiation, UPDATE content, and TCP disconnect timing. No `sleep()` —
use `poll_until()` / `poll_route_withdrawal()`.

### New FakePeer helper (`core/tests/utils/common.rs`)

`send_open_with_llgr(asn, router_id, hold_time, gr_time, llst_secs)` — sends OPEN with
GR capability (code 64) + LLGR capability (code 71) for IPv4 unicast. Add alongside
`send_open_with_gr`.

### Tests

**`test_llgr_zero_stale_time`** — covers: LLST=0 AFI/SAFI swept immediately at GR expiry, not LLGR phase
- FakePeer sends OPEN with GR (restart_time=1s) + LLGR cap with stale_time=0 for IPv4 unicast
- FakePeer announces a prefix, then drops TCP
- After GR timer fires, verify route is withdrawn (not tagged with LLGR_STALE)
- Confirm no LLGR timer running (route gone, not retained)

**`test_llgr_stale_community`** — covers: LLGR_STALE tagged, NO_LLGR swept
- FakePeer (GR=1s, LLST=10s) announces prefix A (clean) and prefix B (NO_LLGR community)
- FakePeer drops TCP
- Poll until prefix A has LLGR_STALE community (`0xFFFF0006`)
- Verify prefix B is gone (swept immediately)

**`test_llgr_not_propagated_to_non_llgr_peer`** — covers: propagation filtering
- S1 (GR + LLGR), S2 (GR only) peered together
- FakePeer connects to S1, announces a route
- Verify S2 receives the route initially
- FakePeer drops TCP → LLGR phase on S1
- Verify S1 has route with LLGR_STALE, S2 no longer has the route

**`test_llgr_timer_expiry`** — covers: LLST sweeps routes
- FakePeer (GR=1s, LLST=2s) announces route, drops TCP
- Verify route tagged LLGR_STALE after GR expires
- Verify route gone after LLST expires (`poll_route_withdrawal`)

**`test_llgr_peer_recovery`** — covers: EoR cancels timer, community removed
- FakePeer (GR=1s, LLST=30s) announces route, drops TCP → LLGR phase
- FakePeer reconnects with `send_open_with_llgr`, re-announces route, sends EoR
- Verify route present with no LLGR_STALE community

**`test_llgr_sweep_on_reconnect`** — covers: RFC 9494 Section 4.2 immediate sweep on reconnect
Three table-driven cases, all share the same setup: FakePeer (GR=1s, LLST=30s) announces
route, drops TCP → LLGR phase active, route tagged LLGR_STALE. Then FakePeer reconnects
with a different OPEN:

| case | reconnect OPEN | expected |
|------|---------------|----------|
| `f_bit_zero` | LLGR cap present, F-bit=0 for IPv4 unicast | route swept immediately |
| `afi_safi_absent` | LLGR cap present but IPv4 unicast not listed | route swept immediately |
| `no_llgr_cap` | no GR or LLGR capability | route swept immediately |

For each case: `poll_route_withdrawal()` confirms route gone promptly (not after 30s LLST).
The 30s LLST makes the distinction obvious — if the timer was not aborted, the route would
linger.

**`test_llgr_stale_received_from_peer`** — covers: RFC 9494 Section 4.3 incoming LLGR_STALE
Two LLGR-capable servers S1 and S2, plus a non-LLGR server S3, all peered:
- FakePeer connects to S1 with `send_open_with_llgr`
- FakePeer sends a route that already carries LLGR_STALE community (`0xFFFF0006`) in its attrs
- Verify S1 stores the route with LLGR_STALE (not stripped)
- Verify S2 (LLGR-capable) receives the route with LLGR_STALE community intact
- Verify S3 (non-LLGR) does NOT receive the route (`poll_route_withdrawal` or route never arrives)
- Verify the route is deprioritized: add a competing route without LLGR_STALE from another peer
  and confirm the clean route is selected as best

**`test_llgr_no_llgr_from_policy`** — covers: RFC 9494 Section 4.2 NO_LLGR via import policy
- Configure an import policy on S1 that adds NO_LLGR community (`0xFFFF0007`) to all routes
  from FakePeer's address
- FakePeer connects with `send_open_with_llgr` (GR=1s, LLST=30s), announces a route *without*
  NO_LLGR in its attrs
- Verify the route is accepted (policy adds NO_LLGR but doesn't reject it)
- FakePeer drops TCP → LLGR phase begins on S1
- Verify the route is removed immediately (the stored path carries NO_LLGR from the import
  policy; `apply_llgr` sweeps it), NOT retained for 30s
- Use `poll_route_withdrawal()` to confirm prompt removal

**`test_llgr_consecutive_restart`** — covers: RFC 9494 Section 4.2 timer MUST NOT be reset
- FakePeer (GR=1s, LLST=4s) announces route, drops TCP → LLGR phase starts
- Wait ~2s (half of LLST), then FakePeer drops TCP again (second disconnect during LLGR)
- The LLGR timer MUST NOT be restarted — original 4s deadline still applies
- `poll_route_withdrawal()` confirms route is swept at ~4s from initial LLGR start, not at
  ~6s (which would indicate the timer was reset on the second disconnect)
- Use a 30s LLST to make the distinction unambiguous if preferred (route gone at ~30s not ~32s)
