# Refactoring Plan — Efficiency + Resiliency

## P0 — Crash Prevention (Resiliency)

1. **`expect()` in production hot path**
   - `rib_out.rs:39` — `AdjRibOut::insert()` calls `.expect("loc-rib path must have ID")`
   - Runs on every route propagation. One missing path ID crashes the daemon.
   - Fix: Convert to `Result`, propagate error up.

2. **`expect()` in daemon startup**
   - `daemon/src/main.rs:62` — panics on invalid router-id CLI input.
   - Fix: Validate and return proper error.

## P1 — Memory Safety Under Load (Resiliency + Efficiency)

3. **Unbounded channels everywhere**
   - `server.rs:646` (ServerOp), `server.rs:832` (PeerOp), `bmp/task.rs:40`, `grpc/service.rs:643,1010`
   - Risk: A peer sending 100k routes during server stall = unbounded memory growth.
   - Fix: Bounded channels with backpressure. `.send().await` blocks sender until space is available — no message loss. Start with ServerOp (4096) and PeerOp (1024), tune from there.

4. **gRPC stream backpressure**
   - `grpc/service.rs:643,1010` — unbounded channels for route streaming.
   - Risk: Slow/dead gRPC client leaks memory indefinitely.
   - Fix: Bounded channel + drop policy for streaming responses.

## P2 — Hot Path Allocation (Efficiency)

5. **Path cloning in `batch_announcements_by_path`**
   - `outgoing.rs:361,364` — clones `as_path()` and `communities()` per prefix per peer.
   - Impact: 100k routes x 50 peers = millions of heap allocations.
   - Fix: Make `AnnouncementBatch` borrow `&Arc<Path>` instead of cloning attribute vecs. Group by Arc pointer identity or cheap attribute hash. Only clone when serializing to wire (once per batch, not once per prefix).

6. **HashSet allocation in `stale_paths()`**
   - `rib_out.rs:76-95` — allocates `HashSet<u32>` per changed prefix.
   - Fix: Linear scan instead. Typical path count is 1-10, so O(n*m) beats HashSet alloc overhead.

7. **`propagate_routes()` per-peer context allocation**
   - `server.rs:1086-1135` — clones policies, capabilities, AFI sets for every peer on every update cycle.
   - Fix: Cache `PeerExportContext` per peer, rebuild only on config/capability change.

## P3 — Observability (Resiliency)

8. **Silent channel send failures**
   - ~10 locations in `server.rs` use `let _ = peer_tx.send(...)`.
   - Risk: When a peer task exits, route updates vanish silently.
   - Fix: Add `warn!` logging with peer context on send failure.

9. **Task supervision**
   - `server.rs:854` — spawns peer tasks with no tracking.
   - Risk: If `peer.run()` panics, it's gone forever with no alert.
   - Fix: Track `JoinHandle`s, log unexpected exits, consider restart.

## P4 — Architectural Efficiency

10. **Route propagation not cancellable**
    - `propagate_routes()` iterates all peers synchronously, blocking the server select loop.
    - Risk: With 500 peers and large update, blocks new connections and other ops.
    - Fix: Yield periodically or split into async chunks.

11. **ADD-PATH path iteration for non-ADD-PATH RS clients**
    - `outgoing.rs:627-660` — iterates all paths even for RS clients that only need the first match.
    - Fix: Early-exit for non-ADD-PATH peers after first accepted path.

12. **gRPC `route_to_proto()` string allocations**
    - `grpc/service.rs:92-149` — clones AS lists, communities, cluster lists; `.to_string()` on every IP.
    - Fix: Zero-copy or cache string representations where possible.

## P5 — Code Hygiene

13. **Sentinel timeout in idle state**
    - `state_idle.rs:38-41` — uses `Duration::from_secs(86400 * 365)` as "never".
    - Fix: Use `Option<Instant>` + `std::future::pending()`.

14. **`Box::leak()` in test helper**
    - `outgoing.rs:820-833` — leaks memory in tests.
    - Fix: Refactor test to avoid `'static` requirement.
