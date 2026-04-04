# BGP-LS Implementation Plan (RFC 9552)

## Overview

BGP-LS distributes link-state topology information via BGP using AFI 16388 / SAFI 71.
NLRIs carry topology keys (node/link/prefix identifiers), and the BGP-LS Attribute
(path attribute type 29) carries properties (name, metric, bandwidth, custom TLVs).

bgpgg targets: dumb pipe (propagator/reflector) first, then gRPC injection (producer)
and gRPC query (consumer feed). No IGP integration.

## Phase 1: AFI/SAFI and Capability Negotiation -- DONE

Add LinkState AFI/SAFI to the existing multiprotocol machinery.

### Changes made

- `core/src/bgp/multiprotocol.rs`
  - Added `Afi::LinkState = 16388`, `Safi::LinkState = 71`
  - Updated `TryFrom`, `Display`, serde impls

- `core/src/config.rs`
  - Added `afi_safis: Vec<AfiSafi>` (default empty) to PeerConfig
  - Generic: works for BGP-LS, flowspec, EVPN, etc.

- `proto/bgp.proto`
  - Added `repeated AfiSafi afi_safis = 23` to SessionConfig (reuses existing AfiSafi message)

- `core/src/grpc/service.rs`
  - Added `proto_to_afi_safis()` converter, updated proto_to_peer_config / peer_config_to_proto

- `core/src/peer/messages.rs`
  - `build_optional_params()` appends config.afi_safis to default list
  - `process_received_open()` includes config.afi_safis in local set for negotiation

- `core/src/peer/mod.rs`
  - No changes needed: `PeerCapabilities.multiprotocol` is `HashSet<AfiSafi>`, already generic

- `core/src/bgp/msg.rs`
  - `AddPathMask` -- wildcard for new AFI/SAFI combos (LS bit added in Phase 5)

- `core/src/bgp/msg_update_codec.rs`
  - Extracted `parse_mp_next_hop()` / `parse_ipv4_next_hop()` / `parse_ipv6_next_hop()`
  - LS next hop uses IPv4 or IPv6 based on length (RFC 9552 Section 5.5)
  - LS NLRI parsing returns empty vec (Phase 2 placeholder)
  - Updated `validate_mp_reach_buffer()` to accept LS next hop lengths

- `core/src/rib/rib_loc.rs`, `core/src/rib/rib_out.rs`
  - Stub arms for `Afi::LinkState` with TODO(bgpls) comments

### Design note: per-family config

All major implementations (FRR, Juniper, BIRD, GoBGP) use per-AFI/SAFI config blocks where
policy, prefix-limits, add-path, and next-hop-self are configured per family. Phase 1 adds
the family list only. Per-family sub-config will be added later by extending AfiSafiConfig
with optional override fields (max_prefix, add_path_send, import_policy, etc.) that fall
back to the top-level PeerConfig defaults when absent.

### Tests

- `test_extract_capabilities_afi_safis` -- LS in/out of afi_safis, capability negotiation
- `test_afi_safi_from_capability_bytes` -- BGP-LS bytes 0x4004/0x47 round-trip
- `test_afi_try_from`, `test_safi_try_from` -- 16388 and 71 accepted
- `test_default_afi_safis` -- defaults are IPv4/IPv6 unicast only

---

## Phase 2: BGP-LS NLRI Codec

Parse and encode BGP-LS NLRIs from/to MP_REACH_NLRI and MP_UNREACH_NLRI.

### New types

Create flat files under `core/src/bgp/`:

- `bgpls_nlri.rs` -- NLRI types, parsing, encoding
- `bgpls_attribute.rs` -- BGP-LS Attribute (type 29) parsing/encoding
- `bgpls_tlv.rs` -- TLV constants and helpers

**Why flat files, not a `bgpls/` module directory?** Matches the existing codebase pattern
(`msg_update.rs`, `msg_update_codec.rs`, `msg_update_types.rs`). The `bgpls_` prefix groups
them visually. A nested module would add `mod.rs` boilerplate and re-exports for no benefit
with just 3 files. Consistency with the codebase wins.

**Why not `core/src/bgpls/` (top-level module)?** The codec is BGP wire format — it belongs
in `src/bgp/`. RIB changes go in `src/rib/`, gRPC in `src/grpc/`, etc. A top-level module
would either duplicate concerns or create cross-module dependencies.

```
// NLRI types
enum LsNlriType { Node = 1, Link = 2, PrefixV4 = 3, PrefixV6 = 4 }

// Protocol IDs
enum LsProtocolId { IsIsL1 = 1, IsIsL2 = 2, OspfV2 = 3, Direct = 4, Static = 5, OspfV3 = 6 }

// Top-level NLRI -- the RIB key
struct LsNlri {
    nlri_type: LsNlriType,
    protocol_id: LsProtocolId,
    identifier: u64,               // 8-byte BGP-LS Instance-ID
    raw: Vec<u8>,                   // canonical bytes for RIB keying and opaque propagation
}

// TLV envelope -- used everywhere
struct LsTlv {
    tlv_type: u16,
    value: Vec<u8>,
}

// Node Descriptor (container TLV 256/257)
struct NodeDescriptor {
    as_number: Option<u32>,         // sub-TLV 512
    bgp_ls_id: Option<u32>,        // sub-TLV 513 (deprecated, parse only)
    ospf_area_id: Option<u32>,     // sub-TLV 514
    igp_router_id: Option<Vec<u8>>,// sub-TLV 515 (variable length)
    unknown: Vec<LsTlv>,           // preserve unknown sub-TLVs
}

// Parsed NLRI variants (for gRPC query -- not needed for propagation)
enum LsNlriData {
    Node { local_node: NodeDescriptor },
    Link {
        local_node: NodeDescriptor,
        remote_node: NodeDescriptor,
        link_descriptors: Vec<LsTlv>,
    },
    PrefixV4 {
        local_node: NodeDescriptor,
        prefix_descriptors: Vec<LsTlv>,
    },
    PrefixV6 {
        local_node: NodeDescriptor,
        prefix_descriptors: Vec<LsTlv>,
    },
}
```

### Parsing

- Parse from MP_REACH_NLRI / MP_UNREACH_NLRI when AFI=16388, SAFI=71
- Read: NLRI Type (2 bytes) + Total NLRI Length (2 bytes) + body
- Body: Protocol-ID (1 byte) + Identifier (8 bytes) + descriptor TLVs
- Store raw canonical bytes for RIB keying
- Validate TLV ordering in NLRI (MUST be ascending by type -- malformed if not)
- Unknown NLRI types: treat as opaque, preserve raw bytes
- Unknown TLVs within known NLRI types: preserve in raw bytes

### Encoding

- Serialize LsNlri back to bytes for MP_REACH_NLRI / MP_UNREACH_NLRI
- For propagation: just use stored raw bytes (opaque forwarding)
- For gRPC injection: build from structured data, enforce TLV ordering

### Error handling (RFC 9552 Section 8.2)

- Malformed NLRI (TLV ordering violation, recoverable): NLRI discard
- Malformed NLRI (length errors, unrecoverable): AFI/SAFI disable or session reset
- Unknown NLRI types: preserve and propagate (override RFC 7606 default)
- Semantic errors (wrong TLV for NLRI type, missing mandatory TLV): NOT malformed

### Files to change

- `core/src/bgp/bgp_ls.rs` (NEW) -- all LS types, parsing, encoding
- `core/src/bgp/msg_update_codec.rs` -- dispatch to LS parser when AFI=16388
- `core/src/bgp/msg_update.rs` -- encode LS NLRIs into MP_REACH/MP_UNREACH
- `core/src/bgp/msg_update_types.rs` -- add BGP-LS attribute type constant (29)

### Tests

- Parse each NLRI type (Node, Link, PrefixV4, PrefixV6)
- Round-trip: parse -> encode -> parse, verify identical
- Unknown NLRI type preserved as opaque
- Unknown TLVs within known NLRI preserved
- TLV ordering violation detected as malformed
- Length errors detected

---

## Phase 3: BGP-LS Attribute (Type 29) Codec

Parse and encode the BGP-LS path attribute that carries node/link/prefix properties.

### Types

```
// BGP-LS Attribute -- optional transitive, type 29
struct LsAttribute {
    raw: Vec<u8>,              // for opaque propagation
    tlvs: Vec<LsTlv>,         // parsed TLV envelope (type + raw value)
}
```

### Parsing

- Optional transitive attribute (flags: 0xC0)
- Parse as sequence of TLVs (type 2 bytes, length 2 bytes, value variable)
- TLV ordering SHOULD be ascending but unordered is NOT malformed
- Unknown TLVs: preserve and propagate
- No semantic validation on propagator path

### Error handling

- Recoverable (TLV length error but overall attribute length correct): Attribute Discard
- Unrecoverable (attribute length inconsistent): AFI/SAFI disable or session reset
- If UPDATE exceeds 4096 bytes due to other attrs: discard BGP-LS attribute first

### Well-known TLV types to parse (for gRPC query)

Node Attribute TLVs:
- 1024: Node Flag Bits (1 byte)
- 1025: Opaque Node Attribute (variable)
- 1026: Node Name (variable, max 255)
- 1027: IS-IS Area Identifier (variable)
- 1028: IPv4 Router-ID of Local Node (4 bytes)
- 1029: IPv6 Router-ID of Local Node (16 bytes)

Link Attribute TLVs:
- 1028/1029: Local Node Router-IDs (same as above)
- 1030: IPv4 Router-ID of Remote Node (4 bytes)
- 1031: IPv6 Router-ID of Remote Node (16 bytes)
- 1088: Administrative group (4 bytes)
- 1089: Max link bandwidth (4 bytes, IEEE float)
- 1090: Max reservable link bandwidth (4 bytes, IEEE float)
- 1091: Unreserved bandwidth (32 bytes, 8x IEEE float)
- 1092: TE Default Metric (4 bytes)
- 1093: Link Protection Type (2 bytes)
- 1094: MPLS Protocol Mask (1 byte)
- 1095: IGP Metric (variable, 1-3 bytes)
- 1096: Shared Risk Link Group (4*n bytes)
- 1097: Opaque Link Attribute (variable)
- 1098: Link Name (variable, max 255)

Prefix Attribute TLVs:
- 1152: IGP Flags (1 byte)
- 1153: IGP Route Tag (4*n bytes)
- 1154: IGP Extended Route Tag (8*n bytes)
- 1155: Prefix Metric (4 bytes)
- 1156: OSPF Forwarding Address (4 or 16 bytes)
- 1157: Opaque Prefix Attribute (variable)

Private use: 65000-65535 (first 4 bytes of value = Enterprise Code)

### Files to change

- `core/src/bgp/bgp_ls.rs` -- LsAttribute parsing/encoding, TLV definitions
- `core/src/bgp/msg_update_codec.rs` -- parse attr type 29 into LsAttribute
- `core/src/bgp/msg_update_types.rs` -- add `LS = 29` to attr_type_code constants
- `core/src/bgp/msg_update_types.rs` -- RFC 7606 action for type 29: Attribute Discard

### Tests

- Parse BGP-LS attribute with known TLVs
- Parse BGP-LS attribute with unknown TLVs (preserved)
- Round-trip encoding
- Attribute with no TLVs (length 0)
- Private-use TLV with Enterprise Code

---

## Phase 4: RIB Storage

Store BGP-LS routes in the Loc-RIB alongside IPv4/IPv6 unicast routes.

### Design

**Extensibility consideration:** Later we'll add more AFI/SAFIs (flowspec, VRF, EVPN, etc.).
The RIB design must accommodate new families without major refactoring.

**Approach: explicit per-family fields with typed keys.** Each AFI/SAFI gets its own field
in LocRib with a proper typed key — not opaque bytes.

Why not a generic `HashMap<AfiSafi, Box<dyn RibTable>>`? GoBGP (Go map), FRR (2D array),
and BIRD (generic rtable) all use heterogeneous table containers. This works in Go/C because
`interface{}`/`void*` gives you dynamic dispatch cheaply. In Rust, a `RibTable` trait with a
generic key type `K` can't be stored in one map — `RibTable<Ipv4Net>` and `RibTable<LsNlriKey>`
are different types. You'd need type erasure (`Box<dyn Any>` keys), losing compile-time safety
and reimplementing dynamic typing. Not worth it.

Explicit fields: each family is statically typed, compiler catches key mismatches. Adding a
new family = add a field + methods. The number of families is small and known.

```
pub struct LocRib<A: PathIdAllocator = BitmapPathIdAllocator> {
    ipv4_unicast: PrefixMap<Ipv4Net, Route>,
    ipv6_unicast: PrefixMap<Ipv6Net, Route>,
    link_state: HashMap<LsNlriKey, Route>,  // NEW: typed key, not opaque bytes
    path_ids: A,
}
```

BGP-LS RIB key is a proper typed struct:

```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LsNlriKey {
    nlri_type: LsNlriType,
    protocol_id: LsProtocolId,
    identifier: u64,
    local_node: NodeDescriptor,
    remote_node: Option<NodeDescriptor>,   // link only
    link_descriptors: Vec<LsTlv>,          // link only
    prefix_descriptors: Vec<LsTlv>,        // prefix only
}
```

Queryable, debuggable, no opaque blobs in the RIB. Raw bytes stored separately on LsNlri
for wire encoding on propagation.

### Best path selection

Standard BGP decision process applies to BGP-LS routes (LOCAL_PREF, AS_PATH length,
ORIGIN, MED, eBGP > iBGP, router-id tiebreak). The IGP metric to next-hop step
is skipped (no forwarding). Existing `Path.best_path_cmp()` works as-is.

### Route delta tracking

Unify the key type so `best_changed` and `changed` cover all AFI/SAFIs. This is not a
generic/trait-object approach — it's a simple sum type (enum). Adding a new family later
is adding a variant; the compiler flags every match that needs updating.

```
enum RouteKey {
    Prefix(IpNetwork),
    LinkState(LsNlriKey),
    // future: Flowspec(...), Evpn(...)
}

pub struct RouteDelta {
    pub best_changed: Vec<RouteKey>,
    pub changed: Vec<RouteKey>,
}
```

Propagation matches on `RouteKey` to decide which LocRib table to look up and how to
encode the UPDATE. This match is needed regardless — the AFI/SAFI determines wire encoding.




### Files to change

- `core/src/rib/rib_loc.rs` -- add `link_state` HashMap, upsert/remove for LS routes
- `core/src/rib/rib_loc.rs` -- RouteDelta extension
- `core/src/rib/path.rs` -- add `ls_attr: Option<LsAttribute>` to PathAttrs (or Path)
- `core/src/rib/rib_in.rs` -- AdjRibIn: add LS table if needed
- `core/src/rib/types.rs` -- Route might need LsNlri field

### Tests

- Insert LS route, verify stored and retrievable
- Best path selection between two LS paths
- Withdraw LS route
- Replace LS route (same NLRI, new attribute)
- Explicit withdraw + re-announce (NLRI TLV change)

---

## Phase 5: UPDATE Processing and Propagation

Wire up the codec and RIB so bgpgg can receive, store, and propagate BGP-LS routes.

### Receiving

- `core/src/peer/` -- when UPDATE contains MP_REACH_NLRI with AFI 16388:
  - Parse LS NLRIs using Phase 2 codec
  - Parse BGP-LS Attribute (type 29) using Phase 3 codec
  - Create Path with LS data
  - Send to server via existing PeerOp channel

- `core/src/server/` -- handle incoming LS routes:
  - Apply import policy (if any)
  - Insert into LocRib.link_state
  - Compute RouteDelta with ls_best_changed / ls_changed

### Propagating

- `core/src/server/propagate.rs` -- extend `propagate_routes()`:
  - For each peer with BGP-LS enabled:
    - Filter LS routes through export policy
    - Apply RR rules (same as IPv4: iBGP split horizon, cluster-list, originator-id)
    - Build UPDATE with MP_REACH_NLRI containing LS NLRIs + BGP-LS attribute

- `core/src/peer/outgoing.rs` -- extend message building:
  - Batch LS announcements by shared attributes (same as IPv4)
  - Encode LS NLRIs into MP_REACH_NLRI
  - Encode withdrawals into MP_UNREACH_NLRI
  - Use raw NLRI bytes for propagation (opaque forwarding)

### Adj-RIB-Out

- Rekey from `IpNetwork` to `RouteKey` so LS routes live alongside IP routes
- Per-peer adj_rib_out needs LS tracking for ADD-PATH support
- Key: RouteKey + path_id
- Same pattern as existing adj_rib_out for IP prefixes

### ADD-PATH for BGP-LS

Add `(Afi::LinkState, Safi::LinkState) => 1 << 6` to `AddPathMask::from_afi_safi()`.
The bitmask approach is fine — adding a bit per family is trivial and keeps `MessageFormat`
`Copy` for the hot path.

### Files to change

- `core/src/bgp/msg.rs` -- add LS bit to AddPathMask
- `core/src/peer/established.rs` (or equivalent) -- handle LS in UPDATE processing
- `core/src/server/propagate.rs` -- propagate LS routes
- `core/src/server/ops.rs` -- server operations for LS route changes
- `core/src/peer/outgoing.rs` -- build LS UPDATE messages

### Tests

- Receive LS UPDATE from peer, verify stored in RIB
- Propagate LS route to another peer
- RR reflection: LS route from client reflected to other clients
- iBGP split horizon: LS route from non-client not sent to non-client
- Withdraw propagation
- Multiple LS NLRIs in single UPDATE

---

## Phase 6: gRPC API

Expose BGP-LS routes via gRPC for injection (producer) and query (consumer feed).

### Proto changes (`proto/bgp.proto`)

```protobuf
// New RPCs
rpc AddLsRoute(AddLsRouteRequest) returns (AddLsRouteResponse);
rpc RemoveLsRoute(RemoveLsRouteRequest) returns (RemoveLsRouteResponse);
rpc ListLsRoutes(ListLsRoutesRequest) returns (ListLsRoutesResponse);
rpc ListLsRoutesStream(ListLsRoutesRequest) returns (stream LsRoute);

// LS NLRI types
enum LsNlriType {
    LS_NODE = 0;
    LS_LINK = 1;
    LS_PREFIX_V4 = 2;
    LS_PREFIX_V6 = 3;
}

enum LsProtocolId {
    LS_ISIS_L1 = 0;
    LS_ISIS_L2 = 1;
    LS_OSPFV2 = 2;
    LS_DIRECT = 3;
    LS_STATIC = 4;
    LS_OSPFV3 = 5;
}

message LsNodeDescriptor {
    optional uint32 as_number = 1;
    optional uint32 bgp_ls_id = 2;
    optional uint32 ospf_area_id = 3;
    bytes igp_router_id = 4;
}

message LsTlv {
    uint32 type = 1;
    bytes value = 2;
}

message LsNlri {
    LsNlriType nlri_type = 1;
    LsProtocolId protocol_id = 2;
    uint64 identifier = 3;
    LsNodeDescriptor local_node = 4;
    optional LsNodeDescriptor remote_node = 5;       // link only
    repeated LsTlv link_descriptors = 6;              // link only
    repeated LsTlv prefix_descriptors = 7;            // prefix only
}

message LsAttribute {
    repeated LsTlv tlvs = 1;
    // Convenience fields for well-known TLVs (populated from tlvs)
    optional string node_name = 10;
    optional uint32 igp_metric = 11;
    optional float max_link_bandwidth = 12;
    optional string link_name = 13;
    // ... more as needed
}

message AddLsRouteRequest {
    LsNlri nlri = 1;
    LsAttribute attribute = 2;
}

message AddLsRouteResponse {
    bool success = 1;
    string message = 2;
}

message RemoveLsRouteRequest {
    LsNlri nlri = 1;
}

message ListLsRoutesRequest {
    optional RibType rib_type = 1;
    optional string peer_address = 2;
    optional LsNlriType nlri_type = 3;  // filter by type
}

message LsRoute {
    LsNlri nlri = 1;
    LsAttribute attribute = 2;
    // Standard BGP path info
    repeated uint32 as_path = 3;
    string next_hop = 4;
    string peer_address = 5;
    uint32 local_pref = 6;
    bool best = 7;
}
```

### Implementation

- `core/src/grpc/service.rs` -- implement new RPCs
  - AddLsRoute: convert proto -> LsNlri + LsAttribute, inject into RIB as local route
  - RemoveLsRoute: withdraw by NLRI key
  - ListLsRoutes: iterate LocRib.link_state, convert to proto
  - ListLsRoutesStream: streaming version

### Tests

- Inject LS route via gRPC, verify in RIB
- Inject LS route via gRPC, verify propagated to peer
- Query LS routes via gRPC
- Withdraw LS route via gRPC
- Filter by NLRI type in query

---

## Phase 7: Config and Operational Knobs

### Peer config

BGP-LS is enabled via the generic `afi-safis` list (added in Phase 1):

```yaml
peers:
  10.0.0.1:
    asn: 65001
    afi-safis:
      - afi: 16388
        safi: 71
```

### Per-family sub-config (future)

Extend `AfiSafiConfig` with per-family overrides. `None` = inherit from top-level PeerConfig.

```yaml
peers:
  10.0.0.1:
    asn: 65001
    max-prefix:
      limit: 10000                     # global default
    afi-safis:
      - afi: 16388                     # BGP-LS
        safi: 71
        max-prefix:
          limit: 100000               # override for LS
      - afi: 1                         # override IPv4 unicast defaults
        safi: 1
        add-path-send: all
```

### Global config

```yaml
bgp_ls:
  max_rib_entries: 100000             # max LS NLRIs in RIB (0 = unlimited)
```

### Files to change

- `core/src/config.rs` -- per-family AfiSafiConfig with optional overrides, global BgpLsConfig
- `proto/bgp.proto` -- extend AfiSafiConfig with per-family fields
- `core/src/grpc/service.rs` -- convert extended AfiSafiConfig fields

---

## Phase 8: Policy Extensions (future)

New match conditions for BGP-LS specific filtering:

- `match afi-safi bgp-ls` -- match on address family (may already work)
- `match ls-nlri-type node|link|prefix-v4|prefix-v6`
- `match ls-protocol-id direct|static|ospfv2|...`
- `match ls-instance-id <value>`
- `match ls-node-as <asn>`
- `match ls-node-router-id <ip>`

These enable per-peer topology filtering (e.g., show partner only abstracted topology).

### Files to change

- `core/src/policy/sets.rs` -- new LsMatchSet types
- `core/src/policy/statement.rs` -- new conditions
- `proto/bgp.proto` -- policy proto messages for LS conditions

---

---

## Integration Tests

File: `core/tests/bgpls.rs`. Follows TEST.md patterns — `poll_until()`, no `sleep()`,
table-driven where possible. Keep tests short — extract helpers for LS route polling
and NLRI building so the actual test logic is obvious.

### Test cases

1. **Capability negotiation + filtering** -- star topology: center server with LS enabled
   to both spokes. Spoke A has LS enabled, spoke B does not. Table-driven: verify LS
   capability negotiated with spoke A but not B. Inject LS route on center, verify spoke A
   receives it, spoke B does not.

2. **LS route injection and propagation** -- server1 injects LS Node NLRI via gRPC,
   poll until server2 receives it via `ListLsRoutes`. Verify NLRI fields and BGP-LS attribute
   arrive intact.

3. **LS route withdrawal** -- inject LS route, verify propagated, withdraw via gRPC,
   poll until removed from server2.

4. **Multiple NLRI types** -- inject Node, Link, and Prefix NLRIs, verify all three
   propagated and queryable.

5. **Unknown TLV preservation** -- FakePeer sends LS NLRI with unknown TLV types,
   verify bgpgg preserves and propagates them unchanged to another peer. FakePeer needed
   here because real servers can't originate arbitrary unknown TLVs.

6. **Max RIB entries** -- configure max_rib_entries limit, inject routes up to the limit,
   verify the next injection is rejected/dropped.

7. **Best path selection** -- two peers announce same LS NLRI with different LOCAL_PREF,
   verify bgpgg picks the higher one.

8. **LS route replace** -- same NLRI, updated BGP-LS attribute (type 29), verify old
   attribute replaced, not duplicated.

9. **NLRI TLV change = different route** -- change a descriptor TLV in the NLRI, verify
   it creates a new RIB entry (different key), not a replacement.

10. **Session down cleanup** -- peer goes down, verify its LS routes withdrawn from RIB
    and from other peers.

### Route reflector test (in `core/tests/route_reflector.rs`)

New test function `test_rr_bgpls_reflection()`. Same topology pattern as
`test_route_reflector_basic()`: client1 -> RR -> client2. Inject LS NLRI on client1,
poll until client2 has it, verify ORIGINATOR_ID and CLUSTER_LIST set correctly.

### Policy tests (in `core/tests/policy.rs`)

- Import deny on AFI/SAFI BGP-LS -- LS route rejected, IP routes on same session accepted
- Export deny on AFI/SAFI BGP-LS -- LS route not propagated to peer

### Error handling tests (in `core/tests/bgpls.rs`)

All use FakePeer to send hand-crafted bytes. Tests the three-level error escalation
from RFC 9552 Section 8.2:

**Level 1: NLRI discard (recoverable NLRI error)**
- LS NLRI with TLV ordering violation -- bad NLRI discarded, other NLRIs in same
  UPDATE processed normally. Session stays up.

**Level 2: Attribute discard (recoverable attribute error)**
- BGP-LS attribute (type 29) with malformed TLV length inside, but overall attribute
  length correct -- attribute discarded, route propagated without it. Session stays up.
- Missing BGP-LS attribute -- valid (attribute is optional), route stored and propagated.

**Level 3: AFI/SAFI disable or session reset (unrecoverable)**
- LS NLRI with length encoding error that makes rest of UPDATE unparseable --
  if other AFI/SAFIs active on session: disable BGP-LS AFI/SAFI, session stays up.
  If BGP-LS is only AFI/SAFI: session reset (NOTIFICATION sent).

**Preservation tests:**
- Unknown NLRI type (e.g., type 99) -- preserved as opaque, propagated to next peer
- Unknown TLVs inside known NLRI type -- preserved, propagated unchanged
- Unknown TLVs inside BGP-LS attribute -- preserved, propagated unchanged

---

## Implementation Order

1. Phase 1 (AFI/SAFI) -- small, unblocks everything
2. Phase 2 (NLRI codec) -- the bulk of the work, mechanical TLV parsing
3. Phase 3 (Attribute codec) -- similar to Phase 2, fewer TLVs
4. Phase 4 (RIB) -- straightforward HashMap addition
5. Phase 5 (Processing + Propagation) -- wiring, uses existing patterns
6. Phase 6 (gRPC) -- follows existing AddRoute/ListRoutes patterns
7. Phase 7 (Config) -- small, can be partially done alongside earlier phases
8. Phase 8 (Policy) -- future, not needed for initial release

Phases 1-5 make bgpgg a correct BGP-LS propagator (dumb pipe / route reflector).
Phase 6 adds producer/consumer capability.
Phase 7 adds operational control.
Phase 8 adds fine-grained topology filtering.

## Design Principles

- Opaque propagation: for RIB keying and forwarding, use raw NLRI bytes. Don't require
  deep parsing to propagate correctly.
- Deep parsing is lazy: only parse TLV semantics when needed (gRPC query).
  Propagation path never does semantic validation.
- Preserve everything: unknown NLRI types, unknown TLVs -- store raw bytes, forward as-is.
- No IGP integration: topology comes from gRPC injection or BGP peers. bgpgg is transport.
- Per-peer opt-in: BGP-LS is off by default. Operator explicitly enables per peer.

## Interop Testing

- GoBGP is the primary open-source interop target (only other OSS implementation)
- Test: bgpgg <-> GoBGP BGP-LS session, exchange NLRIs
- Test: bgpgg as RR between two GoBGP speakers
