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

## Phase 2: BGP-LS NLRI Codec -- DONE

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

## Phase 3: BGP-LS Attribute (Type 29) Codec -- DONE

Parse and encode the BGP-LS path attribute that carries node/link/prefix properties.

### Changes made

- `core/src/bgp/bgpls.rs` (NEW) -- shared BGP-LS types: `LsTlv`, `LsTlvType` (NLRI descriptor
  TLV types), `LsAttrTlvType` (attribute TLV types). Moved `LsTlv` and `LsTlvType` here from
  `bgpls_nlri.rs` since they're used by both NLRI and attribute modules.

- `core/src/bgp/bgpls_attr.rs` (NEW) -- `LsAttrTlv` enum, `LsAttribute` struct, parsing/encoding
  - `LsAttrTlv`: typed enum with one variant per known TLV, grouped by RFC 9552 Section 5.3
    (Node 5.3.1, Link 5.3.2, Prefix 5.3.3), plus `Unknown(LsTlv)` catch-all
  - Each known variant validates length at parse time (fixed-length fields checked exactly,
    variable-length fields like SRLG/IGP Route Tag checked for non-empty multiple-of-N)
  - `LsAttribute`: `raw: Vec<u8>` (opaque propagation) + `tlvs: Vec<LsAttrTlv>` (typed access)
  - `build_ls_attribute()`: construct from typed TLVs, encodes to set raw field
  - TLV ordering not validated (SHOULD not MUST per RFC 9552 for attributes)

- `core/src/bgp/msg_update_types.rs`
  - Added `attr_type_code::LINK_STATE = 29`
  - Added `AttrType::LinkState = 29` with expected flags OPTIONAL | TRANSITIVE
  - Added `PathAttrValue::LsAttribute(LsAttribute)` variant

- `core/src/bgp/msg_update_codec.rs`
  - `parse_attr_value`: dispatches type 29 to `parse_ls_attribute()`
  - `validate_attribute_length`: variable length (always valid)
  - `write_path_attribute`: encodes via `write_ls_attribute()` (raw bytes)
  - RFC 7606 error action: Attribute Discard (via `malformed_attr_action` catch-all)

- `core/src/bgp/bgpls_nlri.rs` -- imports `LsTlv` and `LsTlvType` from `bgpls.rs`

### Design notes

**Why one flat enum, not NodeAttrTlv / LinkAttrTlv / PrefixAttrTlv?** At attribute parse time
we don't know the NLRI type -- the type 29 attribute is a separate path attribute from
MP_REACH_NLRI. TLV type ranges also overlap (1028/1029 appear in both Node and Link per RFC).
One enum with variants grouped by section is the simplest correct approach.

**Why typed variants instead of raw `Vec<LsTlv>`?** Matches the NLRI pattern where descriptors
are parsed into typed structs (`NodeDescriptor`, `LinkDescriptor`, etc). Known TLVs get length
validation at parse time. gRPC query (Phase 6) can pattern-match directly.

### Tests

- `test_parse_node_attr_tlvs` -- all 6 node TLV types parsed into typed variants
- `test_parse_link_attr_tlvs` -- 10 link TLV types including IEEE float, SRLG, variable IGP metric
- `test_parse_prefix_attr_tlvs` -- 6 prefix TLV types including dual-length OSPF fwd addr
- `test_unknown_tlvs_preserved` -- unknown + private-use TLVs survive as `Unknown(LsTlv)`
- `test_round_trip` -- build -> encode -> parse for node, link, prefix, mixed, empty
- `test_empty_attribute` -- zero-length attribute valid
- `test_malformed_tlv_truncated_header` -- 2 bytes rejects
- `test_malformed_tlv_length_overflow` -- TLV claims more bytes than available
- `test_malformed_trailing_bytes` -- valid TLV + incomplete header
- `test_malformed_known_tlv_wrong_length` -- 18 cases covering every fixed/multiple-of constraint
- `test_unordered_tlvs_accepted` -- descending order accepted per RFC
- `test_ls_attribute_roundtrip` (codec) -- full path attribute wire format round-trip
- `test_ls_attribute_malformed_discard` (codec) -- malformed type 29 triggers Attribute Discard

---

## Phase 4: RIB Storage -- DONE

Store BGP-LS routes in the Loc-RIB alongside IPv4/IPv6 unicast routes.

### Changes made

**RouteKey and Route unification.** `RouteKey` enum (`Prefix(IpNetwork) | LinkState(LsNlri)`)
is the unified route identifier across all address families. `Route.key: RouteKey` replaces
the old `Route.prefix: IpNetwork`. `RouteDelta` uses `Vec<RouteKey>`. All LocRib public
methods (`get_best_path`, `get_all_paths`, `has_route`, `upsert_path`, `remove_peer_path`,
`remove_paths`) take `&RouteKey` — no separate LS-specific methods.

**LocRib tables.** Three per-family tables: `ipv4_unicast: PrefixMap<Ipv4Net, Route>`,
`ipv6_unicast: PrefixMap<Ipv6Net, Route>`, `link_state: HashMap<LsNlri, Route>`.
IPv4/IPv6 use PrefixMap (HashMap + trie for RPKI subtree queries). LS uses plain HashMap
(no hierarchical prefix structure). Internal dispatch via `get_route_mut()` and
`remove_route_entry()`. `get_routes_afi(afi)` returns routes for any family.

**Path helpers.** Container-agnostic free functions: `upsert_path_in_route(&mut Route)`,
`remove_paths_from_route(&mut Route)`, `collect_peer_path_ids(Iterator<&mut Route>)`.
LocRib methods handle container dispatch then call these. No per-family duplication.

**Stale handling.** `stale.rs` provides per-route operations: `mark_stale(Iterator<&mut Route>)`,
`apply_stale_to_route(&mut Route)`. LocRib's `handle_stale()` orchestrates: collects stale
keys, applies strategy per route, cleans up empty entries, builds RouteDelta. `mark_peer_routes_stale`,
`apply_llgr`, `remove_peer_routes_stale` all handle `(Afi::LinkState, Safi::LinkState)`.

**AdjRibIn.** Unified API: `add_route(RouteKey, Arc<Path>)`, `remove_route(&RouteKey)`,
`get_route(&RouteKey)`. One `upsert_path` helper dispatches to the right table. LS table
keyed by `LsNlri`.

**PathAttrs.** Added `ls_attr: Option<LsAttr>` for BGP-LS attribute (type 29).
`UpdateMessage::ls_attr()` accessor added.

**Propagation.** `resend_routes_to_peer` uses `get_routes_afi(afi)` for all families
including LS. `outgoing.rs` skips `RouteKey::LinkState` with `continue` (Phase 5 fills in
the LS UPDATE builder).

### Files changed

- `core/src/rib/types.rs` -- `RouteKey` enum, `Route.key: RouteKey`
- `core/src/rib/rib_loc.rs` -- link_state table, unified RouteKey API, stale orchestration
- `core/src/rib/rib_in.rs` -- unified `add_route`/`remove_route`/`get_route` via RouteKey
- `core/src/rib/stale.rs` -- container-agnostic `mark_stale`, `apply_stale_to_route`
- `core/src/rib/path.rs` -- `ls_attr: Option<LsAttr>` on PathAttrs
- `core/src/rib/mod.rs` -- re-export RouteKey
- `core/src/bgp/msg_update.rs` -- `UpdateMessage::ls_attr()` accessor
- `core/src/peer/outgoing.rs` -- RouteKey dispatch, skip LS for now
- `core/src/server/propagate.rs` -- `get_routes_afi` for resend, RouteKey in delta
- `core/src/server/ops.rs` -- RouteKey wrapping in adj-rib-in calls
- `core/src/server/ops_mgmt.rs` -- RouteKey match for BMP (LS skipped, Phase 5)
- `core/src/grpc/service.rs` -- RouteKey match in route_to_proto
- Multiple files -- `ls_attr: None` on PathAttrs construction sites

### Tests

- `test_upsert_ls_path` -- insert LS route, verify retrievable via `get_best_path`
- `test_ls_best_path_selection` -- two paths same key, higher LOCAL_PREF wins
- `test_withdraw_ls_route` -- remove path, verify gone
- `test_replace_ls_route` -- same key new attrs, verify replaced
- `test_remove_ls_routes_from_peer` -- peer disconnect clears LS routes, RouteDelta correct
- `test_ls_different_nlri_key` -- different descriptors = separate entries
- `test_mark_stale`, `test_sweep`, `test_llgr_transition` -- stale tests updated for Route.key

---

## Phase 5: UPDATE Processing and Propagation -- DONE

Wire up the codec and RIB so bgpgg can receive, store, and propagate BGP-LS routes.

### Changes made

**Unified route pipeline.** `PrefixPath` renamed to `RoutePath { key: RouteKey }` across
the entire codebase. `Withdrawal` generalized from `(IpNetwork, Option<u32>)` to
`(RouteKey, Option<u32>)` and moved to `rib/types.rs`. `PendingRoute`, `apply_peer_update`,
and the propagation pipeline all operate on `RouteKey` generically.

- `core/src/rib/types.rs` -- `RoutePath`, `Withdrawal`, `RouteKey::afi_safi()`
- `core/src/peer/mod.rs` -- `PendingRoute::Announce(RoutePath)`, `route_key()` method
- `core/src/rib/rib_out.rs` -- `AdjRibOut` rekeyed from `IpNetwork` to `RouteKey`
- `core/src/rib/rib_loc.rs` -- `apply_peer_update` closure takes `&RouteKey`; `get_paths()`
  returns LS routes for `Afi::LinkState`

**Incoming.** `core/src/peer/incoming.rs` -- `process_withdrawals()` and
`process_announcements()` extract LS NLRIs from `UpdateMessage::ls_nlri_list()` /
`ls_withdrawn_list()` alongside IP NLRIs. Same `Path` object carries `ls_attr`.

**Outgoing.** Separate constructors per wire format (RFC 4271 Section 6.3: one
MP_REACH_NLRI per UPDATE):
- `UpdateMessage::new()` -- IP routes (IPv4 traditional NLRI + IPv6 MP_REACH)
- `UpdateMessage::new_ls()` -- BGP-LS routes (MP_REACH with AFI 16388 + type-29 attr)
- `UpdateMessage::new_withdraw()` -- IP withdrawals
- `UpdateMessage::new_ls_withdraw()` -- BGP-LS withdrawals
- Common attributes extracted to `build_common_path_attrs()`
- `core/src/peer/outgoing.rs` -- `send_ls_announcements()` batches LS routes by shared
  path attributes; `send_withdrawals()` splits IP/LS into separate UPDATEs

**Propagation.** `propagate_routes_to_peer()` iterates per AFI/SAFI, filters by
`route_key.afi_safi()`. `compute_export_path`, `build_export_attrs`,
`build_export_next_hop` all take `&RouteKey`. LS routes: no prefix-based policy
(default accept, Phase 8 adds LS policy); next-hop follows standard BGP rules
per RFC 9552 Section 5.5.

**Server.** `apply_import()` handles `RouteKey::LinkState` (skip VRP, default accept).
`validate_afi_safi()` uses `RouteKey::afi_safi()`. `resend_routes_to_peer()` supports
`Safi::LinkState`.

**BMP.** `send_bmp_route_monitoring()` splits IP/LS into separate UPDATEs.

**RFC compliance fixes:**
- RFC 4760 Section 3: NEXT_HOP attribute only emitted for IPv4 unicast NLRI; ignored
  (not rejected) when received alongside MP_REACH_NLRI
- RFC 4271 Section 6.3: one MP_REACH per UPDATE enforced by separate constructors

### Tests

- `test_ls_update_roundtrip` -- build LS UPDATE via `new_ls()`, serialize, parse, verify
  NLRI + type-29 attribute survive
- `test_ls_update_no_attr` -- LS UPDATE without type-29 attribute (valid per RFC 9552
  Section 8.2.2)
- `test_ls_withdraw_roundtrip` -- `new_ls_withdraw()` roundtrip
- `test_update_message_ipv6_encode_decode` -- IPv6 MP_REACH roundtrip (existing, unchanged)
- `test_update_message_next_hop_with_mp_reach_ignored` -- RFC 4760 Section 3: NEXT_HOP
  ignored when MP_REACH present
- `test_next_hop_with_mp_reach_ignored` (codec) -- same at attribute parsing level
- `test_apply_peer_update_ls_route` -- LS route inserted via `apply_peer_update`
- `test_apply_peer_update_ls_withdrawal` -- LS withdrawal removes route
- `test_get_paths_ls` -- `get_paths(Afi::LinkState)` returns LS routes

---

## Phase 6: gRPC API -- DONE

Expose BGP-LS routes via the existing unified gRPC API. A BGP-LS route is a route --
same `AddRoute`/`RemoveRoute`/`ListRoutes` RPCs, not separate LS-specific RPCs.

### Design decision: oneof per route type

`AddRouteRequest`, `RemoveRouteRequest`, and `Route` use `oneof` to discriminate route
types. Each type gets its own sub-message with only relevant fields. Adding flowspec or
EVPN is just a new variant -- no field pollution.

```protobuf
message AddRouteRequest {
    oneof route {
        AddIpRouteRequest ip = 1;
        AddLsRouteRequest ls = 2;
    }
}
message RemoveRouteRequest {
    oneof key {
        string prefix = 1;
        LsNlri ls_nlri = 2;
    }
}
message Route {
    repeated Path paths = 1;
    oneof key {
        string prefix = 2;
        LsNlri ls_nlri = 3;
    }
}
```

Large oneof variants (`LsNlri`, `AddIpRouteRequest`) are boxed via `prost_build::boxed()`
in `core/build.rs` to avoid enum size bloat.

### Proto messages

LS-specific types in `proto/bgp.proto`:

- `LsNlriType`, `LsProtocolId` enums
- `LsNodeDescriptor`, `LsLinkDescriptor`, `LsPrefixDescriptor` -- typed NLRI descriptors
- `LsNlri` -- full NLRI with type, protocol_id, identifier, descriptors
- `LsNodeAttribute`, `LsLinkAttribute`, `LsPrefixAttribute` -- typed attribute fields
- `LsAttribute` -- raw TLVs + typed node/link/prefix sub-messages
- `AddIpRouteRequest`, `AddLsRouteRequest` -- per-type injection messages
- `ListRoutesRequest` has `afi`/`safi` fields for family filtering

### Changes made

- `proto/bgp.proto` -- oneof-based `AddRouteRequest`, `RemoveRouteRequest`, `Route`;
  all LS message types
- `core/build.rs` -- `.boxed()` for large oneof variants
- `core/src/grpc/proto_ls.rs` (NEW) -- bidirectional proto<->internal conversion for
  all LS types (NLRI, descriptors, attributes)
- `core/src/grpc/service.rs` -- `add_route`/`remove_route` match on oneof variant;
  `route_to_proto` populates LS fields for LinkState routes
- `core/src/grpc/client.rs` -- thin wrappers: `add_route(AddRouteRequest)`,
  `remove_route(RemoveRouteRequest)`, `list_routes(ListRoutesRequest)`.
  Caller builds proto struct directly.
- `core/src/rib/rib_loc.rs` -- `add_local_route`/`remove_local_route` generalized
  from `IpNetwork` to `RouteKey`. Unified `get_routes(Option<AfiSafi>)` across all
  three RIBs (LocRib, AdjRibIn, AdjRibOut) -- goes straight to the right per-family
  table, no post-filtering.
- `core/src/server/ops_mgmt.rs` -- `MgmtOp::AddRoute`/`RemoveRoute` use `RouteKey`.
  `GetRoutes`/`GetRoutesStream` pass `AfiSafi` filter to RIB.
- `core/src/bgp/multiprotocol.rs` -- `AfiSafi::from_raw(Option<u32>, Option<u32>)`
- `cli/src/commands/global.rs` -- `rib add-ls node` and `rib del-ls node` subcommands;
  `rib show` displays LS routes with type/protocol/node info

### Tests

Unit tests (proto_ls.rs): NLRI roundtrip (node, link), attribute roundtrip (node, link bandwidth).
Unit tests (rib_loc.rs): `test_get_routes_family_filter` -- table-driven, verifies
actual Route objects for each family filter including unsupported AFI/SAFI.

Integration tests (core/tests/mgmt.rs):
- `test_add_ls_route` -- inject via gRPC, verify in Loc-RIB with NLRI + attribute intact
- `test_remove_ls_route` -- inject then withdraw, verify removal
- `test_list_routes_family_filter` -- IP + LS routes coexist, filter by AFI/SAFI

---

## Phase 7: Config and Operational Knobs -- DONE

### Changes made

**Per-family config overrides.** `AfiSafiConfig` struct in `config.rs` wraps AFI/SAFI with
optional `max_prefix` and `add_path_send` overrides. `PeerConfig.afi_safis` changed from
`Vec<AfiSafi>` to `Vec<AfiSafiConfig>`. `PeerConfig::afi_safi_list()` extracts plain
`Vec<AfiSafi>` for protocol-level callers (capability negotiation, LLGR).
`PeerConfig::effective_max_prefix(&AfiSafi)` resolves per-family override or peer-level fallback.
Validation rejects duplicate AFI/SAFI entries.

**Per-family max-prefix enforcement.** `ops.rs` max-prefix check changed from aggregate
`prefix_count()` to per-family `family_count()`. Each family in the UPDATE is checked
independently via `effective_max_prefix()`. Discard action only drops announcements for the
over-limit family, not the entire UPDATE. `AdjRibIn::family_count(&AfiSafi)` added for
per-family counting.

**Global BGP-LS config.** `BgpLsConfig { max_ls_entries: u32 }` on `Config` (default 0 =
unlimited). `LocRibConfig` struct passed to `LocRib::new()`. Guard in `upsert_path()` rejects
new LS entries at capacity (updates to existing NLRIs always allowed). `add_local_route()`
returns `Result<RouteDelta, LocRibError>` so gRPC injection gets a proper error on rejection.

**Proto split.** `AfiSafi` message remains plain (afi + safi only, used by LLGR). New
`AfiSafiConfig` message carries per-family overrides (used by SessionConfig.afi_safis).

```yaml
peers:
  10.0.0.1:
    asn: 65001
    max-prefix:
      limit: 10000                     # peer-level default
    afi-safis:
      - afi: 16388                     # BGP-LS
        safi: 71
        max-prefix:
          limit: 100000               # override for LS
      - afi: 1                         # override IPv4 unicast defaults
        safi: 1
        add-path-send: all

bgp-ls:
  max-ls-entries: 100000               # max LS NLRIs in Loc-RIB (0 = unlimited)
```

### Files changed

- `core/src/config.rs` -- `AfiSafiConfig`, `BgpLsConfig`, `effective_max_prefix()`, validation
- `core/src/rib/rib_loc.rs` -- `LocRibConfig`, `LocRibError`, `max_ls_entries` guard, `add_local_route` returns Result
- `core/src/rib/rib_in.rs` -- `family_count(&AfiSafi)`
- `core/src/server/ops.rs` -- per-family max-prefix enforcement
- `core/src/server/ops_mgmt.rs` -- handle `add_local_route` Result
- `core/src/server/mod.rs` -- pass `LocRibConfig` to `LocRib::new()`
- `core/src/grpc/service.rs` -- `proto_to_afi_safis` returns `Vec<AfiSafiConfig>`, proto round-trip
- `core/src/peer/messages.rs` -- use `afi_safi_list()` for capability negotiation
- `proto/bgp.proto` -- `AfiSafiConfig` message, `SessionConfig` uses it

### Tests

- `test_effective_max_prefix` -- table-driven: per-family override, fallback, both absent
- `test_effective_max_prefix_different_families` -- LS override vs IPv4 peer-level fallback
- `test_afi_safi_list` -- extracts plain AfiSafi from AfiSafiConfig vec
- `test_validate_duplicate_afi_safis` -- duplicate rejection
- `test_afi_safi_config_yaml_deserialization` -- new format with overrides
- `test_afi_safi_config_yaml_minimal` -- backward-compatible old format
- `test_bgp_ls_config_default`, `test_bgp_ls_config_yaml` -- global config
- `test_family_count` -- per-family counting in AdjRibIn
- `test_max_ls_entries` -- table-driven: unlimited, capped, under limit
- `test_max_ls_entries_update_existing_allowed` -- update at capacity OK, new key rejected
- `test_max_ls_entries_does_not_affect_ip` -- LS limit doesn't block IPv4
- `test_add_local_route_rejected_at_capacity` -- LocRibError returned

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

6. **Max RIB entries** -- configure max_ls_entries limit, inject routes up to the limit,
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
