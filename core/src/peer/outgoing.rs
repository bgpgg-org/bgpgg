// Copyright 2025 bgpgg Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Route propagation logic for BGP UPDATE messages

use crate::bgp::ext_community::is_transitive;
use crate::bgp::msg::{Message, MessageFormat, MAX_MESSAGE_SIZE};
use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin, UpdateMessage};
use crate::bgp::msg_update_types::{
    NextHopAddr, Nlri, NO_ADVERTISE, NO_EXPORT, NO_EXPORT_SUBCONFED,
};
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::log::{debug, error, info, warn};
use crate::net::IpNetwork;
use crate::peer::BgpState;
use crate::peer::PeerOp;
use crate::policy::PolicyResult;
use crate::rib::rib_loc::{LocRib, RouteDelta};
use crate::rib::{AdjRibOut, Path, PathAttrs, PrefixPath, RouteSource};

#[cfg(test)]
use crate::policy::Policy;
use std::collections::HashMap;
use std::net::IpAddr;

use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// A batch of route announcements sharing the same path attributes
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct AnnouncementBatch {
    pub path: Arc<Path>,
    pub prefixes: Vec<IpNetwork>,
}

/// Bundles per-peer parameters needed for route export
pub struct PeerExportContext<'a> {
    pub peer_addr: IpAddr,
    pub peer_tx: &'a mpsc::UnboundedSender<PeerOp>,
    pub local_asn: u32,
    pub peer_asn: u32,
    pub local_next_hop: IpAddr,
    pub export_policies: &'a [Arc<crate::policy::Policy>],
    pub rr_client: bool,
    pub rs_client: bool,
    pub cluster_id: Ipv4Addr,
    pub send_format: MessageFormat,
}

/// Check if a path should be exported to a peer (pre-policy filtering).
fn should_export_to_peer(path: &Path, ctx: &PeerExportContext) -> bool {
    let is_ibgp = ctx.local_asn == ctx.peer_asn;

    // RFC 4456: iBGP reflection requires at least one RR client
    if is_ibgp && path.source().is_ibgp() && !path.source().is_rr_client() && !ctx.rr_client {
        return false;
    }

    // Don't send a path back to the peer it was learned from
    if path.source().peer_ip() == Some(ctx.peer_addr) {
        return false;
    }

    // RFC 1997: NO_ADVERTISE, NO_EXPORT, NO_EXPORT_SUBCONFED
    if should_filter_by_community(path.communities(), ctx.local_asn, ctx.peer_asn) {
        return false;
    }

    true
}

/// Check if a route should be filtered based on well-known communities
/// RFC 1997 Section 3: Well-known communities
fn should_filter_by_community(communities: &[u32], local_asn: u32, peer_asn: u32) -> bool {
    if communities.contains(&NO_ADVERTISE) {
        return true;
    }

    let is_ebgp = local_asn != peer_asn;

    if is_ebgp && (communities.contains(&NO_EXPORT) || communities.contains(&NO_EXPORT_SUBCONFED)) {
        return true;
    }

    false
}

/// Check if we should propagate routes to this peer
pub fn should_propagate_to_peer(
    peer_addr: IpAddr,
    peer_state: BgpState,
    originating_peer: Option<IpAddr>,
) -> bool {
    // Skip the peer that sent us the original update (if any)
    if let Some(orig_peer) = originating_peer {
        if peer_addr == orig_peer {
            return false;
        }
    }

    // Only send to established peers
    peer_state == BgpState::Established
}

/// Build AS path for export to a peer
/// RFC 4271 Section 5.1.2:
/// - Local routes to eBGP: [local_asn]
/// - Local routes to iBGP: [] (empty)
/// - Learned routes to eBGP: prepend local_asn to first AS_SEQUENCE (or create new segment)
/// - Learned routes to iBGP: unchanged
///
/// RFC 7947: Route servers preserve AS_PATH unchanged (no local ASN prepending)
///
/// Preserves AS_SET segments during propagation
pub fn build_export_as_path(path: &Path, ctx: &PeerExportContext) -> Vec<AsPathSegment> {
    // RFC 7947: Route servers preserve AS_PATH (no prepending)
    if ctx.rs_client {
        return path.as_path().clone();
    }

    let is_ebgp = ctx.peer_asn != ctx.local_asn;

    // Truly locally originated routes (empty AS_PATH)
    if matches!(path.source(), RouteSource::Local) && path.as_path().is_empty() {
        if is_ebgp {
            // eBGP: AS_PATH = [local_asn]
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![ctx.local_asn],
            }]
        } else {
            // iBGP: AS_PATH = [] (empty)
            vec![]
        }
    } else if is_ebgp {
        prepend_local_asn(path.as_path(), ctx.local_asn)
    } else {
        // iBGP: preserve AS_PATH unchanged
        path.as_path().clone()
    }
}

/// Prepend local ASN to AS_PATH for eBGP export
/// RFC 4271: Prepend to existing AS_SEQUENCE or create new segment
fn prepend_local_asn(as_path: &[AsPathSegment], local_asn: u32) -> Vec<AsPathSegment> {
    let mut new_segments = Vec::new();

    if let Some(first) = as_path.first() {
        if first.segment_type == AsPathSegmentType::AsSequence {
            // Prepend to existing AS_SEQUENCE
            let mut new_asn_list = vec![local_asn];
            new_asn_list.extend_from_slice(&first.asn_list);
            new_segments.push(AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: new_asn_list.len() as u8,
                asn_list: new_asn_list,
            });
            new_segments.extend_from_slice(&as_path[1..]);
        } else {
            // First segment is AS_SET, create new AS_SEQUENCE segment
            new_segments.push(AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![local_asn],
            });
            new_segments.extend_from_slice(as_path);
        }
    } else {
        // Empty AS_PATH, create new AS_SEQUENCE
        new_segments.push(AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 1,
            asn_list: vec![local_asn],
        });
    }

    new_segments
}

/// Determine LOCAL_PREF to include in UPDATE message
///
/// RFC 4271 Section 5.1.5:
/// - iBGP: LOCAL_PREF SHALL be included
/// - eBGP: LOCAL_PREF MUST NOT be included
///
/// RFC 7947: Route servers follow the same session type rules
pub fn build_export_local_pref(path: &Path, ctx: &PeerExportContext) -> Option<u32> {
    if ctx.local_asn == ctx.peer_asn {
        path.local_pref()
    } else {
        None
    }
}

/// Determine MULTI_EXIT_DISC (MED) to include in UPDATE message
///
/// RFC 4271 Section 5.1.4:
/// - iBGP: MED MAY be propagated to other BGP speakers within the same AS
/// - eBGP: MED MUST NOT be propagated to other neighboring ASes
///
/// RFC 7947: Route servers preserve MED unchanged
pub fn build_export_med(path: &Path, ctx: &PeerExportContext) -> Option<u32> {
    if ctx.rs_client {
        return path.med();
    }

    let is_ibgp = ctx.local_asn == ctx.peer_asn;
    if is_ibgp {
        return path.med();
    }

    // eBGP: only send MED if route originated from our AS
    // Check source for local routes (before iBGP propagation changes it to Ibgp)
    if matches!(path.source(), RouteSource::Local) {
        return path.med();
    }

    match path.as_path().first() {
        None => path.med(), // Empty AS_PATH means local route
        Some(seg) if seg.asn_list.first() != Some(&ctx.local_asn) => None, // External AS
        Some(seg) if seg.segment_type == AsPathSegmentType::AsSet => None, // RFC 4271 9.2.2.2
        Some(_) => path.med(), // Route from our AS
    }
}

/// Filter extended communities for export to peer
/// RFC 4360: Non-transitive extended communities (bit 6 = 1) must be filtered when advertising to eBGP peers
/// RFC 7947: Route servers preserve ALL communities (both transitive and non-transitive)
pub fn build_export_extended_communities(path: &Path, ctx: &PeerExportContext) -> Vec<u64> {
    // RFC 7947: Route servers preserve ALL communities
    // (both transitive and non-transitive)
    if ctx.rs_client {
        return path.extended_communities().clone();
    }

    let is_ebgp = ctx.local_asn != ctx.peer_asn;

    if is_ebgp {
        // Filter out non-transitive extended communities (RFC 4360 Section 6)
        path.extended_communities()
            .iter()
            .filter(|&&extcomm| is_transitive(extcomm))
            .copied()
            .collect()
    } else {
        // iBGP: propagate all extended communities
        path.extended_communities().clone()
    }
}

/// Send withdrawal messages to a peer.
fn send_withdrawals(ctx: &PeerExportContext, withdrawn: Vec<Nlri>, format: MessageFormat) {
    if withdrawn.is_empty() {
        return;
    }

    let count = withdrawn.len();
    let withdraw_msg = UpdateMessage::new_withdraw(withdrawn, format);
    let serialized = withdraw_msg.serialize();
    if let Err(e) = ctx.peer_tx.send(PeerOp::SendUpdate(serialized)) {
        error!(peer_addr = %ctx.peer_addr, error = %e, "failed to send withdrawals to peer");
    } else {
        info!(count, peer_addr = %ctx.peer_addr, "propagated withdrawals to peer");
    }
}

/// Batching key: attributes that must match for announcements to be batched together.
/// Includes local_path_id so ADD-PATH paths with different IDs are never merged.
type BatchingKey = (
    Origin,
    Vec<AsPathSegment>,
    NextHopAddr,
    bool,
    Vec<u32>,
    Option<u32>,
);

/// Group announcements by path attributes to enable batching
/// Returns a vector of batches, where each batch contains a path and all prefixes sharing those attributes
pub(crate) fn batch_announcements_by_path(to_announce: &[PrefixPath]) -> Vec<AnnouncementBatch> {
    let mut batches: HashMap<BatchingKey, AnnouncementBatch> = HashMap::new();

    for PrefixPath { prefix, path } in to_announce {
        let key = (
            path.origin(),
            path.as_path().clone(),
            *path.next_hop(),
            path.atomic_aggregate(),
            path.communities().clone(),
            path.local_path_id,
        );
        let batch = batches.entry(key).or_insert_with(|| AnnouncementBatch {
            path: Arc::clone(path),
            prefixes: Vec::new(),
        });
        batch.prefixes.push(*prefix);
    }

    batches.into_values().collect()
}

fn address_families_match(next_hop: &NextHopAddr, ip_addr: IpAddr) -> bool {
    matches!(
        (next_hop, ip_addr),
        (NextHopAddr::Ipv4(_), IpAddr::V4(_)) | (NextHopAddr::Ipv6(_), IpAddr::V6(_))
    )
}

fn build_ebgp_next_hop(
    path: &Path,
    local_next_hop: IpAddr,
    prefix: &IpNetwork,
) -> Option<NextHopAddr> {
    if address_families_match(path.next_hop(), local_next_hop) {
        // Same address family - rewrite to local interface
        Some(local_next_hop.into())
    } else if !path.next_hop().is_unspecified() {
        // Cross-family with explicit next hop - preserve it
        Some(*path.next_hop())
    } else {
        // Cross-family without explicit next hop - can't advertise
        warn!(
            %prefix,
            "filtering cross-family route without explicit next hop"
        );
        None
    }
}

fn build_ibgp_next_hop(
    path: &Path,
    local_next_hop: IpAddr,
    prefix: &IpNetwork,
) -> Option<NextHopAddr> {
    if !path.source().is_local() {
        // Learned route - preserve next hop
        return Some(*path.next_hop());
    }

    // Locally originated route
    if !path.next_hop().is_unspecified() {
        // Explicit next hop - preserve it
        Some(*path.next_hop())
    } else if address_families_match(path.next_hop(), local_next_hop) {
        // Same address family - use local interface
        Some(local_next_hop.into())
    } else {
        // Cross-family without explicit next hop - can't advertise
        warn!(
            %prefix,
            "filtering cross-family route without explicit next hop"
        );
        None
    }
}

/// Build the NEXT_HOP for export to a peer
/// RFC 4271 Section 5.1.3: Rewrite NEXT_HOP to local interface address
/// RFC 2545/4760: Cross-family (e.g., IPv6 route over IPv4 session) must preserve explicit next hop
/// RFC 7947: Route servers preserve NEXT_HOP unchanged
fn build_export_next_hop(
    path: &Path,
    ctx: &PeerExportContext,
    prefix: &IpNetwork,
) -> Option<NextHopAddr> {
    // RFC 7947: Route servers preserve NEXT_HOP unchanged
    if ctx.rs_client {
        return Some(*path.next_hop());
    }

    if ctx.local_asn != ctx.peer_asn {
        build_ebgp_next_hop(path, ctx.local_next_hop, prefix)
    } else {
        build_ibgp_next_hop(path, ctx.local_next_hop, prefix)
    }
}

/// Build export attributes from a post-policy path. Returns None if next hop
/// cannot be built (cross-family routes without explicit next hop).
fn build_export_attrs(
    path: &Path,
    ctx: &PeerExportContext,
    prefix: &IpNetwork,
) -> Option<PathAttrs> {
    let is_ibgp = ctx.local_asn == ctx.peer_asn;
    let is_rs_client = ctx.rs_client;

    // RFC 4456: RR attributes (skip for RS clients)
    let (originator_id, cluster_list) = if is_rs_client {
        (None, Vec::new()) // RS doesn't add RR attributes
    } else {
        build_export_rr_attrs(path, ctx, is_ibgp)
    };

    Some(PathAttrs {
        origin: path.attrs.origin,
        as_path: build_export_as_path(path, ctx),
        next_hop: build_export_next_hop(path, ctx, prefix)?,
        source: path.attrs.source,
        local_pref: build_export_local_pref(path, ctx),
        med: build_export_med(path, ctx),
        atomic_aggregate: path.attrs.atomic_aggregate,
        aggregator: path.attrs.aggregator.clone(),
        communities: path.attrs.communities.clone(),
        extended_communities: build_export_extended_communities(path, ctx),
        large_communities: path.attrs.large_communities.clone(),
        unknown_attrs: path
            .attrs
            .unknown_attrs
            .iter()
            .filter(|attr| attr.is_unknown_transitive())
            .cloned()
            .collect(),
        originator_id,
        cluster_list,
    })
}

/// Build RR attributes for export (originator_id, cluster_list).
fn build_export_rr_attrs(
    path: &Path,
    ctx: &PeerExportContext,
    is_ibgp: bool,
) -> (Option<Ipv4Addr>, Vec<Ipv4Addr>) {
    // RFC 4456: RR attributes are non-transitive, strip for eBGP.
    // For iBGP: preserve when reflecting or when explicitly set.
    let preserve = is_ibgp && (path.source().is_ibgp() || path.originator_id().is_some());
    if !preserve {
        return (None, Vec::new());
    }

    // RFC 4456: When reflecting, set ORIGINATOR_ID and prepend cluster_id
    if path.source().is_ibgp() {
        let originator_id = Some(
            path.attrs
                .originator_id
                .unwrap_or_else(|| path.attrs.source.bgp_id().unwrap()),
        );
        let mut cluster_list = path.attrs.cluster_list.clone();
        cluster_list.insert(0, ctx.cluster_id);
        (originator_id, cluster_list)
    } else {
        (path.attrs.originator_id, path.attrs.cluster_list.clone())
    }
}

/// Apply per-prefix export filtering and attribute transformation for a peer.
/// Returns None if the path should be filtered (RR rules, source-peer, community, policy).
fn compute_export_path(
    prefix: &IpNetwork,
    path: &Arc<Path>,
    ctx: &PeerExportContext,
) -> Option<PrefixPath> {
    if !should_export_to_peer(path, ctx) {
        return None;
    }

    let mut exported = Path::clone(path);
    if !evaluate_export_policy(ctx.export_policies, prefix, &mut exported) {
        return None;
    }

    Some(PrefixPath::new(
        *prefix,
        Path {
            local_path_id: exported.local_path_id,
            remote_path_id: exported.remote_path_id,
            attrs: build_export_attrs(&exported, ctx, prefix)?,
            stale: false,
        },
    ))
}

/// Compute filtered and transformed routes for a peer
/// Returns Vec of (prefix, transformed_path) ready to advertise
///
/// RFC 4456 Route Reflector rules for iBGP routes to iBGP peers:
/// - Route from client -> reflect to all (clients + non-clients)
/// - Route from non-client -> reflect to clients only
/// - Sets ORIGINATOR_ID and prepends cluster_id to CLUSTER_LIST when reflecting
pub fn compute_routes_for_peer(
    to_announce: &[PrefixPath],
    ctx: &PeerExportContext,
) -> Vec<PrefixPath> {
    to_announce
        .iter()
        .filter_map(|PrefixPath { prefix, path }| compute_export_path(prefix, path, ctx))
        .collect()
}

/// Evaluate export policies. Returns true if accepted.
fn evaluate_export_policy(
    policies: &[Arc<crate::policy::Policy>],
    prefix: &IpNetwork,
    path: &mut Path,
) -> bool {
    for policy in policies {
        match policy.evaluate(prefix, path) {
            PolicyResult::Accept => return true,
            PolicyResult::Reject => return false,
            PolicyResult::Continue => continue,
        }
    }
    false
}

const CHUNK_SIZE: usize = 10_000;

/// Export all routes to a peer, filtering through export policy.
/// Returns the routes that were actually sent (post-policy).
pub fn export_all_routes_to_peer(
    routes: &[PrefixPath],
    ctx: &PeerExportContext,
    format: MessageFormat,
) -> Vec<PrefixPath> {
    let mut all_sent = Vec::new();
    for chunk in routes.chunks(CHUNK_SIZE) {
        let filtered = compute_routes_for_peer(chunk, ctx);
        send_batched_announcements(ctx, &filtered, format);
        all_sent.extend(filtered);
    }
    all_sent
}

/// Batch and send announcements to a peer.
fn send_batched_announcements(
    ctx: &PeerExportContext,
    to_send: &[PrefixPath],
    format: MessageFormat,
) {
    let batches = batch_announcements_by_path(to_send);

    for batch in batches {
        debug!(peer_addr = %ctx.peer_addr, local_pref = ?batch.path.local_pref(), med = ?batch.path.med(), "exporting route");

        let update_msg = UpdateMessage::new(&batch.path, batch.prefixes.clone(), format);

        // RFC 6793: Serialize UPDATE with ASN encoding based on peer capability
        // RFC 4271 Section 9.2: Check message size before sending
        let serialized = update_msg.serialize();
        if serialized.len() > MAX_MESSAGE_SIZE as usize {
            warn!(peer_addr = %ctx.peer_addr, prefix_count = batch.prefixes.len(), size = serialized.len(), max_size = MAX_MESSAGE_SIZE, "UPDATE message exceeds maximum size, not advertising");
            continue;
        }

        if let Err(e) = ctx.peer_tx.send(PeerOp::SendUpdate(serialized)) {
            error!(peer_addr = %ctx.peer_addr, error = %e, "failed to send UPDATE to peer");
        } else {
            info!(count = batch.prefixes.len(), peer_addr = %ctx.peer_addr, "propagated routes to peer");
        }
    }
}

/// Select paths for export to a peer, applying export policy.
/// For ADD-PATH peers, considers all paths. For normal peers, only the best path.
fn select_paths_for_export(
    prefix: &IpNetwork,
    send_add_path: bool,
    loc_rib: &LocRib,
    ctx: &PeerExportContext,
) -> Vec<PrefixPath> {
    let candidates: Vec<Arc<Path>> = if send_add_path {
        loc_rib.get_all_paths(prefix)
    } else {
        loc_rib.get_best_path(prefix).into_iter().cloned().collect()
    };

    candidates
        .iter()
        .filter_map(|path| compute_export_path(prefix, path, ctx))
        .collect()
}

/// Build withdrawal NLRIs for stale paths.
/// ADD-PATH mode: one withdrawal per path_id. Normal mode: one withdrawal if all paths removed.
fn build_withdrawals_for_prefix(
    prefix: IpNetwork,
    stale_paths: &[Arc<Path>],
    export_paths: &[PrefixPath],
    send_add_path: bool,
) -> Vec<Nlri> {
    if send_add_path {
        stale_paths
            .iter()
            .filter_map(|path| {
                path.local_path_id.map(|pid| Nlri {
                    prefix,
                    path_id: Some(pid),
                })
            })
            .collect()
    } else if export_paths.is_empty() && !stale_paths.is_empty() {
        vec![Nlri {
            prefix,
            path_id: None,
        }]
    } else {
        vec![]
    }
}

/// Export paths to a peer and update adj-rib-out.
///
/// For each changed prefix, computes the desired export state and diffs against
/// adj-rib-out. Withdrawals fall out naturally when a prefix has no exportable path
/// (filtered, withdrawn, or absent) but exists in adj-rib-out.
///
/// Unified for both ADD-PATH and non-ADD-PATH peers. The only difference is:
/// - Candidate selection: all paths (ADD-PATH) vs best path only
/// - Withdrawal NLRIs: path_id included (ADD-PATH) vs omitted
pub fn propagate_routes_to_peer(
    ctx: &PeerExportContext,
    delta: &RouteDelta,
    loc_rib: &LocRib,
    adj_rib_out: &mut AdjRibOut,
) {
    let mut announcements: Vec<PrefixPath> = Vec::new();
    let mut stale_entries: Vec<(IpNetwork, u32)> = Vec::new();
    let mut withdrawals = Vec::new();

    for afi in [Afi::Ipv4, Afi::Ipv6] {
        let afi_safi = AfiSafi::new(afi, Safi::Unicast);
        let send_add_path = ctx.send_format.add_path.contains(&afi_safi);
        let prefixes = if send_add_path {
            &delta.changed
        } else {
            &delta.best_changed
        };

        for prefix in prefixes {
            if !matches!(
                (prefix, afi),
                (IpNetwork::V4(_), Afi::Ipv4) | (IpNetwork::V6(_), Afi::Ipv6)
            ) {
                continue;
            }

            let export_paths = select_paths_for_export(prefix, send_add_path, loc_rib, ctx);
            let stale_paths = adj_rib_out.stale_paths(prefix, &export_paths);

            // Build wire withdrawals
            withdrawals.extend(build_withdrawals_for_prefix(
                *prefix,
                &stale_paths,
                &export_paths,
                send_add_path,
            ));

            announcements.extend(export_paths);

            // Track stale entries for adj-rib-out removal
            for path in &stale_paths {
                if let Some(pid) = path.local_path_id {
                    stale_entries.push((*prefix, pid));
                }
            }
        }
    }

    send_withdrawals(ctx, withdrawals, ctx.send_format);
    send_batched_announcements(ctx, &announcements, ctx.send_format);

    for (prefix, path_id) in &stale_entries {
        adj_rib_out.remove_path(prefix, *path_id);
    }
    for PrefixPath { prefix, path } in announcements {
        adj_rib_out.insert(prefix, path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg::AddPathMask;
    use crate::bgp::msg_update::Origin;
    use crate::net::{IpNetwork, Ipv4Net};
    use crate::policy::statement::Action;
    use crate::policy::Statement;
    use crate::rib::{PathAttrs, RouteSource};

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn test_bgp_id(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(1, 1, 1, last)
    }

    fn make_path(source: RouteSource, as_path: Vec<AsPathSegment>, next_hop: NextHopAddr) -> Path {
        Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            attrs: PathAttrs {
                origin: Origin::IGP,
                as_path,
                next_hop,
                source,
                local_pref: Some(100),
                med: None,
                atomic_aggregate: false,
                aggregator: None,
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
            },
        }
    }

    fn make_peer_export_ctx(
        local_asn: u32,
        peer_asn: u32,
        rs_client: bool,
    ) -> PeerExportContext<'static> {
        let (tx, _rx) = mpsc::unbounded_channel();
        // Leak the channel to get 'static lifetime for test
        let tx_static: &'static mpsc::UnboundedSender<PeerOp> = Box::leak(Box::new(tx));

        PeerExportContext {
            peer_addr: test_ip(1),
            peer_tx: tx_static,
            local_asn,
            peer_asn,
            local_next_hop: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            export_policies: &[],
            rr_client: false,
            rs_client,
            cluster_id: Ipv4Addr::new(1, 1, 1, 1),
            send_format: MessageFormat {
                use_4byte_asn: false,
                add_path: AddPathMask::NONE,
                is_ebgp: local_asn != peer_asn,
            },
        }
    }

    #[test]
    fn test_should_propagate_to_peer() {
        // Should propagate to established peer when no originating peer
        assert!(should_propagate_to_peer(
            test_ip(2),
            BgpState::Established,
            None
        ));

        // Should propagate to established peer when different from originating peer
        assert!(should_propagate_to_peer(
            test_ip(2),
            BgpState::Established,
            Some(test_ip(1))
        ));

        // Should NOT propagate to same peer that sent the route
        assert!(!should_propagate_to_peer(
            test_ip(2),
            BgpState::Established,
            Some(test_ip(2))
        ));

        // Should NOT propagate to non-established peer
        assert!(!should_propagate_to_peer(
            test_ip(3),
            BgpState::Connect,
            Some(test_ip(1))
        ));
    }

    #[test]
    fn test_build_export_as_path() {
        struct TestCase {
            name: &'static str,
            path_as_path: Vec<AsPathSegment>,
            path_source: RouteSource,
            local_asn: u32,
            peer_asn: u32,
            rs_client: bool,
            expected_as_path: Vec<Vec<u32>>, // List of ASN sequences
        }

        let test_cases = vec![
            TestCase {
                name: "local route to eBGP: prepend local ASN",
                path_as_path: vec![],
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                expected_as_path: vec![vec![65000]],
            },
            TestCase {
                name: "local route to iBGP: empty AS_PATH",
                path_as_path: vec![],
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                expected_as_path: vec![],
            },
            TestCase {
                name: "learned route to eBGP: prepend local ASN",
                path_as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                }],
                path_source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                expected_as_path: vec![vec![65000, 65001, 65002]],
            },
            TestCase {
                name: "learned route to iBGP: preserve AS_PATH",
                path_as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65003],
                }],
                path_source: RouteSource::Ibgp {
                    peer_ip: test_ip(2),
                    bgp_id: test_bgp_id(2),
                    rr_client: false,
                },
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                expected_as_path: vec![vec![65003]],
            },
            TestCase {
                name: "RS client: preserve AS_PATH (no prepending)",
                path_as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                }],
                path_source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                local_asn: 65000,
                peer_asn: 65003,
                rs_client: true,
                expected_as_path: vec![vec![65001, 65002]],
            },
            TestCase {
                name: "RS client with local route: preserve AS_PATH",
                path_as_path: vec![],
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: true,
                expected_as_path: vec![],
            },
        ];

        for test_case in test_cases {
            let path = make_path(
                test_case.path_source,
                test_case.path_as_path,
                NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
            );

            let ctx =
                make_peer_export_ctx(test_case.local_asn, test_case.peer_asn, test_case.rs_client);
            let result = build_export_as_path(&path, &ctx);

            // Convert result to Vec<Vec<u32>> for easier comparison
            let result_asns: Vec<Vec<u32>> =
                result.iter().map(|seg| seg.asn_list.clone()).collect();

            assert_eq!(
                result_asns, test_case.expected_as_path,
                "Test case '{}' failed: expected {:?}, got {:?}",
                test_case.name, test_case.expected_as_path, result_asns
            );
        }
    }

    #[test]
    fn test_batch_announcements_by_path() {
        let path_a = Arc::new(make_path(
            RouteSource::Local,
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65000],
            }],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        ));

        let path_b = Arc::new(make_path(
            RouteSource::Local,
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65000],
            }],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 2)),
        ));

        let p1 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 1, 0),
            prefix_length: 24,
        });
        let p2 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 2, 0),
            prefix_length: 24,
        });
        let p3 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 3, 0),
            prefix_length: 24,
        });
        let announcements = vec![
            PrefixPath {
                prefix: p1,
                path: Arc::clone(&path_a),
            },
            PrefixPath {
                prefix: p2,
                path: Arc::clone(&path_b),
            },
            PrefixPath {
                prefix: p3,
                path: Arc::clone(&path_a),
            },
        ];

        let mut actual = batch_announcements_by_path(&announcements);
        actual.sort_by_key(|batch| batch.prefixes.len());

        assert_eq!(
            actual,
            vec![
                AnnouncementBatch {
                    path: Arc::clone(&path_b),
                    prefixes: vec![p2],
                },
                AnnouncementBatch {
                    path: Arc::clone(&path_a),
                    prefixes: vec![p1, p3],
                },
            ]
        );
    }

    #[test]
    fn test_as_set_preservation_ebgp() {
        // Route with AS_SET should be preserved when exporting to eBGP
        let path_with_as_set = make_path(
            RouteSource::Ebgp {
                peer_ip: test_ip(1),
                bgp_id: test_bgp_id(1),
            },
            vec![
                AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                },
                AsPathSegment {
                    segment_type: AsPathSegmentType::AsSet,
                    segment_len: 3,
                    asn_list: vec![65003, 65004, 65005],
                },
            ],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        );

        // Export to eBGP peer should prepend local ASN and preserve AS_SET
        let ctx = make_peer_export_ctx(65000, 65100, false);
        let result = build_export_as_path(&path_with_as_set, &ctx);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[0].asn_list, vec![65000, 65001, 65002]);
        assert_eq!(result[1].segment_type, AsPathSegmentType::AsSet);
        assert_eq!(result[1].asn_list, vec![65003, 65004, 65005]);
    }

    #[test]
    fn test_as_set_first_segment_ebgp() {
        // Route starting with AS_SET should create new AS_SEQUENCE for local ASN
        let path_starting_with_as_set = make_path(
            RouteSource::Ebgp {
                peer_ip: test_ip(1),
                bgp_id: test_bgp_id(1),
            },
            vec![
                AsPathSegment {
                    segment_type: AsPathSegmentType::AsSet,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                },
                AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65003],
                },
            ],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        );

        // Export to eBGP should create new AS_SEQUENCE segment for local ASN
        let ctx = make_peer_export_ctx(65000, 65100, false);
        let result = build_export_as_path(&path_starting_with_as_set, &ctx);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[0].asn_list, vec![65000]);
        assert_eq!(result[1].segment_type, AsPathSegmentType::AsSet);
        assert_eq!(result[1].asn_list, vec![65001, 65002]);
        assert_eq!(result[2].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[2].asn_list, vec![65003]);
    }

    #[test]
    fn test_as_set_preservation_ibgp() {
        // Route with AS_SET should be preserved unchanged when exporting to iBGP
        let path_with_as_set = make_path(
            RouteSource::Ebgp {
                peer_ip: test_ip(1),
                bgp_id: test_bgp_id(1),
            },
            vec![
                AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                },
                AsPathSegment {
                    segment_type: AsPathSegmentType::AsSet,
                    segment_len: 3,
                    asn_list: vec![65003, 65004, 65005],
                },
            ],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        );

        // Export to iBGP peer should preserve AS_PATH unchanged
        let ctx = make_peer_export_ctx(65000, 65000, false);
        let result = build_export_as_path(&path_with_as_set, &ctx);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[0].asn_list, vec![65001, 65002]);
        assert_eq!(result[1].segment_type, AsPathSegmentType::AsSet);
        assert_eq!(result[1].asn_list, vec![65003, 65004, 65005]);
    }

    #[test]
    fn test_build_export_next_hop() {
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let prefix = "10.0.0.0/24".parse().unwrap();

        struct TestCase {
            name: &'static str,
            path_next_hop: NextHopAddr,
            path_source: RouteSource,
            local_asn: u32,
            peer_asn: u32,
            rs_client: bool,
            expected: NextHopAddr,
        }

        let test_cases = vec![
            TestCase {
                name: "iBGP: local route with unspecified NH -> set to local",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::UNSPECIFIED),
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                expected: NextHopAddr::Ipv4(router_id),
            },
            TestCase {
                name: "iBGP: local route with explicit NH -> preserve",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                expected: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
            },
            TestCase {
                name: "iBGP: learned route -> preserve NH",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 2, 1)),
                path_source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                expected: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 2, 1)),
            },
            TestCase {
                name: "eBGP: local route with unspecified NH -> set to local",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::UNSPECIFIED),
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                expected: NextHopAddr::Ipv4(router_id),
            },
            TestCase {
                name: "eBGP: local route with explicit NH -> rewrite to local",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                expected: NextHopAddr::Ipv4(router_id),
            },
            TestCase {
                name: "eBGP: learned route -> rewrite to local",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 3, 1)),
                path_source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                expected: NextHopAddr::Ipv4(router_id),
            },
            TestCase {
                name: "RS client: preserve original NH",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 3, 1)),
                path_source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: true,
                expected: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 3, 1)),
            },
        ];

        for test_case in test_cases {
            let path = make_path(test_case.path_source, vec![], test_case.path_next_hop);

            let ctx =
                make_peer_export_ctx(test_case.local_asn, test_case.peer_asn, test_case.rs_client);
            let result = build_export_next_hop(&path, &ctx, &prefix);

            assert_eq!(
                result,
                Some(test_case.expected),
                "Test case '{}' failed: expected {:?}, got {:?}",
                test_case.name,
                Some(test_case.expected),
                result
            );
        }
    }

    #[test]
    fn test_build_export_local_pref() {
        let path = Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            attrs: PathAttrs {
                origin: Origin::IGP,
                as_path: vec![],
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                source: RouteSource::Local,
                local_pref: Some(200),
                med: None,
                atomic_aggregate: false,
                aggregator: None,
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
            },
        };

        // iBGP: include LOCAL_PREF
        let ctx_ibgp = make_peer_export_ctx(65001, 65001, false);
        assert_eq!(build_export_local_pref(&path, &ctx_ibgp), Some(200));

        // eBGP: MUST NOT include LOCAL_PREF
        let ctx_ebgp = make_peer_export_ctx(65001, 65002, false);
        assert_eq!(build_export_local_pref(&path, &ctx_ebgp), None);
    }

    #[test]
    fn test_build_export_med() {
        struct TestCase {
            name: &'static str,
            as_path: Vec<AsPathSegment>,
            source: RouteSource,
            local_asn: u32,
            peer_asn: u32,
            rs_client: bool,
            expected_med: Option<u32>,
        }

        let test_cases = vec![
            // Local routes (empty AS_PATH)
            TestCase {
                name: "local route to iBGP",
                as_path: vec![],
                source: RouteSource::Local,
                local_asn: 65001,
                peer_asn: 65001,
                rs_client: false,
                expected_med: Some(50),
            },
            TestCase {
                name: "local route to eBGP",
                as_path: vec![],
                source: RouteSource::Local,
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: false,
                expected_med: Some(50),
            },
            TestCase {
                name: "local route to RS client",
                as_path: vec![],
                source: RouteSource::Local,
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: true,
                expected_med: Some(50),
            },
            // Local route with non-empty AS_PATH (defensive check for API misuse)
            TestCase {
                name: "local route with non-empty AS_PATH to eBGP",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65099], // Different from local_asn
                }],
                source: RouteSource::Local,
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: false,
                expected_med: Some(50), // Should send MED because source=Local
            },
            // Route from our AS
            TestCase {
                name: "route from our AS to iBGP",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65001,
                peer_asn: 65001,
                rs_client: false,
                expected_med: Some(50),
            },
            TestCase {
                name: "route from our AS to eBGP",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: false,
                expected_med: Some(50),
            },
            // Route from external AS (the critical bug case)
            TestCase {
                name: "route from external AS to iBGP",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65000],
                }],
                source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65001,
                peer_asn: 65001,
                rs_client: false,
                expected_med: Some(50),
            },
            TestCase {
                name: "route from external AS to eBGP (must strip MED)",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65000],
                }],
                source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: false,
                expected_med: None,
            },
            // AS_SET handling (RFC 4271 9.2.2.2)
            TestCase {
                name: "AS_SET as first segment to eBGP (must strip MED)",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSet,
                    segment_len: 2,
                    asn_list: vec![65001, 65003],
                }],
                source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: false,
                expected_med: None,
            },
            TestCase {
                name: "AS_SET as first segment to iBGP",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSet,
                    segment_len: 2,
                    asn_list: vec![65001, 65003],
                }],
                source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65001,
                peer_asn: 65001,
                rs_client: false,
                expected_med: Some(50),
            },
            // Route server transparency
            TestCase {
                name: "RS client always preserves MED",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65000],
                }],
                source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: true,
                expected_med: Some(50),
            },
        ];

        for test_case in test_cases {
            let path = Path {
                local_path_id: None,
                remote_path_id: None,
                stale: false,
                attrs: PathAttrs {
                    origin: Origin::IGP,
                    as_path: test_case.as_path,
                    next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                    source: test_case.source,
                    local_pref: Some(100),
                    med: Some(50),
                    atomic_aggregate: false,
                    aggregator: None,
                    communities: vec![],
                    extended_communities: vec![],
                    large_communities: vec![],
                    unknown_attrs: vec![],
                    originator_id: None,
                    cluster_list: vec![],
                },
            };

            let ctx =
                make_peer_export_ctx(test_case.local_asn, test_case.peer_asn, test_case.rs_client);
            let result = build_export_med(&path, &ctx);
            assert_eq!(
                result, test_case.expected_med,
                "Test case '{}' failed: expected {:?}, got {:?}",
                test_case.name, test_case.expected_med, result
            );
        }
    }

    #[test]
    fn test_send_announcements_oversized_message() {
        // RFC 4271 Section 9.2: Messages exceeding MAX_MESSAGE_SIZE must not be sent
        let (tx, mut rx) = mpsc::unbounded_channel();
        let peer_addr = test_ip(1);
        let policy =
            Arc::new(Policy::new("test".to_string()).with(Statement::new().then(Action::Accept)));

        // Create huge AS_PATH to make UPDATE message exceed 4096 bytes
        // Multiple AS_SEQUENCE segments with 255 ASNs each = ~4000 bytes total
        let mut as_path = vec![];
        for seg in 0..10 {
            let mut asn_list = vec![];
            for i in 0..255 {
                asn_list.push(65000 + ((seg * 255 + i) % 536));
            }
            as_path.push(AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 255,
                asn_list,
            });
        }

        let path = make_path(
            RouteSource::Ebgp {
                peer_ip: test_ip(2),
                bgp_id: test_bgp_id(2),
            },
            as_path,
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        );

        // Just one prefix, but huge AS_PATH should make UPDATE > 4096 bytes
        let prefix = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        });
        let routes = vec![PrefixPath {
            prefix,
            path: Arc::new(path),
        }];

        // Send announcements - should skip due to size
        let policies = vec![policy];
        let ctx = PeerExportContext {
            peer_addr,
            peer_tx: &tx,
            local_asn: 65000,
            peer_asn: 65001,
            local_next_hop: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            export_policies: &policies,
            rr_client: false,
            rs_client: false,
            cluster_id: Ipv4Addr::new(1, 1, 1, 1),
            send_format: MessageFormat {
                use_4byte_asn: false,
                add_path: AddPathMask::NONE,
                is_ebgp: false,
            },
        };
        let filtered = compute_routes_for_peer(&routes, &ctx);
        send_batched_announcements(
            &ctx,
            &filtered,
            MessageFormat {
                use_4byte_asn: false,
                add_path: AddPathMask::NONE,
                is_ebgp: false,
            },
        );

        // Verify no message was sent
        assert!(
            rx.try_recv().is_err(),
            "Oversized UPDATE should not be sent"
        );
    }

    #[test]
    fn test_should_filter_by_community_no_advertise() {
        use crate::bgp::msg_update_types::NO_ADVERTISE;

        let communities = vec![NO_ADVERTISE, 65001];
        assert!(should_filter_by_community(&communities, 65000, 65001));
        assert!(should_filter_by_community(&communities, 65000, 65000));
    }

    #[test]
    fn test_should_filter_by_community_no_export_ebgp() {
        use crate::bgp::msg_update_types::NO_EXPORT;

        let communities = vec![NO_EXPORT, 65001];
        assert!(
            should_filter_by_community(&communities, 65000, 65001),
            "NO_EXPORT should filter for eBGP"
        );
        assert!(
            !should_filter_by_community(&communities, 65000, 65000),
            "NO_EXPORT should not filter for iBGP"
        );
    }

    #[test]
    fn test_should_filter_by_community_no_export_subconfed_ebgp() {
        use crate::bgp::msg_update_types::NO_EXPORT_SUBCONFED;

        let communities = vec![NO_EXPORT_SUBCONFED];
        assert!(
            should_filter_by_community(&communities, 65000, 65001),
            "NO_EXPORT_SUBCONFED should filter for eBGP"
        );
        assert!(
            !should_filter_by_community(&communities, 65000, 65000),
            "NO_EXPORT_SUBCONFED should not filter for iBGP"
        );
    }

    #[test]
    fn test_should_filter_by_community_regular() {
        let communities = vec![65001, 65002];
        assert!(
            !should_filter_by_community(&communities, 65000, 65001),
            "Regular communities should not filter"
        );
        assert!(
            !should_filter_by_community(&communities, 65000, 65000),
            "Regular communities should not filter"
        );
    }

    #[test]
    fn test_build_export_extended_communities() {
        let transitive = 0x0002FDE800000064u64; // Transitive extended community
        let non_transitive = 0x4002FDE800000064u64; // Non-transitive extended community

        struct TestCase {
            name: &'static str,
            local_asn: u32,
            peer_asn: u32,
            rs_client: bool,
            expected: Vec<u64>,
        }

        let test_cases = vec![
            TestCase {
                name: "eBGP filters non-transitive",
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                expected: vec![transitive],
            },
            TestCase {
                name: "iBGP keeps all",
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                expected: vec![transitive, non_transitive],
            },
            TestCase {
                name: "RS client preserves all (including non-transitive)",
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: true,
                expected: vec![transitive, non_transitive],
            },
        ];

        for test_case in test_cases {
            let path = Path {
                local_path_id: None,
                remote_path_id: None,
                stale: false,
                attrs: PathAttrs {
                    origin: Origin::IGP,
                    as_path: vec![],
                    next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                    source: RouteSource::Local,
                    local_pref: None,
                    med: None,
                    atomic_aggregate: false,
                    aggregator: None,
                    communities: vec![],
                    extended_communities: vec![transitive, non_transitive],
                    large_communities: vec![],
                    unknown_attrs: vec![],
                    originator_id: None,
                    cluster_list: vec![],
                },
            };

            let ctx =
                make_peer_export_ctx(test_case.local_asn, test_case.peer_asn, test_case.rs_client);
            let result = build_export_extended_communities(&path, &ctx);
            assert_eq!(
                result, test_case.expected,
                "Test case '{}' failed: expected {:?}, got {:?}",
                test_case.name, test_case.expected, result
            );
        }
    }

    #[test]
    fn test_apply_rr_attributes() {
        let cluster_id = Ipv4Addr::new(1, 1, 1, 1);
        let peer_bgp_id = Ipv4Addr::new(2, 2, 2, 2);

        // Sets ORIGINATOR_ID from source when not present
        let mut path = make_path(
            RouteSource::Ibgp {
                peer_ip: test_ip(1),
                bgp_id: peer_bgp_id,
                rr_client: false,
            },
            vec![],
            NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        );
        let ctx = PeerExportContext {
            peer_addr: test_ip(2),
            peer_tx: &tokio::sync::mpsc::unbounded_channel().0,
            local_asn: 65000,
            peer_asn: 65000,
            local_next_hop: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            export_policies: &[],
            rr_client: false,
            rs_client: false,
            cluster_id,
            send_format: MessageFormat {
                use_4byte_asn: false,
                add_path: AddPathMask::NONE,
                is_ebgp: false,
            },
        };
        let (originator_id, cluster_list) = build_export_rr_attrs(&path, &ctx, true);
        assert_eq!(originator_id, Some(peer_bgp_id));
        assert_eq!(cluster_list, vec![cluster_id]);

        // Preserves existing ORIGINATOR_ID, prepends to CLUSTER_LIST
        let existing_originator = Ipv4Addr::new(3, 3, 3, 3);
        let existing_cluster = Ipv4Addr::new(4, 4, 4, 4);
        path.attrs.originator_id = Some(existing_originator);
        path.attrs.cluster_list = vec![existing_cluster];
        let (originator_id, cluster_list) = build_export_rr_attrs(&path, &ctx, true);
        assert_eq!(originator_id, Some(existing_originator));
        assert_eq!(cluster_list, vec![cluster_id, existing_cluster]);
    }
}
