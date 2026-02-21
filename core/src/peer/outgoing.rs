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
use crate::log::{debug, error, info, warn};
use crate::net::IpNetwork;
use crate::peer::BgpState;
use crate::peer::PeerOp;
use crate::policy::PolicyResult;
use crate::rib::rib_loc::LocRib;
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
    pub peer_supports_4byte_asn: bool,
    pub rr_client: bool,
    pub cluster_id: Ipv4Addr,
    pub add_path_send: bool,
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
/// Preserves AS_SET segments during propagation
pub fn build_export_as_path(path: &Path, local_asn: u32, peer_asn: u32) -> Vec<AsPathSegment> {
    let is_ebgp = peer_asn != local_asn;

    if matches!(path.source(), RouteSource::Local) && path.as_path().is_empty() {
        // Truly locally originated routes (empty AS_PATH)
        if is_ebgp {
            // eBGP: AS_PATH = [local_asn]
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![local_asn],
            }]
        } else {
            // iBGP: AS_PATH = [] (empty)
            vec![]
        }
    } else if is_ebgp {
        // Learned routes to eBGP: prepend local ASN to first AS_SEQUENCE
        // If first segment is AS_SEQUENCE, prepend to it; otherwise create new segment
        let mut new_segments = Vec::new();

        if let Some(first) = path.as_path().first() {
            if first.segment_type == AsPathSegmentType::AsSequence {
                // Prepend to existing AS_SEQUENCE
                let mut new_asn_list = vec![local_asn];
                new_asn_list.extend_from_slice(&first.asn_list);
                new_segments.push(AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: new_asn_list.len() as u8,
                    asn_list: new_asn_list,
                });
                // Add remaining segments unchanged
                new_segments.extend_from_slice(&path.as_path()[1..]);
            } else {
                // First segment is AS_SET, create new AS_SEQUENCE segment
                new_segments.push(AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![local_asn],
                });
                // Preserve all segments including AS_SET
                new_segments.extend_from_slice(path.as_path());
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
    } else {
        // Learned routes to iBGP: do not modify AS_PATH, preserve all segments
        path.as_path().clone()
    }
}

/// Determine LOCAL_PREF to include in UPDATE message
/// RFC 4271 Section 5.1.5:
/// - iBGP: LOCAL_PREF SHALL be included
/// - eBGP: LOCAL_PREF MUST NOT be included
pub fn build_export_local_pref(path: &Path, local_asn: u32, peer_asn: u32) -> Option<u32> {
    let is_ibgp = local_asn == peer_asn;
    if is_ibgp {
        path.local_pref()
    } else {
        None
    }
}

/// Determine MULTI_EXIT_DISC (MED) to include in UPDATE message
/// RFC 4271 Section 5.1.4:
/// - iBGP: MED MAY be propagated to other BGP speakers within the same AS
/// - eBGP: MED MUST NOT be propagated to other neighboring ASes
pub fn build_export_med(path: &Path, local_asn: u32, peer_asn: u32) -> Option<u32> {
    let is_ibgp = local_asn == peer_asn;
    if is_ibgp {
        // Propagate MED over iBGP
        path.med()
    } else if path.source().is_ebgp() {
        // Strip MED when re-advertising to eBGP a route learned from eBGP
        None
    } else {
        // Send MED when route is local or from iBGP
        path.med()
    }
}

/// Filter extended communities for export to peer
/// RFC 4360: Non-transitive extended communities (bit 6 = 1) must be filtered when advertising to eBGP peers
pub fn build_export_extended_communities(path: &Path, local_asn: u32, peer_asn: u32) -> Vec<u64> {
    let is_ebgp = local_asn != peer_asn;

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
fn send_withdrawals(
    ctx: &PeerExportContext,
    withdrawn: Vec<Nlri>,
    format: MessageFormat,
) {
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

    for (prefix, path) in to_announce {
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
fn build_export_next_hop(
    path: &Path,
    local_next_hop: IpAddr,
    local_asn: u32,
    peer_asn: u32,
    prefix: &IpNetwork,
) -> Option<NextHopAddr> {
    if local_asn != peer_asn {
        build_ebgp_next_hop(path, local_next_hop, prefix)
    } else {
        build_ibgp_next_hop(path, local_next_hop, prefix)
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

    // RFC 4456: RR attributes
    let (originator_id, cluster_list) = build_export_rr_attrs(path, ctx, is_ibgp);

    Some(PathAttrs {
        origin: path.attrs.origin,
        as_path: build_export_as_path(path, ctx.local_asn, ctx.peer_asn),
        next_hop: build_export_next_hop(path, ctx.local_next_hop, ctx.local_asn, ctx.peer_asn, prefix)?,
        source: path.attrs.source,
        local_pref: build_export_local_pref(path, ctx.local_asn, ctx.peer_asn),
        med: build_export_med(path, ctx.local_asn, ctx.peer_asn),
        atomic_aggregate: path.attrs.atomic_aggregate,
        aggregator: path.attrs.aggregator.clone(),
        communities: path.attrs.communities.clone(),
        extended_communities: build_export_extended_communities(path, ctx.local_asn, ctx.peer_asn),
        large_communities: path.attrs.large_communities.clone(),
        unknown_attrs: path.attrs.unknown_attrs.iter()
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
            path.attrs.originator_id.unwrap_or_else(|| path.attrs.source.bgp_id().unwrap()),
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
) -> Option<Path> {
    if !should_export_to_peer(path, ctx) {
        return None;
    }

    let mut exported = Path::clone(path);
    if !evaluate_export_policy(ctx.export_policies, prefix, &mut exported) {
        return None;
    }

    Some(Path {
        local_path_id: exported.local_path_id,
        remote_path_id: exported.remote_path_id,
        attrs: build_export_attrs(&exported, ctx, prefix)?,
        stale: false,
    })
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
        .filter_map(|(prefix, path)| {
            compute_export_path(prefix, path, ctx).map(|exported| (*prefix, Arc::new(exported)))
        })
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

/// Compute ADD-PATH diff: compare loc-rib paths against adj-rib-out for changed prefixes.
/// Returns (to_announce, to_withdraw) where withdrawals are (prefix, path_id) pairs for
/// paths present in adj-rib-out but no longer in loc-rib.
pub fn build_addpath_updates(
    changed: &[IpNetwork],
    loc_rib: &LocRib,
    adj_rib_out: &AdjRibOut,
) -> (Vec<PrefixPath>, Vec<(IpNetwork, u32)>) {
    let mut to_announce = Vec::new();
    let mut to_withdraw = Vec::new();

    for prefix in changed {
        let current_paths = loc_rib.get_all_paths(prefix);
        let adj_path_ids = adj_rib_out.path_ids_for_prefix(prefix);

        for path in &current_paths {
            to_announce.push((*prefix, Arc::clone(path)));
        }

        for pid in &adj_path_ids {
            if !current_paths.iter().any(|p| p.local_path_id == Some(*pid)) {
                to_withdraw.push((*prefix, *pid));
            }
        }
    }

    (to_announce, to_withdraw)
}

/// Batch and send announcements to a peer.
pub fn send_batched_announcements(
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

/// Export paths to a peer and update adj-rib-out.
///
/// For each changed prefix, computes the desired export state and diffs against
/// adj-rib-out. Withdrawals fall out naturally when a prefix has no exportable path
/// (filtered, withdrawn, or absent) but exists in adj-rib-out.
pub fn propagate_routes_to_peer(
    ctx: &PeerExportContext,
    changed_prefixes: &[IpNetwork],
    loc_rib: &LocRib,
    adj_rib_out: &mut AdjRibOut,
) {
    let format = MessageFormat {
        use_4byte_asn: ctx.peer_supports_4byte_asn,
        add_path: ctx.add_path_send,
    };

    if ctx.add_path_send {
        let (addpath_to_announce, addpath_to_withdraw) =
            build_addpath_updates(changed_prefixes, loc_rib, adj_rib_out);

        let withdrawn: Vec<Nlri> = addpath_to_withdraw
            .iter()
            .map(|(prefix, path_id)| Nlri {
                prefix: *prefix,
                path_id: Some(*path_id),
            })
            .collect();
        send_withdrawals(ctx, withdrawn, format);

        let filtered = compute_routes_for_peer(&addpath_to_announce, ctx);
        send_batched_announcements(ctx, &filtered, format);

        for (prefix, path_id) in &addpath_to_withdraw {
            adj_rib_out.remove_path(prefix, *path_id);
        }
        for (prefix, path) in filtered {
            adj_rib_out.insert(prefix, path);
        }
    } else {
        let mut to_announce = Vec::new();
        let mut to_withdraw = Vec::new();

        for prefix in changed_prefixes {
            let desired = loc_rib
                .get_best_path(prefix)
                .and_then(|best| compute_export_path(prefix, best, ctx));

            match (desired, adj_rib_out.has_prefix(prefix)) {
                (Some(path), _) => to_announce.push((*prefix, Arc::new(path))),
                (None, true) => to_withdraw.push(*prefix),
                (None, false) => {}
            }
        }

        let withdrawn: Vec<Nlri> = to_withdraw
            .iter()
            .map(|prefix| Nlri {
                prefix: *prefix,
                path_id: None,
            })
            .collect();
        send_withdrawals(ctx, withdrawn, format);
        send_batched_announcements(ctx, &to_announce, format);

        for prefix in &to_withdraw {
            adj_rib_out.remove_prefix(prefix);
        }
        for (prefix, path) in to_announce {
            adj_rib_out.replace(prefix, path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        // Local routes are stored with empty AS_PATH
        let local_path = make_path(
            RouteSource::Local,
            vec![],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        );

        let ebgp_path = make_path(
            RouteSource::Ebgp {
                peer_ip: test_ip(1),
                bgp_id: test_bgp_id(1),
            },
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 2,
                asn_list: vec![65001, 65002],
            }],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 2)),
        );

        let ibgp_path = make_path(
            RouteSource::Ibgp {
                peer_ip: test_ip(2),
                bgp_id: test_bgp_id(2),
                rr_client: false,
            },
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65003],
            }],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 3)),
        );

        // Local route to eBGP peer: AS_PATH = [local_asn]
        let result = build_export_as_path(&local_path, 65000, 65001);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[0].asn_list, vec![65000]);

        // Local route to iBGP peer: AS_PATH = [] (empty, no segments)
        let result = build_export_as_path(&local_path, 65000, 65000);
        assert_eq!(result.len(), 0);

        // Learned route to eBGP peer: prepend local ASN
        let result = build_export_as_path(&ebgp_path, 65000, 65001);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[0].asn_list, vec![65000, 65001, 65002]);

        // Learned route to iBGP peer: do NOT modify AS_PATH
        let result = build_export_as_path(&ibgp_path, 65000, 65000);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[0].asn_list, vec![65003]);
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
            (p1, Arc::clone(&path_a)),
            (p2, Arc::clone(&path_b)),
            (p3, Arc::clone(&path_a)),
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
        let result = build_export_as_path(&path_with_as_set, 65000, 65100);
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
        let result = build_export_as_path(&path_starting_with_as_set, 65000, 65100);
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
        let result = build_export_as_path(&path_with_as_set, 65000, 65000);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[0].asn_list, vec![65001, 65002]);
        assert_eq!(result[1].segment_type, AsPathSegmentType::AsSet);
        assert_eq!(result[1].asn_list, vec![65003, 65004, 65005]);
    }

    #[test]
    fn test_build_export_next_hop() {
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let local_asn = 65000;
        let peer_asn_ebgp = 65001;
        let peer_asn_ibgp = 65000;
        let prefix = "10.0.0.0/24".parse().unwrap();

        let local_path = make_path(
            RouteSource::Local,
            vec![],
            NextHopAddr::Ipv4(Ipv4Addr::UNSPECIFIED),
        );
        let local_explicit = make_path(
            RouteSource::Local,
            vec![],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        );
        let ibgp_learned = make_path(
            RouteSource::Ibgp {
                peer_ip: test_ip(1),
                bgp_id: test_bgp_id(1),
                rr_client: false,
            },
            vec![],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 2, 1)),
        );
        let ebgp_learned = make_path(
            RouteSource::Ebgp {
                peer_ip: test_ip(1),
                bgp_id: test_bgp_id(1),
            },
            vec![],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 3, 1)),
        );

        // iBGP: Local route with unspecified next hop -> set to local address
        assert_eq!(
            build_export_next_hop(
                &local_path,
                IpAddr::V4(router_id),
                local_asn,
                peer_asn_ibgp,
                &prefix,
            ),
            Some(NextHopAddr::Ipv4(router_id))
        );

        // iBGP: Local route with explicit next hop -> preserve
        assert_eq!(
            build_export_next_hop(
                &local_explicit,
                IpAddr::V4(router_id),
                local_asn,
                peer_asn_ibgp,
                &prefix,
            ),
            Some(NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)))
        );

        // iBGP: Learned route -> preserve next hop
        assert_eq!(
            build_export_next_hop(
                &ibgp_learned,
                IpAddr::V4(router_id),
                local_asn,
                peer_asn_ibgp,
                &prefix,
            ),
            Some(NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 2, 1)))
        );

        // eBGP: Local route with unspecified next hop -> set to local address
        assert_eq!(
            build_export_next_hop(
                &local_path,
                IpAddr::V4(router_id),
                local_asn,
                peer_asn_ebgp,
                &prefix,
            ),
            Some(NextHopAddr::Ipv4(router_id))
        );

        // eBGP: Local route with explicit next hop (same AF) -> rewrite to local address
        assert_eq!(
            build_export_next_hop(
                &local_explicit,
                IpAddr::V4(router_id),
                local_asn,
                peer_asn_ebgp,
                &prefix,
            ),
            Some(NextHopAddr::Ipv4(router_id))
        );

        // eBGP: Learned route -> rewrite to local address
        assert_eq!(
            build_export_next_hop(
                &ebgp_learned,
                IpAddr::V4(router_id),
                local_asn,
                peer_asn_ebgp,
                &prefix,
            ),
            Some(NextHopAddr::Ipv4(router_id))
        );
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
        assert_eq!(build_export_local_pref(&path, 65001, 65001), Some(200));

        // eBGP: MUST NOT include LOCAL_PREF
        assert_eq!(build_export_local_pref(&path, 65001, 65002), None);
    }

    #[test]
    fn test_build_export_med() {
        // Route from eBGP with MED
        let ebgp_path = Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            attrs: PathAttrs {
                origin: Origin::IGP,
                as_path: vec![],
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
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

        // iBGP: propagate MED
        assert_eq!(build_export_med(&ebgp_path, 65001, 65001), Some(50));

        // eBGP: strip MED (route from eBGP must not be sent to other AS)
        assert_eq!(build_export_med(&ebgp_path, 65001, 65002), None);

        // Local route with MED
        let local_path = Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            attrs: PathAttrs {
                origin: Origin::IGP,
                as_path: vec![],
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                source: RouteSource::Local,
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

        // eBGP: send MED for local route
        assert_eq!(build_export_med(&local_path, 65001, 65002), Some(50));
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
        let routes = vec![(prefix, Arc::new(path))];

        // Send announcements - should skip due to size
        let policies = vec![policy];
        let ctx = PeerExportContext {
            peer_addr,
            peer_tx: &tx,
            local_asn: 65000,
            peer_asn: 65001,
            local_next_hop: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            export_policies: &policies,
            peer_supports_4byte_asn: false,
            rr_client: false,
            cluster_id: Ipv4Addr::new(1, 1, 1, 1),
            add_path_send: false,
        };
        let filtered = compute_routes_for_peer(&routes, &ctx);
        send_batched_announcements(
            &ctx,
            &filtered,
            MessageFormat {
                use_4byte_asn: false,
                add_path: false,
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
        let transitive = 0x0002FDE800000064u64;
        let non_transitive = 0x4002FDE800000064u64;

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

        // eBGP: filters non-transitive
        assert_eq!(
            build_export_extended_communities(&path, 65000, 65001),
            vec![transitive]
        );

        // iBGP: keeps all
        assert_eq!(
            build_export_extended_communities(&path, 65000, 65000),
            vec![transitive, non_transitive]
        );
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
            peer_supports_4byte_asn: false,
            rr_client: false,
            cluster_id,
            add_path_send: false,
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
