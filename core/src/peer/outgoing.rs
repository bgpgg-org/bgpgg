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

use crate::bgp::msg::{Message, MAX_MESSAGE_SIZE};
use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin, UpdateMessage};
use crate::bgp::msg_update_types::{NO_ADVERTISE, NO_EXPORT, NO_EXPORT_SUBCONFED};
use crate::log::Logger;
use crate::net::IpNetwork;
use crate::peer::BgpState;
use crate::peer::PeerOp;
use crate::rib::{Path, RouteSource};
use crate::{debug, error, info, warn};

#[cfg(test)]
use crate::policy::Policy;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::mpsc;

/// A batch of route announcements sharing the same path attributes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AnnouncementBatch {
    pub path: Arc<Path>,
    pub prefixes: Vec<IpNetwork>,
}

/// Check if a route should be filtered based on well-known communities
/// RFC 1997 Section 3: Well-known communities
fn should_filter_by_community(communities: &[u32], local_asn: u16, peer_asn: u16) -> bool {
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
pub fn build_export_as_path(path: &Path, local_asn: u16, peer_asn: u16) -> Vec<AsPathSegment> {
    let is_ebgp = peer_asn != local_asn;

    if matches!(path.source, RouteSource::Local) && path.as_path.is_empty() {
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

        if let Some(first) = path.as_path.first() {
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
                new_segments.extend_from_slice(&path.as_path[1..]);
            } else {
                // First segment is AS_SET, create new AS_SEQUENCE segment
                new_segments.push(AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![local_asn],
                });
                // Preserve all segments including AS_SET
                new_segments.extend_from_slice(&path.as_path);
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
        path.as_path.clone()
    }
}

/// Determine LOCAL_PREF to include in UPDATE message
/// RFC 4271 Section 5.1.5:
/// - iBGP: LOCAL_PREF SHALL be included
/// - eBGP: LOCAL_PREF MUST NOT be included
pub fn build_export_local_pref(path: &Path, local_asn: u16, peer_asn: u16) -> Option<u32> {
    let is_ibgp = local_asn == peer_asn;
    if is_ibgp {
        path.local_pref
    } else {
        None
    }
}

/// Determine MULTI_EXIT_DISC (MED) to include in UPDATE message
/// RFC 4271 Section 5.1.4:
/// - iBGP: MED MAY be propagated to other BGP speakers within the same AS
/// - eBGP: MED MUST NOT be propagated to other neighboring ASes
pub fn build_export_med(path: &Path, local_asn: u16, peer_asn: u16) -> Option<u32> {
    let is_ibgp = local_asn == peer_asn;
    if is_ibgp {
        // Propagate MED over iBGP
        path.med
    } else if path.source.is_ebgp() {
        // Strip MED when re-advertising to eBGP a route learned from eBGP
        None
    } else {
        // Send MED when route is local or from iBGP
        path.med
    }
}

/// Send withdrawal messages to a peer
pub fn send_withdrawals_to_peer(
    peer_addr: IpAddr,
    peer_tx: &mpsc::UnboundedSender<PeerOp>,
    to_withdraw: &[IpNetwork],
    logger: &Arc<Logger>,
) {
    if to_withdraw.is_empty() {
        return;
    }

    let withdraw_msg = UpdateMessage::new_withdraw(to_withdraw.to_vec());
    if let Err(e) = peer_tx.send(PeerOp::SendUpdate(withdraw_msg)) {
        error!(logger, "failed to send WITHDRAW to peer", "peer_ip" => peer_addr.to_string(), "error" => e.to_string());
    } else {
        info!(logger, "propagated withdrawals to peer", "count" => to_withdraw.len(), "peer_ip" => peer_addr.to_string());
    }
}

/// Batching key: attributes that must match for announcements to be batched together
type BatchingKey = (Origin, Vec<AsPathSegment>, Ipv4Addr, bool, Vec<u32>);

/// Group announcements by path attributes to enable batching
/// Returns a vector of batches, where each batch contains a path and all prefixes sharing those attributes
pub(crate) fn batch_announcements_by_path(
    to_announce: &[(IpNetwork, Arc<Path>)],
) -> Vec<AnnouncementBatch> {
    let mut batches: HashMap<BatchingKey, AnnouncementBatch> = HashMap::new();

    for (prefix, path) in to_announce {
        let key = (
            path.origin,
            path.as_path.clone(),
            path.next_hop,
            path.atomic_aggregate,
            path.communities.clone(),
        );
        let batch = batches.entry(key).or_insert_with(|| AnnouncementBatch {
            path: Arc::clone(path),
            prefixes: Vec::new(),
        });
        batch.prefixes.push(*prefix);
    }

    batches.into_values().collect()
}

/// Build the NEXT_HOP for export to a peer
/// RFC 4271 Section 5.1.3:
/// - eBGP: "By default, the BGP speaker SHOULD use the IP address of the interface
///   that the speaker uses to establish the BGP connection to peer X in the NEXT_HOP attribute."
///   -> Always rewrite NEXT_HOP to self
/// - iBGP: Preserve NEXT_HOP from received routes; set to router ID for locally-originated
///   routes with unspecified NEXT_HOP
fn build_export_next_hop(
    path: &Path,
    local_router_id: Ipv4Addr,
    local_asn: u16,
    peer_asn: u16,
) -> Ipv4Addr {
    let is_ebgp = peer_asn != local_asn;

    if is_ebgp {
        // eBGP: always rewrite NEXT_HOP to self
        local_router_id
    } else {
        // iBGP: only rewrite locally-originated routes with unspecified NEXT_HOP
        if path.source.is_local() && path.next_hop.is_unspecified() {
            local_router_id
        } else {
            path.next_hop
        }
    }
}

/// Compute filtered and transformed routes for a peer
/// Returns Vec of (prefix, transformed_path) ready to advertise
pub fn compute_routes_for_peer(
    to_announce: &[(IpNetwork, Arc<Path>)],
    local_asn: u16,
    peer_asn: u16,
    local_router_id: Ipv4Addr,
    export_policies: &[Arc<crate::policy::Policy>],
) -> Vec<(IpNetwork, Path)> {
    // Apply well-known community filtering BEFORE export policy
    // RFC 1997: NO_ADVERTISE, NO_EXPORT, NO_EXPORT_SUBCONFED
    to_announce
        .iter()
        .filter_map(|(prefix, path)| {
            if should_filter_by_community(&path.communities, local_asn, peer_asn) {
                return None;
            }
            // Clone inner Path for policy mutation
            let mut path_mut = (**path).clone();

            // Evaluate export policies in order until Accept/Reject
            let accepted = {
                let mut result = false;
                for policy in export_policies {
                    match policy.evaluate(prefix, &mut path_mut) {
                        crate::policy::PolicyResult::Accept => {
                            result = true;
                            break;
                        }
                        crate::policy::PolicyResult::Reject => {
                            result = false;
                            break;
                        }
                        crate::policy::PolicyResult::Continue => continue,
                    }
                }
                result
            };

            if !accepted {
                return None;
            }

            // Apply export attribute transformations
            path_mut.as_path = build_export_as_path(&path_mut, local_asn, peer_asn);
            path_mut.next_hop =
                build_export_next_hop(&path_mut, local_router_id, local_asn, peer_asn);
            path_mut.local_pref = build_export_local_pref(&path_mut, local_asn, peer_asn);
            path_mut.med = build_export_med(&path_mut, local_asn, peer_asn);

            Some((*prefix, path_mut))
        })
        .collect()
}

/// Send route announcements to a peer
/// Batches prefixes that share the same path attributes into single UPDATE messages
#[allow(clippy::too_many_arguments)]
pub fn send_announcements_to_peer(
    peer_addr: IpAddr,
    peer_tx: &mpsc::UnboundedSender<PeerOp>,
    to_announce: &[(IpNetwork, Arc<Path>)],
    local_asn: u16,
    peer_asn: u16,
    local_router_id: Ipv4Addr,
    export_policies: &[Arc<crate::policy::Policy>],
    logger: &Arc<Logger>,
) {
    if to_announce.is_empty() {
        return;
    }

    // Compute filtered and transformed routes
    let filtered = compute_routes_for_peer(
        to_announce,
        local_asn,
        peer_asn,
        local_router_id,
        export_policies,
    );

    if filtered.is_empty() {
        return;
    }

    // Convert back to Arc<Path> for batching
    let filtered_arc: Vec<(IpNetwork, Arc<Path>)> = filtered
        .into_iter()
        .map(|(prefix, path)| (prefix, Arc::new(path)))
        .collect();

    let batches = batch_announcements_by_path(&filtered_arc);

    // Send one UPDATE message per unique set of path attributes
    for batch in batches {
        // Attributes already transformed in compute_routes_for_peer
        let as_path_segments = batch.path.as_path.clone();
        let next_hop = batch.path.next_hop;
        let local_pref = batch.path.local_pref;
        let med = batch.path.med;
        let atomic_aggregate = batch.path.atomic_aggregate;

        // RFC 4271 Section 6.3: only propagate transitive unknown attributes
        let unknown_attrs: Vec<_> = batch
            .path
            .unknown_attrs
            .iter()
            .filter(|attr| attr.is_unknown_transitive())
            .cloned()
            .collect();

        debug!(logger, "exporting route",
            "peer_ip" => peer_addr.to_string(),
            "path_local_pref" => format!("{:?}", batch.path.local_pref),
            "export_local_pref" => format!("{:?}", local_pref),
            "path_med" => format!("{:?}", batch.path.med),
            "export_med" => format!("{:?}", med));

        let update_msg = UpdateMessage::new(
            batch.path.origin,
            as_path_segments,
            next_hop,
            batch.prefixes.clone(),
            local_pref,
            med,
            atomic_aggregate,
            batch.path.communities.clone(),
            batch.path.extended_communities.clone(),
            unknown_attrs,
        );

        // RFC 4271 Section 9.2: Check message size before sending
        let serialized = update_msg.serialize();
        if serialized.len() > MAX_MESSAGE_SIZE as usize {
            warn!(logger, "UPDATE message exceeds maximum size, not advertising",
                "peer_ip" => peer_addr.to_string(),
                "prefix_count" => batch.prefixes.len(),
                "size" => serialized.len(),
                "max_size" => MAX_MESSAGE_SIZE);
            continue;
        }

        if let Err(e) = peer_tx.send(PeerOp::SendUpdate(update_msg)) {
            error!(logger, "failed to send UPDATE to peer", "peer_ip" => peer_addr.to_string(), "error" => e.to_string());
        } else {
            info!(logger, "propagated routes to peer", "count" => batch.prefixes.len(), "peer_ip" => peer_addr.to_string());
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
    use crate::rib::RouteSource;
    use std::collections::HashSet;

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn make_path(source: RouteSource, as_path: Vec<AsPathSegment>, next_hop: Ipv4Addr) -> Path {
        Path {
            origin: Origin::IGP,
            as_path,
            next_hop,
            source,
            local_pref: Some(100),
            med: None,
            atomic_aggregate: false,
            communities: vec![],
            extended_communities: vec![],
            unknown_attrs: vec![],
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
        let local_path = make_path(RouteSource::Local, vec![], Ipv4Addr::new(192, 168, 1, 1));

        let ebgp_path = make_path(
            RouteSource::Ebgp(test_ip(1)),
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 2,
                asn_list: vec![65001, 65002],
            }],
            Ipv4Addr::new(192, 168, 1, 2),
        );

        let ibgp_path = make_path(
            RouteSource::Ibgp(test_ip(2)),
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65003],
            }],
            Ipv4Addr::new(192, 168, 1, 3),
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
            Ipv4Addr::new(192, 168, 1, 1),
        ));

        let path_b = Arc::new(make_path(
            RouteSource::Local,
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65000],
            }],
            Ipv4Addr::new(192, 168, 1, 2),
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

        let actual = HashSet::from_iter(batch_announcements_by_path(&announcements));

        let expected = HashSet::from([
            AnnouncementBatch {
                path: path_a,
                prefixes: vec![p1, p3],
            },
            AnnouncementBatch {
                path: path_b,
                prefixes: vec![p2],
            },
        ]);

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_as_set_preservation_ebgp() {
        // Route with AS_SET should be preserved when exporting to eBGP
        let path_with_as_set = make_path(
            RouteSource::Ebgp(test_ip(1)),
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
            Ipv4Addr::new(192, 168, 1, 1),
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
            RouteSource::Ebgp(test_ip(1)),
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
            Ipv4Addr::new(192, 168, 1, 1),
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
            RouteSource::Ebgp(test_ip(1)),
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
            Ipv4Addr::new(192, 168, 1, 1),
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

        // iBGP: Local route with 0.0.0.0 -> rewrite to router ID
        let local_path = make_path(RouteSource::Local, vec![], Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            build_export_next_hop(&local_path, router_id, local_asn, peer_asn_ibgp),
            router_id
        );

        // iBGP: Local route with explicit next hop -> preserve
        let local_explicit = make_path(RouteSource::Local, vec![], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            build_export_next_hop(&local_explicit, router_id, local_asn, peer_asn_ibgp),
            Ipv4Addr::new(192, 168, 1, 1)
        );

        // iBGP: Learned route -> preserve NEXT_HOP
        let ibgp_path = make_path(
            RouteSource::Ibgp(test_ip(1)),
            vec![],
            Ipv4Addr::new(192, 168, 2, 1),
        );
        assert_eq!(
            build_export_next_hop(&ibgp_path, router_id, local_asn, peer_asn_ibgp),
            Ipv4Addr::new(192, 168, 2, 1)
        );

        // eBGP: Learned route -> rewrite to self
        let ebgp_path = make_path(
            RouteSource::Ebgp(test_ip(1)),
            vec![],
            Ipv4Addr::new(192, 168, 3, 1),
        );
        assert_eq!(
            build_export_next_hop(&ebgp_path, router_id, local_asn, peer_asn_ebgp),
            router_id
        );

        // eBGP: Local route with 0.0.0.0 -> rewrite to router ID
        assert_eq!(
            build_export_next_hop(&local_path, router_id, local_asn, peer_asn_ebgp),
            router_id
        );

        // eBGP: Local route with explicit next hop -> rewrite to router ID
        assert_eq!(
            build_export_next_hop(&local_explicit, router_id, local_asn, peer_asn_ebgp),
            router_id
        );
    }

    #[test]
    fn test_build_export_local_pref() {
        let path = Path {
            origin: Origin::IGP,
            as_path: vec![],
            next_hop: Ipv4Addr::new(192, 168, 1, 1),
            source: RouteSource::Local,
            local_pref: Some(200),
            med: None,
            atomic_aggregate: false,
            communities: vec![],
            extended_communities: vec![],
            unknown_attrs: vec![],
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
            origin: Origin::IGP,
            as_path: vec![],
            next_hop: Ipv4Addr::new(192, 168, 1, 1),
            source: RouteSource::Ebgp(test_ip(1)),
            local_pref: Some(100),
            med: Some(50),
            atomic_aggregate: false,
            communities: vec![],
            extended_communities: vec![],
            unknown_attrs: vec![],
        };

        // iBGP: propagate MED
        assert_eq!(build_export_med(&ebgp_path, 65001, 65001), Some(50));

        // eBGP: strip MED (route from eBGP must not be sent to other AS)
        assert_eq!(build_export_med(&ebgp_path, 65001, 65002), None);

        // Local route with MED
        let local_path = Path {
            origin: Origin::IGP,
            as_path: vec![],
            next_hop: Ipv4Addr::new(192, 168, 1, 1),
            source: RouteSource::Local,
            local_pref: Some(100),
            med: Some(50),
            atomic_aggregate: false,
            communities: vec![],
            extended_communities: vec![],
            unknown_attrs: vec![],
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
            RouteSource::Ebgp(test_ip(2)),
            as_path,
            Ipv4Addr::new(192, 168, 1, 1),
        );

        // Just one prefix, but huge AS_PATH should make UPDATE > 4096 bytes
        let prefix = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        });
        let routes = vec![(prefix, Arc::new(path))];

        // Send announcements - should skip due to size
        let logger = Arc::new(Logger::default());
        let policies = vec![policy];
        send_announcements_to_peer(
            peer_addr,
            &tx,
            &routes,
            65000,
            65001,
            Ipv4Addr::new(1, 1, 1, 1),
            &policies,
            &logger,
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
}
