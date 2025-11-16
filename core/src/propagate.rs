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

use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin, UpdateMessage};
use crate::bgp::utils::IpNetwork;
use crate::fsm::BgpState;
use crate::peer::PeerOp;
use crate::rib::{Path, RouteSource};
use crate::{error, info};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

/// A batch of route announcements sharing the same path attributes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AnnouncementBatch {
    pub path: Path,
    pub prefixes: Vec<IpNetwork>,
}

/// Check if we should propagate routes to this peer
pub fn should_propagate_to_peer(
    peer_addr: &str,
    peer_state: BgpState,
    originating_peer: &Option<String>,
) -> bool {
    // Skip the peer that sent us the original update (if any)
    if let Some(ref orig_peer) = originating_peer {
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

/// Send withdrawal messages to a peer
pub fn send_withdrawals_to_peer(
    peer_addr: &str,
    message_tx: &mpsc::UnboundedSender<PeerOp>,
    to_withdraw: &[IpNetwork],
) {
    if to_withdraw.is_empty() {
        return;
    }

    let withdraw_msg = UpdateMessage::new_withdraw(to_withdraw.to_vec());
    if let Err(e) = message_tx.send(PeerOp::SendUpdate(withdraw_msg)) {
        error!("failed to send WITHDRAW to peer", "peer_ip" => peer_addr, "error" => e.to_string());
    } else {
        info!("propagated withdrawals to peer", "count" => to_withdraw.len(), "peer_ip" => peer_addr);
    }
}

/// Group announcements by path attributes to enable batching
/// Returns a vector of batches, where each batch contains a path and all prefixes sharing those attributes
fn batch_announcements_by_path(to_announce: &[(IpNetwork, Path)]) -> Vec<AnnouncementBatch> {
    let mut batches: HashMap<(Origin, Vec<AsPathSegment>, Ipv4Addr), AnnouncementBatch> =
        HashMap::new();

    for (prefix, path) in to_announce {
        let key = (path.origin, path.as_path.clone(), path.next_hop);
        let batch = batches.entry(key).or_insert_with(|| AnnouncementBatch {
            path: path.clone(),
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
        if path.is_local() && path.next_hop.is_unspecified() {
            local_router_id
        } else {
            path.next_hop
        }
    }
}

/// Send route announcements to a peer
/// Batches prefixes that share the same path attributes into single UPDATE messages
pub fn send_announcements_to_peer(
    peer_addr: &str,
    message_tx: &mpsc::UnboundedSender<PeerOp>,
    to_announce: &[(IpNetwork, Path)],
    local_asn: u16,
    peer_asn: u16,
    local_router_id: Ipv4Addr,
) {
    if to_announce.is_empty() {
        return;
    }

    let is_ibgp = peer_asn == local_asn;
    let batches = batch_announcements_by_path(to_announce);

    // Send one UPDATE message per unique set of path attributes
    for batch in batches {
        // iBGP split horizon: skip routes learned via iBGP when sending to iBGP peers
        if is_ibgp && batch.path.source.is_ibgp() {
            continue;
        }
        let prefix_count = batch.prefixes.len();
        let as_path_segments = build_export_as_path(&batch.path, local_asn, peer_asn);
        let next_hop = build_export_next_hop(&batch.path, local_router_id, local_asn, peer_asn);

        let update_msg = UpdateMessage::new(
            batch.path.origin,
            as_path_segments,
            next_hop,
            batch.prefixes,
        );

        if let Err(e) = message_tx.send(PeerOp::SendUpdate(update_msg)) {
            error!("failed to send UPDATE to peer", "peer_ip" => peer_addr, "error" => e.to_string());
        } else {
            info!("propagated routes to peer", "count" => prefix_count, "peer_ip" => peer_addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_update::Origin;
    use crate::bgp::utils::{IpNetwork, Ipv4Net};
    use crate::rib::RouteSource;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    fn make_path(source: RouteSource, as_path: Vec<AsPathSegment>, next_hop: Ipv4Addr) -> Path {
        Path {
            origin: Origin::IGP,
            as_path,
            next_hop,
            source,
            local_pref: Some(100),
            med: None,
        }
    }

    #[test]
    fn test_should_propagate_to_peer() {
        // Should propagate to established peer when no originating peer
        assert!(should_propagate_to_peer(
            "10.0.0.2",
            BgpState::Established,
            &None
        ));

        // Should propagate to established peer when different from originating peer
        assert!(should_propagate_to_peer(
            "10.0.0.2",
            BgpState::Established,
            &Some("10.0.0.1".to_string())
        ));

        // Should NOT propagate to same peer that sent the route
        assert!(!should_propagate_to_peer(
            "10.0.0.2",
            BgpState::Established,
            &Some("10.0.0.2".to_string())
        ));

        // Should NOT propagate to non-established peer
        assert!(!should_propagate_to_peer(
            "10.0.0.3",
            BgpState::Connect,
            &Some("10.0.0.1".to_string())
        ));
    }

    #[test]
    fn test_build_export_as_path() {
        // Local routes are stored with empty AS_PATH
        let local_path = make_path(RouteSource::Local, vec![], Ipv4Addr::new(192, 168, 1, 1));

        let ebgp_path = make_path(
            RouteSource::Ebgp("10.0.0.1".to_string()),
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 2,
                asn_list: vec![65001, 65002],
            }],
            Ipv4Addr::new(192, 168, 1, 2),
        );

        let ibgp_path = make_path(
            RouteSource::Ibgp("10.0.0.2".to_string()),
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
        let path_a = make_path(
            RouteSource::Local,
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65000],
            }],
            Ipv4Addr::new(192, 168, 1, 1),
        );

        let path_b = make_path(
            RouteSource::Local,
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65000],
            }],
            Ipv4Addr::new(192, 168, 1, 2),
        );

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
            (p1, path_a.clone()),
            (p2, path_b.clone()),
            (p3, path_a.clone()),
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
            RouteSource::Ebgp("10.0.0.1".to_string()),
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
            RouteSource::Ebgp("10.0.0.1".to_string()),
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
            RouteSource::Ebgp("10.0.0.1".to_string()),
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
            RouteSource::Ibgp("10.0.0.1".to_string()),
            vec![],
            Ipv4Addr::new(192, 168, 2, 1),
        );
        assert_eq!(
            build_export_next_hop(&ibgp_path, router_id, local_asn, peer_asn_ibgp),
            Ipv4Addr::new(192, 168, 2, 1)
        );

        // eBGP: Learned route -> rewrite to self
        let ebgp_path = make_path(
            RouteSource::Ebgp("10.0.0.1".to_string()),
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
}
