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
/// For locally originated routes, use the existing AS path (which already contains local ASN)
/// For routes learned from peers, prepend local ASN
pub fn build_export_as_path(path: &Path, local_asn: u16) -> Vec<AsPathSegment> {
    let new_as_path = if matches!(path.source, RouteSource::Local) {
        path.as_path.clone()
    } else {
        let mut as_path = vec![local_asn];
        as_path.extend_from_slice(&path.as_path);
        as_path
    };

    vec![AsPathSegment {
        segment_type: AsPathSegmentType::AsSequence,
        segment_len: new_as_path.len() as u8,
        asn_list: new_as_path,
    }]
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
    let mut batches: HashMap<(Origin, Vec<u16>, Ipv4Addr), AnnouncementBatch> = HashMap::new();

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

/// Send route announcements to a peer
/// Batches prefixes that share the same path attributes into single UPDATE messages
pub fn send_announcements_to_peer(
    peer_addr: &str,
    message_tx: &mpsc::UnboundedSender<PeerOp>,
    to_announce: &[(IpNetwork, Path)],
    local_asn: u16,
) {
    if to_announce.is_empty() {
        return;
    }

    let batches = batch_announcements_by_path(to_announce);

    // Send one UPDATE message per unique set of path attributes
    for batch in batches {
        let prefix_count = batch.prefixes.len();
        let as_path_segments = build_export_as_path(&batch.path, local_asn);
        let update_msg = UpdateMessage::new(
            batch.path.origin,
            as_path_segments,
            batch.path.next_hop,
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

    fn make_path(source: RouteSource, as_path: Vec<u16>, next_hop: Ipv4Addr) -> Path {
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
        let local_path = make_path(
            RouteSource::Local,
            vec![65000],
            Ipv4Addr::new(192, 168, 1, 1),
        );

        let ebgp_path = make_path(
            RouteSource::Ebgp("10.0.0.1".to_string()),
            vec![65001, 65002],
            Ipv4Addr::new(192, 168, 1, 2),
        );

        // Local route: keep existing AS path (already contains local ASN)
        let result = build_export_as_path(&local_path, 65000);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[0].asn_list, vec![65000]);

        // Learned route: prepend local ASN
        let result = build_export_as_path(&ebgp_path, 65000);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[0].asn_list, vec![65000, 65001, 65002]);
    }

    #[test]
    fn test_batch_announcements_by_path() {
        let path_a = make_path(
            RouteSource::Local,
            vec![65000],
            Ipv4Addr::new(192, 168, 1, 1),
        );

        let path_b = make_path(
            RouteSource::Local,
            vec![65000],
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
}
