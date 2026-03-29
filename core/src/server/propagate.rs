// Copyright 2026 bgpgg Authors
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

use super::{BgpServer, BmpOp};
use crate::bgp::msg::{AddPathMask, MessageFormat};
use crate::bgp::msg_update::UpdateMessage;
use crate::bgp::msg_update_types::Nlri;
use crate::bgp::multiprotocol::{Afi, Safi};
use crate::log::{error, info, warn};
use crate::peer::outgoing::{
    batch_announcements_by_path, propagate_routes_to_peer, should_propagate_to_peer,
    PeerExportContext,
};
use crate::peer::Withdrawal;
use crate::rib::rib_loc::RouteDelta;
use crate::rib::PrefixPath;
use std::net::IpAddr;
use std::sync::Arc;

impl BgpServer {
    /// Broadcast a BMP operation to all active BMP tasks
    pub(crate) fn broadcast_bmp(&self, op: BmpOp) {
        let op = Arc::new(op);
        for task_info in self.bmp_tasks.values() {
            let _ = task_info.task_tx.send(Arc::clone(&op));
        }
    }

    /// Propagate route changes to all established peers (except the originating peer)
    /// If originating_peer is None, propagates to all peers (used for locally originated routes)
    ///
    /// Loops per-AFI/SAFI so ADD-PATH is checked per address family, not globally.
    ///
    /// RFC 4456 Route Reflector filtering is handled by compute_export_path based on:
    /// - path.source.is_rr_client(): whether source peer was an RR client
    /// - rr_client: whether peer is an RR client
    pub(crate) async fn propagate_routes(
        &mut self,
        delta: RouteDelta,
        originating_peer: Option<IpAddr>,
    ) {
        if !delta.has_changes() {
            return;
        }

        let local_asn = self.config.asn;
        let cluster_id = self.config.cluster_id();
        let local_addr = self.local_addr;
        let loc_rib = &self.loc_rib;

        for (peer_addr, entry) in self.peers.iter_mut() {
            let Some(conn) = entry.established_conn() else {
                continue;
            };

            if !should_propagate_to_peer(*peer_addr, conn.state, originating_peer) {
                continue;
            }

            let Some(peer_tx) = conn.peer_tx.clone() else {
                continue;
            };
            let Some(capabilities) = conn.capabilities.clone() else {
                continue;
            };

            let peer_asn = conn.asn.unwrap_or(local_asn);
            let local_next_hop = conn
                .conn_info
                .as_ref()
                .map(|conn_info| conn_info.local_address)
                .unwrap_or(local_addr);
            let send_format = conn.send_format();
            let negotiated_afi_safis = conn.negotiated_afi_safis();

            let export_policies = entry.policy_out().to_vec();
            if export_policies.is_empty() {
                error!(peer_ip = %peer_addr, "export policies not set for established peer");
                continue;
            }

            let ctx = PeerExportContext {
                peer_addr: *peer_addr,
                peer_tx: &peer_tx,
                local_asn,
                peer_asn,
                local_next_hop,
                export_policies: &export_policies,
                rr_client: entry.config.rr_client,
                rs_client: entry.config.rs_client,
                cluster_id,
                send_format,
                negotiated_afi_safis: &negotiated_afi_safis,
                next_hop_self: entry.config.next_hop_self,
                graceful_shutdown: entry.config.graceful_shutdown,
                capabilities: &capabilities,
            };

            propagate_routes_to_peer(&ctx, &delta, loc_rib, &mut entry.adj_rib_out);
        }
    }

    pub(super) fn resend_routes_to_peer(&mut self, peer_ip: IpAddr, afi: Afi, safi: Safi) {
        let Some(peer_info) = self.peers.get_mut(&peer_ip) else {
            warn!(%peer_ip, "resend routes for unknown peer");
            return;
        };

        if safi != Safi::Unicast {
            warn!(?safi, "unsupported SAFI");
            return;
        }
        if peer_info.export_policies.is_empty() {
            return;
        }

        // Extract values from conn before dropping the immutable borrow on peer_info,
        // since propagate_routes_to_peer needs &mut peer_info.adj_rib_out.
        let (peer_asn, peer_tx, capabilities, send_format, local_next_hop, negotiated_afi_safis) = {
            let Some(conn) = peer_info.established_conn() else {
                return;
            };
            let Some(peer_asn) = conn.asn else {
                return;
            };
            let Some(peer_tx) = conn.peer_tx.clone() else {
                return;
            };
            let Some(capabilities) = conn.capabilities.clone() else {
                return;
            };
            let send_format = conn.send_format();
            let local_next_hop = conn
                .conn_info
                .as_ref()
                .map(|ci| ci.local_address)
                .unwrap_or(self.local_addr);
            let negotiated_afi_safis = conn.negotiated_afi_safis();
            (
                peer_asn,
                peer_tx,
                capabilities,
                send_format,
                local_next_hop,
                negotiated_afi_safis,
            )
        };

        let export_policies = &peer_info.export_policies;

        let ctx = PeerExportContext {
            peer_addr: peer_ip,
            peer_tx: &peer_tx,
            local_asn: self.config.asn,
            peer_asn,
            local_next_hop,
            export_policies,
            rr_client: peer_info.config.rr_client,
            rs_client: peer_info.config.rs_client,
            cluster_id: self.config.cluster_id(),
            send_format,
            negotiated_afi_safis: &negotiated_afi_safis,
            next_hop_self: peer_info.config.next_hop_self,
            graceful_shutdown: peer_info.config.graceful_shutdown,
            capabilities: &capabilities,
        };

        let all_prefixes = self.loc_rib.prefixes_for_afi(afi);
        let delta = RouteDelta {
            best_changed: all_prefixes.clone(),
            changed: all_prefixes,
        };
        propagate_routes_to_peer(&ctx, &delta, &self.loc_rib, &mut peer_info.adj_rib_out);

        info!(%peer_ip, ?afi, "resent routes to peer");
    }

    pub(super) fn send_bmp_route_monitoring(
        &self,
        peer_ip: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        withdrawn: &[Withdrawal],
        announced: &[PrefixPath],
    ) {
        // Mirror the actual BGP session encoding
        let peer_info = self.peers.get(&peer_ip);
        let use_4byte_asn = peer_info.map(|p| p.supports_4byte_asn()).unwrap_or(true);
        let add_path = peer_info
            .map(|p| p.add_path_receive_mask())
            .unwrap_or(AddPathMask::NONE);
        let format = MessageFormat {
            use_4byte_asn,
            add_path,
            is_ebgp: false,
        };

        // Send withdrawals if any
        if !withdrawn.is_empty() {
            let nlri: Vec<Nlri> = withdrawn
                .iter()
                .map(|(prefix, path_id)| Nlri {
                    prefix: *prefix,
                    path_id: *path_id,
                })
                .collect();
            let update = UpdateMessage::new_withdraw(nlri, format);
            self.broadcast_bmp(BmpOp::RouteMonitoring {
                peer_ip,
                peer_as,
                peer_bgp_id,
                update,
            });
        }

        // Send announcements batched by path attributes
        if !announced.is_empty() {
            let batches = batch_announcements_by_path(announced);
            for batch in batches {
                let update = UpdateMessage::new(&batch.path, batch.prefixes, format);
                self.broadcast_bmp(BmpOp::RouteMonitoring {
                    peer_ip,
                    peer_as,
                    peer_bgp_id,
                    update,
                });
            }
        }
    }
}
