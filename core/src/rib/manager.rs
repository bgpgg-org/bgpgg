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

use crate::bgp::msg::BgpMessage;
use crate::bgp::msg_update::UpdateMessage;
use crate::rib::rib_in::AdjRibIn;
use crate::rib::rib_loc::LocRib;
use crate::rib::rib_out::AdjRibOut;
use crate::rib::types::Path;
use crate::rib::{Rib, RibMessage};
use crate::{debug, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc;

/// Main RIB Manager
///
/// Coordinates the three types of RIBs and handles BGP message processing,
/// policy application, and best path selection.
pub struct RibManager {
    // Per-peer Adj-RIB-In tables
    adj_rib_in: HashMap<SocketAddr, AdjRibIn>,

    // Single Loc-RIB (best paths)
    loc_rib: LocRib,

    // Per-peer Adj-RIB-Out tables
    adj_rib_out: HashMap<SocketAddr, AdjRibOut>,

    // Configuration
    local_asn: u16,
}

impl RibManager {
    pub fn new(local_asn: u16) -> Self {
        RibManager {
            adj_rib_in: HashMap::new(),
            loc_rib: LocRib::new(),
            adj_rib_out: HashMap::new(),
            local_asn,
        }
    }

    pub async fn run(mut self, mut rx: mpsc::Receiver<RibMessage>) {
        info!("RIB manager started", "local_asn" => self.local_asn);

        while let Some(msg) = rx.recv().await {
            match msg {
                RibMessage::PeerConnected(addr) => {
                    self.handle_peer_connected(addr);
                }
                RibMessage::PeerDisconnected(addr) => {
                    self.handle_peer_disconnected(addr);
                }
                RibMessage::BgpMessage { from, message } => {
                    self.process_bgp_message(from, message);
                }
                RibMessage::QueryLocRib { response_tx } => {
                    let routes = self.loc_rib.get_all_routes();
                    let _ = response_tx.send(routes);
                }
                RibMessage::QueryAdjRibIn { peer, response_tx } => {
                    let routes = self
                        .adj_rib_in
                        .get(&peer)
                        .map(|rib| rib.get_all_routes())
                        .unwrap_or_default();
                    let _ = response_tx.send(routes);
                }
                RibMessage::QueryAdjRibOut { peer, response_tx } => {
                    let routes = self
                        .adj_rib_out
                        .get(&peer)
                        .map(|rib| rib.get_all_routes())
                        .unwrap_or_default();
                    let _ = response_tx.send(routes);
                }
            }
        }

        info!("RIB manager stopped");
    }

    fn handle_peer_connected(&mut self, addr: SocketAddr) {
        info!("peer connected, creating Adj-RIB-In and Adj-RIB-Out", "peer_addr" => addr.to_string());

        self.adj_rib_in.insert(addr, AdjRibIn::new(addr));
        self.adj_rib_out.insert(addr, AdjRibOut::new(addr));
    }

    fn handle_peer_disconnected(&mut self, addr: SocketAddr) {
        info!("peer disconnected, cleaning up", "peer_addr" => addr.to_string());

        // Remove Adj-RIB-In for this peer
        self.adj_rib_in.remove(&addr);

        // Remove Adj-RIB-Out for this peer
        self.adj_rib_out.remove(&addr);

        // Remove all routes from this peer in Loc-RIB
        self.loc_rib.remove_routes_from_peer(addr);

        // Recompute Adj-RIB-Out for all remaining peers
        self.recompute_adj_rib_out();

        info!("cleanup complete", "loc_rib_routes" => self.loc_rib.routes_len());
    }

    fn process_bgp_message(&mut self, from: SocketAddr, message: BgpMessage) {
        match message {
            BgpMessage::Open(open_msg) => {
                debug!("processing OPEN", "peer_addr" => from.to_string(), "asn" => open_msg.asn, "hold_time" => open_msg.hold_time, "bgp_identifier" => open_msg.bgp_identifier);
            }
            BgpMessage::Update(update_msg) => {
                debug!("processing UPDATE", "peer_addr" => from.to_string(), "update" => format!("{:?}", update_msg));
                self.process_update(from, update_msg);
            }
            BgpMessage::KeepAlive(_) => {
                debug!("processing KEEPALIVE", "peer_addr" => from.to_string());
            }
            BgpMessage::Notification(notif_msg) => {
                warn!("processing NOTIFICATION", "peer_addr" => from.to_string(), "notification" => format!("{:?}", notif_msg));
            }
        }
    }

    fn process_update(&mut self, from: SocketAddr, update_msg: UpdateMessage) {
        // Extract path attributes
        let origin = match update_msg.get_origin() {
            Some(o) => o,
            None => {
                warn!("UPDATE missing Origin attribute, skipping", "peer_addr" => from.to_string());
                return;
            }
        };

        let as_path = match update_msg.get_as_path() {
            Some(p) => p,
            None => {
                warn!("UPDATE missing AS Path attribute, skipping", "peer_addr" => from.to_string());
                return;
            }
        };

        let next_hop = match update_msg.get_next_hop() {
            Some(nh) => nh,
            None => {
                warn!("UPDATE missing Next Hop attribute, skipping", "peer_addr" => from.to_string());
                return;
            }
        };

        // Get or create Adj-RIB-In for this peer
        let adj_rib_in = self
            .adj_rib_in
            .entry(from)
            .or_insert_with(|| AdjRibIn::new(from));

        // Step 1: Update Adj-RIB-In (raw routes from peer)

        // Process withdrawn routes
        for prefix in update_msg.withdrawn_routes() {
            info!("withdrawing route", "prefix" => format!("{:?}", prefix), "peer_addr" => from.to_string());
            adj_rib_in.remove_route(*prefix);
        }

        // Process announced routes (NLRI)
        for prefix in update_msg.nlri_list() {
            let path = Path {
                origin,
                as_path: as_path.clone(),
                next_hop,
                from_peer: from,
                local_pref: None,
                med: None,
            };
            info!("adding route to Adj-RIB-In", "prefix" => format!("{:?}", prefix), "peer_addr" => from.to_string());
            adj_rib_in.add_route(*prefix, path.clone());
        }

        // Step 2: Apply import policy and update Loc-RIB
        self.update_loc_rib_from_peer(from);

        // Step 3: Run best path selection on Loc-RIB
        self.run_best_path_selection();

        // Step 4: Apply export policy and update all Adj-RIB-Out
        self.recompute_adj_rib_out();

        info!("UPDATE processing complete", "loc_rib_routes" => self.loc_rib.routes_len());
    }

    fn update_loc_rib_from_peer(&mut self, peer_addr: SocketAddr) {
        // Get routes from Adj-RIB-In
        let Some(adj_rib_in) = self.adj_rib_in.get(&peer_addr) else {
            return;
        };

        // Remove old routes from this peer in Loc-RIB
        self.loc_rib.remove_routes_from_peer(peer_addr);

        // Apply import policy and add to Loc-RIB
        for route in adj_rib_in.get_all_routes() {
            for mut path in route.paths {
                // Apply import policy
                if self.apply_import_policy(&mut path) {
                    info!("adding route to Loc-RIB", "prefix" => format!("{:?}", route.prefix), "peer_addr" => peer_addr.to_string());
                    self.loc_rib.add_route(route.prefix, path);
                } else {
                    debug!("route rejected by import policy", "prefix" => format!("{:?}", route.prefix), "peer_addr" => peer_addr.to_string());
                }
            }
        }
    }

    fn apply_import_policy(&self, path: &mut Path) -> bool {
        // Set default local preference if not set
        // TODO: only do this for iBGP
        if path.local_pref.is_none() {
            path.local_pref = Some(100);
        }

        // Reject routes with our own ASN (loop prevention)
        if path.as_path.contains(&self.local_asn) {
            debug!("rejecting route due to AS loop", "local_asn" => self.local_asn);
            return false;
        }

        // Accept by default
        true
    }

    fn run_best_path_selection(&mut self) {
        // In a real implementation, this would:
        // 1. For each prefix in Loc-RIB with multiple paths
        // 2. Apply BGP best path algorithm (highest local_pref, shortest AS path, etc.)
        // 3. Keep only the best path

        // For now, we keep all paths (simple implementation)
        debug!("best path selection (keeping all paths for now)");
    }

    fn recompute_adj_rib_out(&mut self) {
        // Get all routes from Loc-RIB
        let loc_routes = self.loc_rib.get_all_routes();

        // For each peer, compute what to advertise
        let peers: Vec<SocketAddr> = self.adj_rib_out.keys().copied().collect();

        for peer_addr in peers {
            // Build routes to advertise for this peer
            let mut routes_to_add = Vec::new();

            for route in &loc_routes {
                for path in &route.paths {
                    // Apply export policy
                    if let Some(export_path) = self.apply_export_policy(peer_addr, path) {
                        routes_to_add.push((route.prefix, export_path));
                        break; // Only advertise one path per prefix to each peer
                    }
                }
            }

            // Update Adj-RIB-Out for this peer
            if let Some(adj_rib_out) = self.adj_rib_out.get_mut(&peer_addr) {
                adj_rib_out.clear();
                for (prefix, path) in routes_to_add {
                    adj_rib_out.add_route(prefix, path);
                }
                info!("updated Adj-RIB-Out for peer", "peer_addr" => peer_addr.to_string(), "routes_count" => adj_rib_out.routes_len());
            }
        }
    }

    fn apply_export_policy(&self, to_peer: SocketAddr, path: &Path) -> Option<Path> {
        // Don't advertise routes back to the peer we learned them from (split horizon)
        if path.from_peer == to_peer {
            return None;
        }

        // Prepend our ASN to the path
        let mut export_path = path.clone();
        export_path.as_path.insert(0, self.local_asn);

        Some(export_path)
    }
}
