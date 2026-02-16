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

use crate::bgp::msg::MessageFormat;
use crate::bgp::msg_notification::CeaseSubcode;
use crate::bgp::msg_update::UpdateMessage;
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::config::DefinedSetConfig;
use crate::config::PeerConfig;
use crate::log::{debug, error, info, warn};
use crate::net::IpNetwork;
use crate::peer::outgoing::{batch_announcements_by_path, send_announcements_to_peer};
use crate::peer::{BgpState, PeerOp};
use crate::policy::sets::{
    AsPathSet, CommunitySet, ExtCommunitySet, LargeCommunitySet, NeighborSet, PrefixMatch,
    PrefixSet,
};
use crate::policy::{DefinedSetType, PolicyResult};
use crate::rib::{Path, PathAttrs, PrefixPath, Route};
use crate::server::PolicyDirection;
use crate::server::{
    AdminState, BgpServer, BmpOp, BmpPeerStats, BmpTaskInfo, ConnectionInfo, ConnectionType,
    GetPeerResponse, GetPeersResponse, MgmtOp, PeerInfo, ResetType, ServerOp,
};
use crate::types::PeerDownReason;
use regex::Regex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

impl BgpServer {
    pub(crate) async fn handle_mgmt_op(&mut self, req: MgmtOp, bind_addr: SocketAddr) {
        match req {
            MgmtOp::AddPeer {
                addr,
                config,
                response,
            } => {
                self.handle_add_peer(addr, config, response, bind_addr)
                    .await;
            }
            MgmtOp::RemovePeer { addr, response } => {
                self.handle_remove_peer(addr, response).await;
            }
            MgmtOp::DisablePeer { addr, response } => {
                self.handle_disable_peer(addr, response);
            }
            MgmtOp::EnablePeer { addr, response } => {
                self.handle_enable_peer(addr, response);
            }
            MgmtOp::ResetPeer {
                addr,
                reset_type,
                afi,
                safi,
                response,
            } => {
                self.handle_reset_peer(addr, reset_type, afi, safi, response)
                    .await;
            }
            MgmtOp::AddRoute {
                prefix,
                attrs,
                response,
            } => {
                self.handle_add_route(prefix, attrs, response).await;
            }
            MgmtOp::RemoveRoute { prefix, response } => {
                self.handle_remove_route(prefix, response).await;
            }
            MgmtOp::GetPeers { response } => {
                self.handle_get_peers(response);
            }
            MgmtOp::GetPeer { addr, response } => {
                self.handle_get_peer(addr, response).await;
            }
            MgmtOp::GetRoutes {
                rib_type,
                peer_address,
                response,
            } => {
                self.handle_get_routes(rib_type, peer_address, response)
                    .await;
            }
            MgmtOp::GetRoutesStream {
                rib_type,
                peer_address,
                tx,
            } => {
                self.handle_get_routes_stream(rib_type, peer_address, tx)
                    .await;
            }
            MgmtOp::GetPeersStream { tx } => {
                self.handle_get_peers_stream(tx);
            }
            MgmtOp::GetServerInfo { response } => {
                let num_routes = self.loc_rib.routes_len() as u64;
                let _ = response.send((self.local_addr, self.local_port, num_routes));
            }
            MgmtOp::AddBmpServer {
                addr,
                statistics_timeout,
                response,
            } => {
                self.handle_add_bmp_server(addr, statistics_timeout, response)
                    .await;
            }
            MgmtOp::RemoveBmpServer { addr, response } => {
                self.handle_remove_bmp_server(addr, response);
            }
            MgmtOp::GetBmpServers { response } => {
                self.handle_get_bmp_servers(response);
            }
            MgmtOp::AddDefinedSet { set, response } => {
                self.handle_add_defined_set(set, response);
            }
            MgmtOp::RemoveDefinedSet {
                set_type,
                name,
                response,
            } => {
                self.handle_remove_defined_set(set_type, name, response);
            }
            MgmtOp::ListDefinedSets {
                set_type,
                name,
                response,
            } => {
                self.handle_list_defined_sets(set_type, name, response);
            }
            MgmtOp::AddPolicy {
                name,
                statements,
                response,
            } => {
                self.handle_add_policy(name, statements, response);
            }
            MgmtOp::RemovePolicy { name, response } => {
                self.handle_remove_policy(name, response);
            }
            MgmtOp::ListPolicies { name, response } => {
                self.handle_list_policies(name, response);
            }
            MgmtOp::SetPolicyAssignment {
                peer_addr,
                direction,
                policy_names,
                default_action,
                response,
            } => {
                self.handle_set_policy_assignment(
                    peer_addr,
                    direction,
                    policy_names,
                    default_action,
                    response,
                );
            }
        }
    }

    pub(crate) async fn handle_server_op(&mut self, op: ServerOp) {
        match op {
            ServerOp::PeerStateChanged {
                peer_ip,
                state,
                conn_type,
            } => {
                let Some(peer) = self.peers.get_mut(&peer_ip) else {
                    return;
                };

                // Route to correct slot by conn_type
                let slot = peer.slot_mut(conn_type);
                let Some(conn) = slot.as_mut() else {
                    return;
                };

                conn.state = state;
                info!(%peer_ip, ?state, ?conn_type, "peer state changed");

                // When peer becomes Established, send BMP PeerUp and propagate all routes
                if state == BgpState::Established {
                    self.handle_peer_established(peer_ip).await;
                }
            }
            ServerOp::PeerHandshakeComplete {
                peer_ip,
                asn,
                conn_type,
            } => {
                // Update ASN on the correct slot
                // Clone config for immutable access, then mutate peer
                if let Some(peer_config) = self.peers.get(&peer_ip).map(|p| p.config.clone()) {
                    let import_policies = self.resolve_import_policies(&peer_config);
                    let export_policies = self.resolve_export_policies(&peer_config);

                    if let Some(peer) = self.peers.get_mut(&peer_ip) {
                        if let Some(conn) = peer.slot_mut(conn_type).as_mut() {
                            conn.asn = Some(asn);
                        }
                        peer.import_policies = import_policies;
                        peer.export_policies = export_policies;
                        info!(%peer_ip, asn, ?conn_type, "peer handshake complete");
                    }
                }
            }
            ServerOp::PeerUpdate {
                peer_ip,
                withdrawn,
                announced,
            } => {
                let peer = self.peers.get(&peer_ip).expect("peer should exist");

                // Get the established connection for peer info
                let (peer_asn, peer_bgp_id) = peer
                    .established_conn()
                    .map(|c| (c.asn, c.bgp_id))
                    .unwrap_or((None, None));

                let import_policies = peer.policy_in();

                if !import_policies.is_empty() {
                    let delta = self.loc_rib.apply_peer_update(
                        peer_ip,
                        withdrawn.clone(),
                        announced.clone(),
                        |prefix, path| {
                            // Evaluate policies in order until Accept/Reject
                            for policy in import_policies {
                                match policy.evaluate(prefix, path) {
                                    PolicyResult::Accept => return true,
                                    PolicyResult::Reject => return false,
                                    PolicyResult::Continue => continue,
                                }
                            }
                            false // All policies returned Continue -> default reject
                        },
                    );

                    info!(%peer_ip, "UPDATE processing complete");

                    // Propagate changed routes to other peers
                    if delta.has_changes() {
                        self.propagate_routes(delta, Some(peer_ip)).await;
                    }

                    // BMP: Send route monitoring for this update
                    if let (Some(asn), Some(bgp_id)) = (peer_asn, peer_bgp_id) {
                        self.send_bmp_route_monitoring(
                            peer_ip, asn, bgp_id, &withdrawn, &announced,
                        );
                    }
                } else {
                    error!(%peer_ip, "received UPDATE before handshake complete");
                }
            }
            ServerOp::OpenReceived {
                peer_ip,
                bgp_id,
                conn_type,
            } => {
                self.handle_open_received(peer_ip, bgp_id, conn_type).await;
            }
            ServerOp::PeerConnectionInfo {
                peer_ip,
                local_address,
                local_port,
                remote_port,
                sent_open,
                received_open,
                negotiated_capabilities,
                conn_type,
            } => {
                if let Some(peer) = self.peers.get_mut(&peer_ip) {
                    if let Some(conn) = peer.slot_mut(conn_type).as_mut() {
                        conn.conn_info = Some(ConnectionInfo {
                            sent_open,
                            received_open,
                            local_address,
                            local_port,
                            remote_port,
                        });
                        conn.capabilities = Some(negotiated_capabilities);
                    }
                }
            }
            ServerOp::PeerDisconnected {
                peer_ip,
                reason,
                gr_afi_safis,
                conn_type,
            } => {
                let Some(peer) = self.peers.get_mut(&peer_ip) else {
                    return;
                };

                // Check if the disconnect is from the correct slot
                let slot_exists = peer.slot(conn_type).is_some();
                if !slot_exists {
                    // Stale disconnect from old connection
                    debug!(%peer_ip, ?conn_type, "ignoring stale disconnect");
                    return;
                }

                // Extract info before modifying slot
                let was_established = peer
                    .slot(conn_type)
                    .map(|c| c.state == BgpState::Established)
                    .unwrap_or(false);

                let bmp_peer_info = peer.slot(conn_type).and_then(|c| match (c.asn, c.bgp_id) {
                    (Some(asn), Some(bgp_id)) => Some((asn, bgp_id, peer_supports_4byte_asn(peer))),
                    _ => None,
                });

                // Check if there's another connection in the other slot
                let other_slot_active = match conn_type {
                    ConnectionType::Outgoing => peer.incoming.is_some(),
                    ConnectionType::Incoming => peer.outgoing.is_some(),
                };

                if other_slot_active {
                    // Other connection exists - just clear this slot
                    *peer.slot_mut(conn_type) = None;
                    debug!(%peer_ip, ?conn_type, "connection slot cleared, other connection active");
                    return;
                }

                // Keep the slot but reset to Idle state (preserve peer_tx for reconnect)
                if let Some(conn) = peer.slot_mut(conn_type).as_mut() {
                    conn.state = BgpState::Idle;
                    conn.conn_info = None;
                    conn.asn = None;
                    conn.bgp_id = None;
                }
                peer.adj_rib_out.clear();
                info!(%peer_ip, "peer session ended");

                // RFC 4724: Handle routes based on Graceful Restart state
                if !gr_afi_safis.is_empty() {
                    info!(%peer_ip, ?gr_afi_safis,
                          "peer disconnected with Graceful Restart - marking routes as stale (Receiving Speaker mode)");

                    // Mark routes stale for each GR-enabled AFI/SAFI
                    for afi_safi in gr_afi_safis {
                        let count = self.loc_rib.mark_peer_routes_stale(peer_ip, afi_safi);
                        debug!(%peer_ip, %afi_safi, count, "marked routes as stale");
                    }
                    // No withdrawals are propagated (RFC 4724 Section 4.1)
                } else if was_established {
                    // Only propagate withdrawals if the disconnected connection was Established
                    let delta = self.loc_rib.remove_routes_from_peer(peer_ip);
                    if delta.has_changes() {
                        self.propagate_routes(delta, Some(peer_ip)).await;
                    }
                }

                // BMP: Peer Down notification (only if session reached ESTABLISHED)
                if let Some((peer_as, peer_bgp_id, use_4byte_asn)) = bmp_peer_info {
                    self.broadcast_bmp(BmpOp::PeerDown {
                        peer_ip,
                        peer_as,
                        peer_bgp_id,
                        reason,
                        use_4byte_asn,
                    });
                }
            }
            ServerOp::SetAdminState { peer_ip, state } => {
                if let Some(peer) = self.peers.get_mut(&peer_ip) {
                    peer.admin_state = state;
                }
            }
            ServerOp::RouteRefresh { peer_ip, afi, safi } => {
                self.handle_route_refresh(peer_ip, afi, safi).await;
            }
            ServerOp::GracefulRestartTimerExpired { peer_ip } => {
                info!(%peer_ip, "Graceful Restart timer expired - removing stale routes");

                // Remove stale routes for all AFI/SAFIs that have stale routes
                // (the stale flag was set at disconnect time based on GR capabilities)
                let stale_afi_safis = self.loc_rib.stale_afi_safis(peer_ip);
                let delta = self
                    .loc_rib
                    .remove_peer_routes_stale(peer_ip, &stale_afi_safis);

                // Propagate withdrawals if any routes were removed
                if delta.has_changes() {
                    self.propagate_routes(delta, Some(peer_ip)).await;
                }
            }
            ServerOp::GracefulRestartComplete { peer_ip, afi_safi } => {
                info!(%peer_ip, %afi_safi, "Graceful Restart completed for AFI/SAFI - removing remaining stale routes");

                // Remove stale routes for this specific AFI/SAFI
                let delta = self.loc_rib.remove_peer_routes_stale(peer_ip, &[afi_safi]);

                // Propagate withdrawals if any routes were removed
                if delta.has_changes() {
                    self.propagate_routes(delta, Some(peer_ip)).await;
                }
            }
            ServerOp::LocalRibSent { peer_ip, afi_safi } => {
                if let Some(peer) = self.peers.get(&peer_ip) {
                    if let Some(conn) = peer.established_conn() {
                        if let Some(peer_tx) = &conn.peer_tx {
                            let _ = peer_tx.send(PeerOp::LocalRibSent { afi_safi });
                        }
                    }
                }
            }
            ServerOp::GetBmpStatistics { response } => {
                self.handle_get_bmp_statistics(response).await;
            }
        }
    }

    /// Handle OPEN message received - store BGP ID and check collision (RFC 4271 6.8)
    async fn handle_open_received(
        &mut self,
        peer_ip: IpAddr,
        bgp_id: u32,
        conn_type: ConnectionType,
    ) {
        // Update BGP ID for correct slot
        if let Some(peer) = self.peers.get_mut(&peer_ip) {
            if let Some(conn) = peer.slot_mut(conn_type).as_mut() {
                conn.bgp_id = Some(bgp_id);
                info!(%peer_ip, ?conn_type, bgp_id, "stored BGP ID in slot");
            } else {
                error!(%peer_ip, ?conn_type, "OpenReceived but slot is None!");
            }
        } else {
            error!(%peer_ip, "OpenReceived but peer not found!");
        }

        // Check for collision
        self.check_collision(peer_ip).await;
    }

    /// Check and resolve connection collision per RFC 4271 6.8.
    /// With slot-based design: outgoing and incoming are fixed slots.
    async fn check_collision(&mut self, peer_ip: IpAddr) {
        let Some(peer) = self.peers.get_mut(&peer_ip) else {
            return;
        };

        // Need both slots occupied for collision
        let (out, inc) = match (&peer.outgoing, &peer.incoming) {
            (Some(out), Some(inc)) => (out, inc),
            _ => return,
        };

        // Both must have BGP IDs (both received OPEN)
        let Some(out_bgp_id) = out.bgp_id else {
            return;
        };
        let Some(inc_bgp_id) = inc.bgp_id else {
            return;
        };

        // RFC 4271 6.8: Connection initiated by higher BGP ID wins
        // - Outgoing = we initiated -> wins if local > remote
        // - Incoming = remote initiated -> wins if remote > local
        // Note: inc_bgp_id and out_bgp_id are both the REMOTE's ID (from their OPEN)
        let local_bgp_id = u32::from(self.config.router_id);

        // Remote initiated (incoming) wins if remote BGP ID > local BGP ID
        let incoming_wins = inc_bgp_id > local_bgp_id;

        info!(%peer_ip, local_bgp_id, out_bgp_id, inc_bgp_id, incoming_wins, "resolving collision");

        if incoming_wins {
            // Close outgoing, keep incoming
            if let Some(tx) = &out.peer_tx {
                let _ = tx.send(PeerOp::CollisionLost);
            }
            peer.outgoing = None;
            info!(%peer_ip, "collision: outgoing closed, incoming wins");

            // If incoming was already Established, handle it now
            if peer.incoming.as_ref().map(|c| c.state) == Some(BgpState::Established) {
                self.handle_peer_established(peer_ip).await;
            }
        } else {
            // Close incoming, keep outgoing
            if let Some(tx) = &inc.peer_tx {
                let _ = tx.send(PeerOp::CollisionLost);
            }
            peer.incoming = None;
            info!(%peer_ip, "collision: incoming closed, outgoing wins");

            // If outgoing was already Established, handle it now
            if peer.outgoing.as_ref().map(|c| c.state) == Some(BgpState::Established) {
                self.handle_peer_established(peer_ip).await;
            }
        }
    }

    /// Handle peer reaching Established state - BMP PeerUp, route propagation, GR stale handling
    async fn handle_peer_established(&mut self, peer_ip: IpAddr) {
        let Some(peer) = self.peers.get(&peer_ip) else {
            return;
        };

        // Get the established connection
        let Some(conn) = peer.established_conn() else {
            return;
        };

        // Send BMP PeerUp
        if let (Some(asn), Some(bgp_id), Some(conn_info)) = (conn.asn, conn.bgp_id, &conn.conn_info)
        {
            let use_4byte_asn = peer_supports_4byte_asn(peer);
            self.broadcast_bmp(BmpOp::PeerUp {
                peer_ip,
                peer_as: asn,
                peer_bgp_id: bgp_id,
                local_address: conn_info.local_address,
                local_port: conn_info.local_port,
                remote_port: conn_info.remote_port,
                sent_open: conn_info.sent_open.clone(),
                received_open: conn_info.received_open.clone(),
                use_4byte_asn,
            });
        }

        // Extract capabilities and peer_tx before propagate_routes
        let capabilities = conn.capabilities.clone();
        let peer_tx = conn.peer_tx.clone();

        // RFC 4724 Section 4.2: Check F-bit on reconnect for stale route handling
        // If F=0, AFI/SAFI not in GR cap, or no GR cap: immediately clear stale routes
        let gr_cap = capabilities
            .as_ref()
            .and_then(|c| c.graceful_restart.as_ref());
        let afi_safis_to_clear: Vec<_> = match gr_cap {
            Some(cap) => self
                .loc_rib
                .stale_afi_safis(peer_ip)
                .into_iter()
                .filter(|afi_safi| cap.should_clear_stale(*afi_safi))
                .collect(),
            None => self.loc_rib.stale_afi_safis(peer_ip),
        };

        let delta = self
            .loc_rib
            .remove_peer_routes_stale(peer_ip, &afi_safis_to_clear);

        if delta.has_changes() {
            self.propagate_routes(delta, Some(peer_ip)).await;
        }

        // Send full loc-rib to the newly established peer
        let negotiated_afi_safis = capabilities
            .as_ref()
            .map(|caps| caps.afi_safis())
            .unwrap_or_else(|| vec![AfiSafi::new(Afi::Ipv4, Safi::Unicast)]);
        for afi_safi in &negotiated_afi_safis {
            self.resend_routes_to_peer(peer_ip, afi_safi.afi, afi_safi.safi);
        }

        // Signal that loc-rib has been sent for all negotiated AFI/SAFIs
        if let Some(peer_tx) = peer_tx {
            for afi_safi in &negotiated_afi_safis {
                let _ = peer_tx.send(PeerOp::LocalRibSent {
                    afi_safi: *afi_safi,
                });
            }
        }
    }

    async fn handle_add_peer(
        &mut self,
        addr: String,
        config: PeerConfig,
        response: oneshot::Sender<Result<(), String>>,
        bind_addr: SocketAddr,
    ) {
        info!(peer_addr = %addr, "adding peer via request");

        // Parse peer IP address
        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        let peer_addr = SocketAddr::new(peer_ip, config.port);

        // Check if peer already exists
        if self.peers.contains_key(&peer_ip) {
            let _ = response.send(Err(format!("peer {} already exists", peer_ip)));
            return;
        }

        // Create Peer and spawn task (runs forever in Idle state until ManualStart)
        // Passive mode peers only accept incoming connections
        let conn_type = if config.passive_mode {
            ConnectionType::Incoming
        } else {
            ConnectionType::Outgoing
        };

        let peer_tx = self.spawn_peer(peer_addr, config.clone(), bind_addr, conn_type);

        self.peers.insert(
            peer_ip,
            PeerInfo::new(config.clone(), Some(peer_tx.clone()), Some(conn_type)),
        );

        // RFC 4271: ManualStart for admin-added peers
        if config.passive_mode {
            let _ = peer_tx.send(PeerOp::ManualStartPassive);
        } else {
            let _ = peer_tx.send(PeerOp::ManualStart);
        }

        info!(%peer_ip, passive = config.passive_mode, total_peers = self.peers.len(), "peer added");
        let _ = response.send(Ok(()));
    }

    async fn handle_remove_peer(
        &mut self,
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        info!(peer_ip = %addr, "removing peer via request");

        // Parse the address to get IpAddr
        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        // Send graceful shutdown notification to all active connections
        if let Some(entry) = self.peers.get(&peer_ip) {
            entry.send_to_all(|| PeerOp::Shutdown(CeaseSubcode::PeerDeconfigured));
        } else {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        }

        // Send BMP PeerDown before removing peer (if session reached ESTABLISHED)
        if let Some(entry) = self.peers.get(&peer_ip) {
            if let Some(conn) = entry.established_conn() {
                if let (Some(asn), Some(bgp_id)) = (conn.asn, conn.bgp_id) {
                    let use_4byte_asn = peer_supports_4byte_asn(entry);
                    self.broadcast_bmp(BmpOp::PeerDown {
                        peer_ip,
                        peer_as: asn,
                        peer_bgp_id: bgp_id,
                        reason: PeerDownReason::PeerDeConfigured,
                        use_4byte_asn,
                    });
                }
            }
        }

        // Now remove the peer from the map
        self.peers.remove(&peer_ip);

        // Notify Loc-RIB to remove routes from this peer
        let delta = self.loc_rib.remove_routes_from_peer(peer_ip);

        // Propagate route changes (withdrawals or new best paths) to all remaining peers
        self.propagate_routes(delta, None).await;

        let _ = response.send(Ok(()));
    }

    fn handle_disable_peer(&mut self, addr: String, response: oneshot::Sender<Result<(), String>>) {
        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        let Some(entry) = self.peers.get_mut(&peer_ip) else {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        };

        entry.admin_state = AdminState::Down;

        // Stop all active sessions
        entry.send_to_all(|| PeerOp::ManualStop);

        let _ = response.send(Ok(()));
    }

    fn handle_enable_peer(&mut self, addr: String, response: oneshot::Sender<Result<(), String>>) {
        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        let Some(entry) = self.peers.get_mut(&peer_ip) else {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        };

        entry.admin_state = AdminState::Up;

        // RFC 4271: ManualStart for admin-enabled peers (send to all tasks)
        let passive = entry.config.passive_mode;
        entry.send_to_all(|| {
            if passive {
                PeerOp::ManualStartPassive
            } else {
                PeerOp::ManualStart
            }
        });

        let _ = response.send(Ok(()));
    }

    async fn handle_reset_peer(
        &mut self,
        addr: String,
        reset_type: ResetType,
        afi: Option<Afi>,
        safi: Option<Safi>,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        use crate::bgp::multiprotocol::AfiSafi;

        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        let Some(entry) = self.peers.get(&peer_ip) else {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        };

        // Only allow soft reset on Established peers
        if entry.established_conn().is_none() {
            let _ = response.send(Err(format!("peer {} not in Established state", addr)));
            return;
        }

        // Query negotiated capabilities
        let negotiated = match self.get_negotiated_capabilities(entry).await {
            Ok(caps) => caps,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };

        // Determine which AFI/SAFIs to reset based on parameters
        let afi_safis: Vec<AfiSafi> = match (afi, safi) {
            // Both specified: validate it's negotiated
            (Some(afi), Some(safi)) => {
                let requested = AfiSafi::new(afi, safi);
                if !negotiated.contains(&requested) {
                    let _ = response.send(Err(format!(
                        "AFI/SAFI {:?}/{:?} not negotiated with peer {}",
                        afi, safi, addr
                    )));
                    return;
                }
                vec![requested]
            }

            // Any parameter unset: filter negotiated capabilities
            _ => negotiated
                .into_iter()
                .filter(|cap| {
                    afi.is_none_or(|a| cap.afi == a) && safi.is_none_or(|s| cap.safi == s)
                })
                .collect(),
        };

        match reset_type {
            ResetType::SoftIn => {
                self.handle_reset_soft_in(peer_ip, &afi_safis, Some(response));
            }
            ResetType::SoftOut => {
                self.handle_reset_soft_out(peer_ip, &afi_safis, response);
            }
            ResetType::Soft => {
                self.handle_reset_soft_in(peer_ip, &afi_safis, None);
                self.handle_reset_soft_out(peer_ip, &afi_safis, response);
            }
            ResetType::Hard => {
                self.handle_reset_hard(peer_ip, response);
            }
        }
    }

    fn handle_reset_hard(
        &mut self,
        peer_ip: IpAddr,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        let Some(peer) = self.peers.get(&peer_ip) else {
            let _ = response.send(Err(format!("peer {} not found", peer_ip)));
            return;
        };

        // Hard reset only applies to the established connection
        let Some(conn) = peer.established_conn() else {
            let _ = response.send(Err(format!("peer {} has no active task", peer_ip)));
            return;
        };

        let Some(peer_tx) = &conn.peer_tx else {
            let _ = response.send(Err(format!("peer {} has no active task", peer_ip)));
            return;
        };

        if peer_tx.send(PeerOp::HardReset).is_err() {
            let _ = response.send(Err(format!(
                "failed to send hard reset to peer {}",
                peer_ip
            )));
            return;
        }

        info!(%peer_ip, "hard reset initiated");
        let _ = response.send(Ok(()));
    }

    /// Helper to query negotiated capabilities from peer
    async fn get_negotiated_capabilities(
        &self,
        peer_info: &PeerInfo,
    ) -> Result<Vec<AfiSafi>, String> {
        let conn = peer_info
            .established_conn()
            .ok_or_else(|| "peer not established".to_string())?;
        let peer_tx = conn
            .peer_tx
            .as_ref()
            .ok_or_else(|| "peer task not available".to_string())?;

        let (tx, rx) = oneshot::channel();
        peer_tx
            .send(PeerOp::GetNegotiatedCapabilities(tx))
            .map_err(|_| "failed to query peer capabilities".to_string())?;

        let caps = rx
            .await
            .map_err(|_| "failed to get peer capabilities".to_string())?;

        if caps.multiprotocol.is_empty() {
            Err("no negotiated capabilities".to_string())
        } else {
            Ok(caps.multiprotocol.into_iter().collect())
        }
    }

    fn handle_reset_soft_in(
        &mut self,
        peer_ip: IpAddr,
        afi_safis: &[AfiSafi],
        response: Option<oneshot::Sender<Result<(), String>>>,
    ) {
        if let Some(peer_tx) = self
            .peers
            .get(&peer_ip)
            .and_then(|p| p.established_conn())
            .and_then(|c| c.peer_tx.as_ref())
        {
            for afi_safi in afi_safis {
                let _ = peer_tx.send(PeerOp::SendRouteRefresh {
                    afi: afi_safi.afi,
                    safi: afi_safi.safi,
                });
            }
        }
        if let Some(resp) = response {
            let _ = resp.send(Ok(()));
        }
    }

    fn handle_reset_soft_out(
        &mut self,
        peer_ip: IpAddr,
        afi_safis: &[AfiSafi],
        response: oneshot::Sender<Result<(), String>>,
    ) {
        for afi_safi in afi_safis {
            self.resend_routes_to_peer(peer_ip, afi_safi.afi, afi_safi.safi);
        }
        let _ = response.send(Ok(()));
    }

    fn resend_routes_to_peer(&mut self, peer_ip: IpAddr, afi: Afi, safi: Safi) {
        let Some(peer_info) = self.peers.get(&peer_ip) else {
            warn!(%peer_ip, "SOFT_OUT for unknown peer");
            return;
        };

        let Some(conn) = peer_info.established_conn() else {
            return;
        };

        let Some(peer_asn) = conn.asn else {
            return;
        };
        let export_policies = &peer_info.export_policies;
        if export_policies.is_empty() {
            return;
        }
        if safi != Safi::Unicast {
            warn!(?safi, "unsupported SAFI");
            return;
        }

        const CHUNK_SIZE: usize = 10_000;

        if let Some(peer_tx) = &conn.peer_tx {
            let peer_supports_4byte_asn = conn.supports_four_octet_asn();

            let afi_safi = AfiSafi::new(afi, safi);
            let add_path_send = conn.add_path_send_negotiated(&afi_safi);

            let cluster_id = self.config.cluster_id();
            let rr_client = peer_info.config.rr_client;
            let local_next_hop = conn
                .conn_info
                .as_ref()
                .map(|conn_info| conn_info.local_address)
                .unwrap_or(self.local_addr);

            // Collect routes: all paths for ADD-PATH peers, best-only otherwise
            let routes = self.loc_rib.get_paths(afi, add_path_send);

            let mut all_sent = Vec::new();
            let mut total_sent = 0;

            for chunk in routes.chunks(CHUNK_SIZE) {
                let sent = send_announcements_to_peer(
                    peer_ip,
                    peer_tx,
                    chunk,
                    self.config.asn,
                    peer_asn,
                    local_next_hop,
                    export_policies,
                    peer_supports_4byte_asn,
                    rr_client,
                    cluster_id,
                    add_path_send,
                );
                all_sent.extend(sent);
                total_sent += chunk.len();
            }

            info!(%peer_ip, ?afi, total_routes = total_sent, "completed SOFT_OUT reset");

            if let Some(peer) = self.peers.get_mut(&peer_ip) {
                peer.replace_adj_rib_out(afi, all_sent);
            }
        }
    }

    async fn handle_add_route(
        &mut self,
        prefix: IpNetwork,
        attrs: PathAttrs,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        info!(?prefix, next_hop = ?attrs.next_hop, "adding route via request");

        let delta = self.loc_rib.add_local_route(prefix, attrs);

        if delta.has_changes() {
            self.propagate_routes(delta, None).await;
        }

        let _ = response.send(Ok(()));
    }

    async fn handle_remove_route(
        &mut self,
        prefix: IpNetwork,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        info!(?prefix, "removing route via request");

        let delta = self.loc_rib.remove_local_route(prefix);

        if delta.has_changes() {
            self.propagate_routes(delta, None).await;
        }

        let _ = response.send(Ok(()));
    }

    fn handle_get_peers(&self, response: oneshot::Sender<Vec<GetPeersResponse>>) {
        let peers: Vec<GetPeersResponse> = self
            .peers
            .iter()
            .map(|(addr, entry)| {
                let (asn, state) = entry.max_state();
                GetPeersResponse {
                    address: addr.to_string(),
                    asn,
                    state,
                    admin_state: entry.admin_state,
                    import_policies: entry
                        .import_policies
                        .iter()
                        .filter(|p| !p.built_in)
                        .map(|p| p.name.clone())
                        .collect(),
                    export_policies: entry
                        .export_policies
                        .iter()
                        .filter(|p| !p.built_in)
                        .map(|p| p.name.clone())
                        .collect(),
                }
            })
            .collect();
        let _ = response.send(peers);
    }

    async fn handle_get_peer(
        &self,
        addr: String,
        response: oneshot::Sender<Option<GetPeerResponse>>,
    ) {
        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(_) => {
                let _ = response.send(None);
                return;
            }
        };

        let Some(entry) = self.peers.get(&peer_ip) else {
            let _ = response.send(None);
            return;
        };

        let stats = entry.get_statistics().await.unwrap_or_default();
        let (asn, state) = entry.max_state();

        let _ = response.send(Some(GetPeerResponse {
            address: addr,
            asn,
            state,
            admin_state: entry.admin_state,
            import_policies: entry
                .import_policies
                .iter()
                .map(|p| p.name.clone())
                .collect(),
            export_policies: entry
                .export_policies
                .iter()
                .map(|p| p.name.clone())
                .collect(),
            statistics: stats,
        }));
    }

    async fn handle_get_routes(
        &self,
        rib_type: Option<i32>,
        peer_address: Option<String>,
        response: oneshot::Sender<Result<Vec<Route>, String>>,
    ) {
        use crate::grpc::proto::RibType;

        let rib_type_enum = match rib_type {
            Some(t) => RibType::try_from(t).unwrap_or(RibType::Global),
            None => RibType::Global,
        };

        let result = match rib_type_enum {
            RibType::Global => Ok(self.loc_rib.get_all_routes()),
            RibType::AdjIn => self.get_adj_rib_in(peer_address).await,
            RibType::AdjOut => self.compute_adj_rib_out(peer_address),
        };

        let _ = response.send(result);
    }

    async fn handle_get_routes_stream(
        &self,
        rib_type: Option<i32>,
        peer_address: Option<String>,
        tx: mpsc::UnboundedSender<Route>,
    ) {
        use crate::grpc::proto::RibType;

        let rib_type_enum = match rib_type {
            Some(t) => RibType::try_from(t).unwrap_or(RibType::Global),
            None => RibType::Global,
        };

        let routes = match rib_type_enum {
            RibType::Global => Ok(self.loc_rib.get_all_routes()),
            RibType::AdjIn => self.get_adj_rib_in(peer_address).await,
            RibType::AdjOut => self.compute_adj_rib_out(peer_address),
        };

        if let Ok(routes) = routes {
            for route in routes {
                if tx.send(route).is_err() {
                    break; // Client disconnected
                }
            }
        }
    }

    async fn get_adj_rib_in(&self, peer_address: Option<String>) -> Result<Vec<Route>, String> {
        use std::net::IpAddr;

        let peer_addr = peer_address
            .ok_or("peer_address required for ADJ_IN".to_string())?
            .parse::<IpAddr>()
            .map_err(|e| format!("invalid peer address: {}", e))?;

        let peer_info = self
            .peers
            .get(&peer_addr)
            .ok_or(format!("peer {} not found", peer_addr))?;

        let conn = peer_info
            .established_conn()
            .ok_or("peer not established".to_string())?;

        let peer_tx = conn
            .peer_tx
            .as_ref()
            .ok_or("peer task not running".to_string())?;

        // Reuse existing GetAdjRibIn operation
        let (tx, rx) = oneshot::channel();
        peer_tx
            .send(PeerOp::GetAdjRibIn(tx))
            .map_err(|_| "failed to send to peer".to_string())?;

        rx.await.map_err(|_| "peer task closed".to_string())
    }

    fn compute_adj_rib_out(&self, peer_address: Option<String>) -> Result<Vec<Route>, String> {
        let peer_addr = peer_address
            .ok_or("peer_address required for ADJ_OUT".to_string())?
            .parse::<IpAddr>()
            .map_err(|e| format!("invalid peer address: {}", e))?;

        let peer_info = self
            .peers
            .get(&peer_addr)
            .ok_or(format!("peer {} not found", peer_addr))?;

        // Read directly from adj_rib_out (empty if peer isn't established)
        let mut routes_map: HashMap<IpNetwork, Vec<Arc<Path>>> = HashMap::new();
        for ((prefix, _path_id), path) in &peer_info.adj_rib_out {
            routes_map
                .entry(*prefix)
                .or_default()
                .push(Arc::clone(path));
        }

        Ok(routes_map
            .into_iter()
            .map(|(prefix, paths)| Route { prefix, paths })
            .collect())
    }

    fn handle_get_peers_stream(&self, tx: mpsc::UnboundedSender<GetPeersResponse>) {
        for (addr, entry) in self.peers.iter() {
            let (asn, state) = entry.max_state();
            let peer = GetPeersResponse {
                address: addr.to_string(),
                asn,
                state,
                admin_state: entry.admin_state,
                import_policies: entry
                    .import_policies
                    .iter()
                    .filter(|p| !p.built_in)
                    .map(|p| p.name.clone())
                    .collect(),
                export_policies: entry
                    .export_policies
                    .iter()
                    .filter(|p| !p.built_in)
                    .map(|p| p.name.clone())
                    .collect(),
            };
            if tx.send(peer).is_err() {
                break;
            }
        }
    }

    fn get_established_peers(&self) -> Vec<(IpAddr, &PeerInfo)> {
        self.peers
            .iter()
            .filter(|(_, peer_info)| peer_info.established_conn().is_some())
            .map(|(peer_ip, peer_info)| (*peer_ip, peer_info))
            .collect()
    }

    async fn handle_add_bmp_server(
        &mut self,
        addr: SocketAddr,
        statistics_timeout: Option<u64>,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        // Spawn new BmpTask
        let task_tx = self.spawn_bmp_task(addr, statistics_timeout);

        // Store in HashMap
        let task_info = BmpTaskInfo::new(addr, statistics_timeout, task_tx);
        self.bmp_tasks.insert(addr, task_info);

        info!(%addr, "BMP task added");

        // Send initial state to new BMP destination
        let established_peers = self.get_established_peers();
        send_initial_bmp_state_to_task(
            &self.bmp_tasks.get(&addr).unwrap().task_tx,
            established_peers,
            response,
        )
        .await;
    }

    fn handle_remove_bmp_server(
        &mut self,
        addr: SocketAddr,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        if let Some(task_info) = self.bmp_tasks.remove(&addr) {
            drop(task_info.task_tx); // Channel drop triggers graceful shutdown
            info!(%addr, "BMP task removed");
            let _ = response.send(Ok(()));
        } else {
            let _ = response.send(Err(format!("BMP server not found: {}", addr)));
        }
    }

    fn handle_get_bmp_servers(&self, response: oneshot::Sender<Vec<String>>) {
        let addrs: Vec<String> = self.bmp_tasks.keys().map(|a| a.to_string()).collect();
        let _ = response.send(addrs);
    }

    fn send_bmp_route_monitoring(
        &self,
        peer_ip: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        withdrawn: &[IpNetwork],
        announced: &[PrefixPath],
    ) {
        // Determine if peer supports 4-byte ASN to mirror actual BGP encoding
        let use_4byte_asn = self
            .peers
            .get(&peer_ip)
            .map(peer_supports_4byte_asn)
            .unwrap_or(true); // Default to true if peer not found

        // Send withdrawals if any
        if !withdrawn.is_empty() {
            let update = UpdateMessage::new_withdraw(
                withdrawn.to_vec(),
                MessageFormat {
                    use_4byte_asn,
                    add_path: false,
                },
                None,
            );
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
                let update = UpdateMessage::new(
                    &batch.path,
                    batch.prefixes,
                    MessageFormat {
                        use_4byte_asn,
                        add_path: false,
                    },
                );
                self.broadcast_bmp(BmpOp::RouteMonitoring {
                    peer_ip,
                    peer_as,
                    peer_bgp_id,
                    update,
                });
            }
        }
    }

    async fn handle_get_bmp_statistics(&self, response: oneshot::Sender<Vec<BmpPeerStats>>) {
        let mut stats = Vec::new();

        for (peer_ip, peer_info) in self.get_established_peers() {
            let Some(conn) = peer_info.established_conn() else {
                continue;
            };
            let Some(peer_tx) = &conn.peer_tx else {
                continue;
            };
            let Some(asn) = conn.asn else {
                continue;
            };
            let Some(bgp_id) = conn.bgp_id else {
                continue;
            };

            let (tx, rx) = oneshot::channel();
            if peer_tx.send(PeerOp::GetStatistics(tx)).is_err() {
                continue;
            }

            if let Ok(peer_stats) = rx.await {
                stats.push(BmpPeerStats {
                    peer_ip,
                    peer_as: asn,
                    peer_bgp_id: bgp_id,
                    adj_rib_in_count: peer_stats.adj_rib_in_count,
                });
            }
        }

        let _ = response.send(stats);
    }

    // Policy management handlers
    fn handle_add_defined_set(
        &mut self,
        set: crate::config::DefinedSetConfig,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        // Clone current defined sets (clone-on-write pattern)
        let mut new_sets = (*self.policy_ctx.defined_sets).clone();

        // Fail if set already exists
        if new_sets.contains(set.set_type(), set.name()) {
            let _ = response.send(Err(format!("defined set '{}' already exists", set.name())));
            return;
        }

        // Add the set - convert config to runtime type
        match set {
            DefinedSetConfig::PrefixSet(config) => {
                let mut prefix_matches = Vec::new();
                for pm_config in &config.prefixes {
                    match PrefixMatch::new(pm_config) {
                        Ok(pm) => prefix_matches.push(pm),
                        Err(e) => {
                            let _ = response.send(Err(format!("invalid prefix: {}", e)));
                            return;
                        }
                    }
                }
                new_sets.prefix_sets.insert(
                    config.name.clone(),
                    PrefixSet {
                        name: config.name.clone(),
                        prefixes: prefix_matches,
                    },
                );
            }
            DefinedSetConfig::AsPathSet(config) => {
                let mut regexes = Vec::new();
                for pattern in &config.patterns {
                    match Regex::new(pattern) {
                        Ok(r) => regexes.push(r),
                        Err(e) => {
                            let _ =
                                response.send(Err(format!("invalid regex '{}': {}", pattern, e)));
                            return;
                        }
                    }
                }
                new_sets.as_path_sets.insert(
                    config.name.clone(),
                    AsPathSet {
                        name: config.name.clone(),
                        patterns: regexes,
                    },
                );
            }
            DefinedSetConfig::CommunitySet(config) => {
                let mut community_values = Vec::new();
                for comm_str in &config.communities {
                    match parse_community_str(comm_str) {
                        Ok(val) => community_values.push(val),
                        Err(e) => {
                            let _ = response.send(Err(format!("invalid community: {}", e)));
                            return;
                        }
                    }
                }
                new_sets.community_sets.insert(
                    config.name.clone(),
                    CommunitySet {
                        name: config.name.clone(),
                        communities: community_values,
                    },
                );
            }
            DefinedSetConfig::ExtCommunitySet(config) => {
                use crate::bgp::ext_community::parse_extended_community;
                let mut ext_community_values = Vec::new();
                for ec_str in &config.ext_communities {
                    match parse_extended_community(ec_str) {
                        Ok(val) => ext_community_values.push(val),
                        Err(e) => {
                            let _ =
                                response.send(Err(format!("invalid extended community: {}", e)));
                            return;
                        }
                    }
                }
                new_sets.ext_community_sets.insert(
                    config.name.clone(),
                    ExtCommunitySet {
                        name: config.name.clone(),
                        ext_communities: ext_community_values,
                    },
                );
            }
            DefinedSetConfig::NeighborSet(config) => {
                let mut neighbor_addrs = Vec::new();
                for addr_str in &config.neighbors {
                    match IpAddr::from_str(addr_str) {
                        Ok(addr) => neighbor_addrs.push(addr),
                        Err(e) => {
                            let _ = response.send(Err(format!("invalid IP address: {}", e)));
                            return;
                        }
                    }
                }
                new_sets.neighbor_sets.insert(
                    config.name.clone(),
                    NeighborSet {
                        name: config.name.clone(),
                        neighbors: neighbor_addrs,
                    },
                );
            }
            DefinedSetConfig::LargeCommunitySet(config) => {
                use crate::bgp::msg_update_types::parse_large_community;
                let mut large_community_values = Vec::new();
                for lc_str in &config.large_communities {
                    match parse_large_community(lc_str) {
                        Ok(val) => large_community_values.push(val),
                        Err(e) => {
                            let _ = response.send(Err(format!("invalid large community: {}", e)));
                            return;
                        }
                    }
                }
                new_sets.large_community_sets.insert(
                    config.name.clone(),
                    LargeCommunitySet {
                        name: config.name.clone(),
                        large_communities: large_community_values,
                    },
                );
            }
        }

        // Replace the Arc (atomic update)
        self.policy_ctx.defined_sets = Arc::new(new_sets);

        let _ = response.send(Ok(()));
    }

    fn handle_remove_defined_set(
        &mut self,
        set_type: DefinedSetType,
        name: String,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        // Check if any policy references this set
        for (policy_name, policy) in &self.policy_ctx.policies {
            if self.policy_references_set(policy, set_type, &name) {
                let _ = response.send(Err(format!(
                    "cannot remove {}: referenced by policy '{}'",
                    set_type.as_str(),
                    policy_name
                )));
                return;
            }
        }

        // Clone current defined sets (clone-on-write pattern)
        let mut new_sets = (*self.policy_ctx.defined_sets).clone();

        // Delete specific set (idempotent - succeed even if not found)
        new_sets.remove(set_type, &name);
        self.policy_ctx.defined_sets = Arc::new(new_sets);
        let _ = response.send(Ok(()));
    }

    /// Check if a policy references a specific defined set
    fn policy_references_set(
        &self,
        policy: &crate::policy::Policy,
        set_type: DefinedSetType,
        set_name: &str,
    ) -> bool {
        for stmt in policy.statements() {
            // Convert to config to check set references
            let config = stmt.to_config();

            match set_type {
                DefinedSetType::PrefixSet => {
                    if let Some(ref match_set) = config.conditions.match_prefix_set {
                        if match_set.set_name == set_name {
                            return true;
                        }
                    }
                }
                DefinedSetType::NeighborSet => {
                    if let Some(ref match_set) = config.conditions.match_neighbor_set {
                        if match_set.set_name == set_name {
                            return true;
                        }
                    }
                }
                DefinedSetType::AsPathSet => {
                    if let Some(ref match_set) = config.conditions.match_as_path_set {
                        if match_set.set_name == set_name {
                            return true;
                        }
                    }
                }
                DefinedSetType::CommunitySet => {
                    if let Some(ref match_set) = config.conditions.match_community_set {
                        if match_set.set_name == set_name {
                            return true;
                        }
                    }
                }
                DefinedSetType::ExtCommunitySet => {
                    if let Some(ref match_set) = config.conditions.match_ext_community_set {
                        if match_set.set_name == set_name {
                            return true;
                        }
                    }
                }
                DefinedSetType::LargeCommunitySet => {
                    if let Some(ref match_set) = config.conditions.match_large_community_set {
                        if match_set.set_name == set_name {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    fn handle_list_defined_sets(
        &self,
        set_type: Option<DefinedSetType>,
        name: Option<String>,
        response: oneshot::Sender<Vec<crate::config::DefinedSetConfig>>,
    ) {
        use crate::config::{
            AsPathSetConfig, CommunitySetConfig, NeighborSetConfig, PrefixMatchConfig,
            PrefixSetConfig,
        };

        let mut results = Vec::new();

        // Collect prefix sets
        if set_type.is_none() || set_type == Some(DefinedSetType::PrefixSet) {
            for (set_name, prefix_set) in &self.policy_ctx.defined_sets.prefix_sets {
                if name.is_some() && name.as_ref() != Some(set_name) {
                    continue;
                }
                let prefixes = prefix_set
                    .prefixes
                    .iter()
                    .map(|pm| PrefixMatchConfig {
                        prefix: pm.network.to_string(),
                        masklength_range: if pm.min_len == pm.max_len {
                            None
                        } else {
                            Some(format!("{}..{}", pm.min_len, pm.max_len))
                        },
                    })
                    .collect();

                results.push(crate::config::DefinedSetConfig::PrefixSet(
                    PrefixSetConfig {
                        name: set_name.clone(),
                        prefixes,
                    },
                ));
            }
        }

        // Collect neighbor sets
        if set_type.is_none() || set_type == Some(DefinedSetType::NeighborSet) {
            for (set_name, neighbor_set) in &self.policy_ctx.defined_sets.neighbor_sets {
                if name.is_some() && name.as_ref() != Some(set_name) {
                    continue;
                }
                let neighbors = neighbor_set
                    .neighbors
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect();

                results.push(crate::config::DefinedSetConfig::NeighborSet(
                    NeighborSetConfig {
                        name: set_name.clone(),
                        neighbors,
                    },
                ));
            }
        }

        // Collect AS path sets
        if set_type.is_none() || set_type == Some(DefinedSetType::AsPathSet) {
            for (set_name, as_path_set) in &self.policy_ctx.defined_sets.as_path_sets {
                if name.is_some() && name.as_ref() != Some(set_name) {
                    continue;
                }
                let patterns = as_path_set
                    .patterns
                    .iter()
                    .map(|r| r.as_str().to_string())
                    .collect();

                results.push(crate::config::DefinedSetConfig::AsPathSet(
                    AsPathSetConfig {
                        name: set_name.clone(),
                        patterns,
                    },
                ));
            }
        }

        // Collect community sets
        if set_type.is_none() || set_type == Some(DefinedSetType::CommunitySet) {
            for (set_name, community_set) in &self.policy_ctx.defined_sets.community_sets {
                if name.is_some() && name.as_ref() != Some(set_name) {
                    continue;
                }
                let communities = community_set
                    .communities
                    .iter()
                    .map(|c| {
                        let high = (*c >> 16) as u16;
                        let low = (*c & 0xFFFF) as u16;
                        format!("{}:{}", high, low)
                    })
                    .collect();

                results.push(crate::config::DefinedSetConfig::CommunitySet(
                    CommunitySetConfig {
                        name: set_name.clone(),
                        communities,
                    },
                ));
            }
        }

        let _ = response.send(results);
    }

    fn handle_add_policy(
        &mut self,
        name: String,
        statements: Vec<crate::config::StatementConfig>,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        use crate::config::PolicyDefinitionConfig;
        use crate::policy::Policy;

        // Reject policy names starting with underscore (reserved for built-in policies)
        if name.starts_with('_') {
            let _ = response.send(Err(
                "policy names cannot start with underscore (reserved for built-in policies)"
                    .to_string(),
            ));
            return;
        }

        // Build PolicyDefinitionConfig directly from received statements
        let policy_def = PolicyDefinitionConfig {
            name: name.clone(),
            statements,
        };

        // Build Policy from definition using current defined_sets
        match Policy::from_config(&policy_def, &self.policy_ctx.defined_sets) {
            Ok(policy) => {
                self.policy_ctx.policies.insert(name, Arc::new(policy));
                let _ = response.send(Ok(()));
            }
            Err(e) => {
                let _ = response.send(Err(format!("failed to build policy: {}", e)));
            }
        }
    }

    fn handle_remove_policy(
        &mut self,
        name: String,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        // Idempotent - succeed even if policy doesn't exist
        self.policy_ctx.policies.remove(&name);
        let _ = response.send(Ok(()));
    }

    fn handle_list_policies(
        &self,
        name: Option<String>,
        response: oneshot::Sender<Vec<crate::server::PolicyInfoResponse>>,
    ) {
        use crate::server::PolicyInfoResponse;

        let mut results = Vec::new();

        for (policy_name, policy) in &self.policy_ctx.policies {
            if name.is_some() && name.as_ref() != Some(policy_name) {
                continue;
            }

            // Convert compiled statements back to config format
            let statements = policy
                .statements()
                .iter()
                .map(|stmt| stmt.to_config())
                .collect();

            results.push(PolicyInfoResponse {
                name: policy_name.clone(),
                statements,
            });
        }

        let _ = response.send(results);
    }

    fn handle_set_policy_assignment(
        &mut self,
        peer_addr: IpAddr,
        direction: crate::server::PolicyDirection,
        policy_names: Vec<String>,
        _default_action: Option<crate::policy::PolicyResult>,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        // Check if peer exists
        let peer = match self.peers.get_mut(&peer_addr) {
            Some(p) => p,
            None => {
                let _ = response.send(Err(format!("peer {} not found", peer_addr)));
                return;
            }
        };

        // Resolve policy names to Policy objects
        let mut resolved_policies = Vec::new();
        for name in &policy_names {
            match self.policy_ctx.policies.get(name) {
                Some(policy) => resolved_policies.push(policy.clone()),
                None => {
                    let _ = response.send(Err(format!("policy '{}' not found", name)));
                    return;
                }
            }
        }

        // Update peer's policy list
        match direction {
            PolicyDirection::Import => {
                peer.import_policies = resolved_policies;
            }
            PolicyDirection::Export => {
                peer.export_policies = resolved_policies;
            }
        }

        let _ = response.send(Ok(()));
    }
}

/// Parse community string in format "65000:100" or decimal
fn parse_community_str(s: &str) -> Result<u32, String> {
    // Try decimal format first
    if let Ok(val) = s.parse::<u32>() {
        return Ok(val);
    }

    // Try "65000:100" format
    if let Some((high, low)) = s.split_once(':') {
        let high_val = high
            .parse::<u16>()
            .map_err(|_| format!("invalid high part '{}'", high))?;
        let low_val = low
            .parse::<u16>()
            .map_err(|_| format!("invalid low part '{}'", low))?;
        return Ok((high_val as u32) << 16 | (low_val as u32));
    }

    Err(format!(
        "invalid community format '{}' (expected '65000:100' or decimal)",
        s
    ))
}

/// Determine if peer supports 4-byte ASN for BMP encoding
fn peer_supports_4byte_asn(peer_info: &PeerInfo) -> bool {
    peer_info
        .established_conn()
        .and_then(|c| c.capabilities.as_ref())
        .map(|caps| caps.supports_four_octet_asn())
        .unwrap_or(true) // Default to true if not negotiated (BMP is newer protocol)
}

/// Convert routes to UpdateMessages, batching by shared path attributes
fn routes_to_update_messages(routes: &[Route], use_4byte_asn: bool) -> Vec<UpdateMessage> {
    // Convert routes to (prefix, path) tuples for batching
    let announcements: Vec<PrefixPath> = routes
        .iter()
        .flat_map(|route| {
            route
                .paths
                .iter()
                .map(|path| (route.prefix, Arc::clone(path)))
        })
        .collect();

    // Batch announcements by path attributes
    let batches = batch_announcements_by_path(&announcements);

    // Convert each batch to an UpdateMessage
    batches
        .into_iter()
        .map(|batch| {
            UpdateMessage::new(
                &batch.path,
                batch.prefixes,
                MessageFormat {
                    use_4byte_asn,
                    add_path: false,
                },
            )
        })
        .collect()
}

/// Query peer's Adj-RIB-In
async fn get_peer_adj_rib_in(peer_tx: &mpsc::UnboundedSender<PeerOp>) -> Result<Vec<Route>, ()> {
    let (tx, rx) = oneshot::channel();
    let _ = peer_tx.send(PeerOp::GetAdjRibIn(tx));
    rx.await.map_err(|_| ())
}

/// Send initial BMP messages for existing peers after BMP server connects
async fn send_initial_bmp_state_to_task(
    task_tx: &mpsc::UnboundedSender<Arc<BmpOp>>,
    established_peers: Vec<(IpAddr, &PeerInfo)>,
    response: oneshot::Sender<Result<(), String>>,
) {
    // Send all PeerUp messages first
    for (peer_ip, peer_info) in &established_peers {
        let Some(conn) = peer_info.established_conn() else {
            continue;
        };
        if let (Some(asn), Some(bgp_id), Some(conn_info)) = (conn.asn, conn.bgp_id, &conn.conn_info)
        {
            let use_4byte_asn = peer_supports_4byte_asn(peer_info);
            let _ = task_tx.send(Arc::new(BmpOp::PeerUp {
                peer_ip: *peer_ip,
                peer_as: asn,
                peer_bgp_id: bgp_id,
                local_address: conn_info.local_address,
                local_port: conn_info.local_port,
                remote_port: conn_info.remote_port,
                sent_open: conn_info.sent_open.clone(),
                received_open: conn_info.received_open.clone(),
                use_4byte_asn,
            }));
        }
    }

    // Then send all RouteMonitoring messages
    for (peer_ip, peer_info) in established_peers {
        let Some(conn) = peer_info.established_conn() else {
            continue;
        };
        if let (Some(asn), Some(bgp_id), Some(peer_tx)) = (conn.asn, conn.bgp_id, &conn.peer_tx) {
            if let Ok(routes) = get_peer_adj_rib_in(peer_tx).await {
                let use_4byte_asn = peer_supports_4byte_asn(peer_info);
                let updates = routes_to_update_messages(&routes, use_4byte_asn);
                for update in updates {
                    let _ = task_tx.send(Arc::new(BmpOp::RouteMonitoring {
                        peer_ip,
                        peer_as: asn,
                        peer_bgp_id: bgp_id,
                        update,
                    }));
                }
            }
        }
    }
    let _ = response.send(Ok(()));
}

impl BgpServer {
    async fn handle_route_refresh(&mut self, peer_ip: std::net::IpAddr, afi: Afi, safi: Safi) {
        info!(%peer_ip, ?afi, ?safi, "processing ROUTE_REFRESH");

        // Get peer info
        let Some(peer_info) = self.peers.get(&peer_ip) else {
            warn!(%peer_ip, "ROUTE_REFRESH from unknown peer");
            return;
        };

        // Only process if peer is Established
        let Some(conn) = peer_info.established_conn() else {
            warn!(%peer_ip, "ROUTE_REFRESH from non-Established peer");
            return;
        };

        let Some(peer_asn) = conn.asn else {
            warn!(%peer_ip, "ROUTE_REFRESH before ASN known");
            return;
        };

        let export_policies = &peer_info.export_policies;
        if export_policies.is_empty() {
            warn!(%peer_ip, "export policies not initialized");
            return;
        }

        // Only Unicast SAFI is supported currently
        if safi != Safi::Unicast {
            warn!(?safi, "unsupported SAFI requested");
            return;
        }

        const CHUNK_SIZE: usize = 10_000;

        info!(%peer_ip, ?afi, ?safi, chunk_size = CHUNK_SIZE, "processing ROUTE_REFRESH with chunking");

        if let Some(peer_tx) = &conn.peer_tx {
            let peer_supports_4byte_asn = conn.supports_four_octet_asn();

            let afi_safi = AfiSafi::new(afi, safi);
            let add_path_send = conn.add_path_send_negotiated(&afi_safi);

            let cluster_id = self.config.cluster_id();
            let rr_client = peer_info.config.rr_client;
            let local_next_hop = conn
                .conn_info
                .as_ref()
                .map(|conn_info| conn_info.local_address)
                .unwrap_or(self.local_addr);

            // Collect routes: all paths for ADD-PATH peers, best-only otherwise
            let routes = self.loc_rib.get_paths(afi, add_path_send);

            let mut all_sent = Vec::new();
            let mut total_sent = 0;

            for chunk in routes.chunks(CHUNK_SIZE) {
                let sent = send_announcements_to_peer(
                    peer_ip,
                    peer_tx,
                    chunk,
                    self.config.asn,
                    peer_asn,
                    local_next_hop,
                    export_policies,
                    peer_supports_4byte_asn,
                    rr_client,
                    cluster_id,
                    add_path_send,
                );
                all_sent.extend(sent);
                total_sent += chunk.len();
            }

            info!(%peer_ip, total_routes = total_sent, "completed ROUTE_REFRESH");

            if let Some(peer) = self.peers.get_mut(&peer_ip) {
                peer.replace_adj_rib_out(afi, all_sent);
            }
        }
    }
}
