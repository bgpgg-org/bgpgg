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

use crate::bgp::msg_notification::CeaseSubcode;
use crate::bgp::msg_update::{AsPathSegment, Origin, UpdateMessage};
use crate::config::PeerConfig;
use crate::net::IpNetwork;
use crate::peer::outgoing::{
    batch_announcements_by_path, compute_routes_for_peer, should_propagate_to_peer,
};
use crate::peer::{BgpState, PeerOp};
use crate::rib::{Path, Route, RouteSource};
use crate::server::{
    AdminState, BgpServer, BmpOp, BmpPeerStats, BmpTaskInfo, ConnectionInfo, ConnectionType,
    GetPeerResponse, GetPeersResponse, MgmtOp, PeerInfo, ServerOp,
};
use crate::types::PeerDownReason;
use crate::{error, info};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
            MgmtOp::AddRoute {
                prefix,
                next_hop,
                origin,
                as_path,
                local_pref,
                med,
                atomic_aggregate,
                communities,
                response,
            } => {
                self.handle_add_route(
                    prefix,
                    next_hop,
                    origin,
                    as_path,
                    local_pref,
                    med,
                    atomic_aggregate,
                    communities,
                    response,
                )
                .await;
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
            MgmtOp::AddDefinedSet {
                set_type,
                name,
                set_data,
                replace,
                response,
            } => {
                self.handle_add_defined_set(set_type, name, set_data, replace, response);
            }
            MgmtOp::RemoveDefinedSet {
                set_type,
                name,
                all,
                response,
            } => {
                self.handle_remove_defined_set(set_type, name, all, response);
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
            ServerOp::PeerStateChanged { peer_ip, state } => {
                if let Some(peer) = self.peers.get_mut(&peer_ip) {
                    peer.state = state;
                    info!(&self.logger, "peer state changed", "peer_ip" => &peer_ip, "state" => format!("{:?}", state));
                }

                // Send BMP PeerUp when transitioning to Established
                if state == BgpState::Established {
                    if let Some(peer) = self.peers.get(&peer_ip) {
                        if let (Some(asn), Some(bgp_id), Some(conn_info)) =
                            (peer.asn, peer.bgp_id, &peer.conn_info)
                        {
                            self.broadcast_bmp(BmpOp::PeerUp {
                                peer_ip,
                                peer_as: asn as u32,
                                peer_bgp_id: bgp_id,
                                local_address: conn_info.local_address,
                                local_port: conn_info.local_port,
                                remote_port: conn_info.remote_port,
                                sent_open: conn_info.sent_open.clone(),
                                received_open: conn_info.received_open.clone(),
                            });
                        }
                    }
                }
            }
            ServerOp::PeerHandshakeComplete { peer_ip, asn } => {
                // Update ASN and initialize policies
                // Clone config for immutable access, then mutate peer
                if let Some(peer_config) = self.peers.get(&peer_ip).map(|p| p.config.clone()) {
                    let import_policies = self.resolve_import_policies(&peer_config);
                    let export_policies = self.resolve_export_policies(&peer_config, asn);

                    if let Some(peer) = self.peers.get_mut(&peer_ip) {
                        peer.asn = Some(asn);
                        peer.import_policies = import_policies;
                        peer.export_policies = export_policies;
                        info!(&self.logger, "peer handshake complete", "peer_ip" => &peer_ip, "asn" => asn);
                    }
                }
            }
            ServerOp::PeerUpdate {
                peer_ip,
                withdrawn,
                announced,
            } => {
                let peer = self.peers.get(&peer_ip).expect("peer should exist");

                // Extract peer info before mutable operations
                let peer_asn = peer.asn;
                let peer_bgp_id = peer.bgp_id;

                let import_policies = peer.policy_in();
                if !import_policies.is_empty() {
                    let changed_prefixes = self.loc_rib.update_from_peer(
                        peer_ip,
                        withdrawn.clone(),
                        announced.clone(),
                        |prefix, path| {
                            // Evaluate policies in order until Accept/Reject
                            for policy in import_policies {
                                match policy.evaluate(prefix, path) {
                                    crate::policy::PolicyResult::Accept => return true,
                                    crate::policy::PolicyResult::Reject => return false,
                                    crate::policy::PolicyResult::Continue => continue,
                                }
                            }
                            false // All policies returned Continue -> default reject
                        },
                    );
                    info!(&self.logger, "UPDATE processing complete", "peer_ip" => &peer_ip);

                    // Propagate changed routes to other peers
                    if !changed_prefixes.is_empty() {
                        self.propagate_routes(changed_prefixes, Some(peer_ip)).await;
                    }

                    // BMP: Send route monitoring for this update
                    if let (Some(asn), Some(bgp_id)) = (peer_asn, peer_bgp_id) {
                        self.send_bmp_route_monitoring(
                            peer_ip, asn as u32, bgp_id, &withdrawn, &announced,
                        );
                    }
                } else {
                    error!(&self.logger, "received UPDATE before handshake complete", "peer_ip" => &peer_ip);
                }
            }
            ServerOp::OpenReceived {
                peer_ip,
                bgp_id,
                conn_type,
            } => {
                self.handle_open_received(peer_ip, bgp_id, conn_type);
            }
            ServerOp::PeerConnectionInfo {
                peer_ip,
                local_address,
                local_port,
                remote_port,
                sent_open,
                received_open,
            } => {
                if let Some(peer) = self.peers.get_mut(&peer_ip) {
                    peer.conn_info = Some(ConnectionInfo {
                        sent_open,
                        received_open,
                        local_address,
                        local_port,
                        remote_port,
                    });
                }
            }
            ServerOp::PeerDisconnected { peer_ip, reason } => {
                let Some(peer) = self.peers.get_mut(&peer_ip) else {
                    return;
                };

                // Extract peer info for BMP before potentially removing the peer
                // Only send BMP PeerDown if session reached ESTABLISHED (has both AS and BGP ID)
                let bmp_peer_info = match (peer.asn, peer.bgp_id) {
                    (Some(asn), Some(bgp_id)) => Some((asn as u32, bgp_id)),
                    _ => None,
                };

                if peer.configured {
                    // Configured peer: update state, Peer task handles reconnection internally
                    peer.state = BgpState::Idle;
                    peer.conn_info = None;
                    info!(&self.logger, "peer session ended", "peer_ip" => &peer_ip);
                } else {
                    // Unconfigured peer: stop task and remove entirely
                    if let Some(peer_tx) = peer.peer_tx.take() {
                        let _ = peer_tx.send(PeerOp::ManualStop);
                    }
                    self.peers.remove(&peer_ip);
                    info!(&self.logger, "unconfigured peer removed", "peer_ip" => &peer_ip, "total_peers" => self.peers.len());
                }

                // Notify Loc-RIB about disconnection and get affected prefixes
                let changed_prefixes = self.loc_rib.remove_routes_from_peer(peer_ip);

                // Propagate withdrawals to other peers
                if !changed_prefixes.is_empty() {
                    self.propagate_routes(changed_prefixes, Some(peer_ip)).await;
                }

                // BMP: Peer Down notification (only if session reached ESTABLISHED)
                if let Some((peer_as, peer_bgp_id)) = bmp_peer_info {
                    self.broadcast_bmp(BmpOp::PeerDown {
                        peer_ip,
                        peer_as,
                        peer_bgp_id,
                        reason,
                    });
                }
            }
            ServerOp::SetAdminState { peer_ip, state } => {
                if let Some(peer) = self.peers.get_mut(&peer_ip) {
                    peer.admin_state = state;
                }
            }
            ServerOp::GetBmpStatistics { response } => {
                self.handle_get_bmp_statistics(response).await;
            }
        }
    }

    /// Handle OPEN message received - store BGP ID and resolve deferred collisions (RFC 4271 6.8)
    fn handle_open_received(&mut self, peer_ip: IpAddr, bgp_id: u32, conn_type: ConnectionType) {
        if let Some(peer) = self.peers.get_mut(&peer_ip) {
            peer.bgp_id = Some(bgp_id);
        }

        // RFC 4271 6.8: Resolve deferred collision if pending incoming exists
        if conn_type == ConnectionType::Outgoing {
            let pending = self
                .peers
                .get_mut(&peer_ip)
                .and_then(|p| p.pending_incoming.take());
            if let Some(pending_stream) = pending {
                // Now we have BGP ID - reuse existing collision resolution logic
                if self.resolve_collision(peer_ip, ConnectionType::Incoming) {
                    // Outgoing wins - drop pending incoming
                    info!(&self.logger, "collision: outgoing wins, dropping pending incoming", "peer_ip" => peer_ip.to_string());
                    drop(pending_stream);
                } else {
                    // Incoming wins - resolve_collision already closed outgoing
                    info!(&self.logger, "collision: incoming wins, switching connection", "peer_ip" => peer_ip.to_string());
                    self.accept_incoming_connection(pending_stream, peer_ip);
                }
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
        info!(&self.logger, "adding peer via request", "peer_addr" => &addr);

        // Parse peer address
        let peer_addr = match addr.parse::<SocketAddr>() {
            Ok(a) => a,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        let peer_ip = peer_addr.ip();

        // Check if peer already exists
        if self.peers.contains_key(&peer_ip) {
            let _ = response.send(Err(format!("peer {} already exists", peer_ip)));
            return;
        }

        // Create Peer and spawn task (runs forever in Idle state until ManualStart)
        let peer_tx = self.spawn_peer(peer_addr, config.clone(), bind_addr);

        self.peers.insert(
            peer_ip,
            PeerInfo::new(true, config.clone(), Some(peer_tx.clone())),
        );

        // RFC 4271: ManualStart for admin-added peers
        if config.passive_mode {
            let _ = peer_tx.send(PeerOp::ManualStartPassive);
        } else {
            let _ = peer_tx.send(PeerOp::ManualStart);
        }

        info!(&self.logger, "peer added", "peer_ip" => peer_ip.to_string(), "passive" => config.passive_mode, "total_peers" => self.peers.len());
        let _ = response.send(Ok(()));
    }

    async fn handle_remove_peer(
        &mut self,
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        info!(&self.logger, "removing peer via request", "peer_ip" => &addr);

        // Parse the address to get IpAddr
        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        // Send graceful shutdown notification if peer_tx is active
        if let Some(entry) = self.peers.get(&peer_ip) {
            if let Some(peer_tx) = &entry.peer_tx {
                let _ = peer_tx.send(PeerOp::Shutdown(CeaseSubcode::PeerDeconfigured));
            }
        } else {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        }

        // Send BMP PeerDown before removing peer (if session reached ESTABLISHED)
        if let Some(entry) = self.peers.get(&peer_ip) {
            if let (Some(asn), Some(bgp_id)) = (entry.asn, entry.bgp_id) {
                self.broadcast_bmp(BmpOp::PeerDown {
                    peer_ip,
                    peer_as: asn as u32,
                    peer_bgp_id: bgp_id,
                    reason: PeerDownReason::PeerDeConfigured,
                });
            }
        }

        // Now remove the peer from the map
        self.peers.remove(&peer_ip);

        // Notify Loc-RIB to remove routes from this peer
        let changed_prefixes = self.loc_rib.remove_routes_from_peer(peer_ip);

        // Propagate route changes (withdrawals or new best paths) to all remaining peers
        self.propagate_routes(
            changed_prefixes,
            None, // Don't exclude any peer since the removed peer is already gone
        )
        .await;

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

        // Stop active session if exists
        if let Some(peer_tx) = &entry.peer_tx {
            let _ = peer_tx.send(PeerOp::ManualStop);
        }

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

        // RFC 4271: ManualStart for admin-enabled peers
        if let Some(peer_tx) = &entry.peer_tx {
            if entry.config.passive_mode {
                let _ = peer_tx.send(PeerOp::ManualStartPassive);
            } else {
                let _ = peer_tx.send(PeerOp::ManualStart);
            }
        }

        let _ = response.send(Ok(()));
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_add_route(
        &mut self,
        prefix: IpNetwork,
        next_hop: Ipv4Addr,
        origin: Origin,
        as_path: Vec<AsPathSegment>,
        local_pref: Option<u32>,
        med: Option<u32>,
        atomic_aggregate: bool,
        communities: Vec<u32>,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        info!(&self.logger, "adding route via request", "prefix" => format!("{:?}", prefix), "next_hop" => next_hop.to_string());

        // Add route to Loc-RIB (locally originated if as_path is empty, otherwise with specified AS_PATH)
        self.loc_rib.add_local_route(
            prefix,
            next_hop,
            origin,
            as_path,
            local_pref,
            med,
            atomic_aggregate,
            communities,
        );

        // Propagate to all peers using the common propagation logic
        self.propagate_routes(vec![prefix], None).await;

        let _ = response.send(Ok(()));
    }

    async fn handle_remove_route(
        &mut self,
        prefix: IpNetwork,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        info!(&self.logger, "removing route via request", "prefix" => format!("{:?}", prefix));

        // Remove local route from Loc-RIB
        let removed = self.loc_rib.remove_local_route(prefix);

        // Only propagate if something was actually removed
        if removed {
            // Propagate to all peers using the common propagation logic
            // This will automatically send withdrawal if no alternate path exists,
            // or announce the new best path if an alternate path is available
            self.propagate_routes(vec![prefix], None).await;
        }

        let _ = response.send(Ok(()));
    }

    fn handle_get_peers(&self, response: oneshot::Sender<Vec<GetPeersResponse>>) {
        let peers: Vec<GetPeersResponse> = self
            .peers
            .iter()
            .map(|(addr, entry)| GetPeersResponse {
                address: addr.to_string(),
                asn: entry.asn,
                state: entry.state,
                admin_state: entry.admin_state,
                configured: entry.configured,
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

        let _ = response.send(Some(GetPeerResponse {
            address: addr,
            asn: entry.asn,
            state: entry.state,
            admin_state: entry.admin_state,
            configured: entry.configured,
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

        let peer_tx = peer_info
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

        let peer_asn = peer_info.asn.ok_or("peer ASN not set".to_string())?;

        let export_policies = &peer_info.export_policies;
        if export_policies.is_empty() {
            return Err("export policies not initialized".to_string());
        }

        // Build to_announce list from ALL loc_rib routes (same as propagation)
        let mut to_announce = Vec::new();
        for route in self.loc_rib.iter_routes() {
            if let Some(best_path) = self.loc_rib.get_best_path(&route.prefix) {
                // Extract originating_peer from path.source
                let originating_peer = match best_path.source {
                    RouteSource::Ebgp(addr) | RouteSource::Ibgp(addr) => Some(addr),
                    RouteSource::Local => None,
                };

                // Apply EXACT same check as propagation
                if !should_propagate_to_peer(peer_addr, peer_info.state, originating_peer) {
                    continue;
                }

                to_announce.push((route.prefix, best_path.clone()));
            }
        }

        // Use EXACT same filtering + transformation logic
        let filtered = compute_routes_for_peer(
            &to_announce,
            self.config.asn,
            peer_asn,
            self.config.router_id,
            export_policies,
        );

        // Group by prefix for Route struct
        let mut routes_map: HashMap<IpNetwork, Vec<Path>> = HashMap::new();
        for (prefix, path) in filtered {
            routes_map.entry(prefix).or_default().push(path);
        }

        let adj_out_routes: Vec<Route> = routes_map
            .into_iter()
            .map(|(prefix, paths)| Route {
                prefix,
                paths: paths.into_iter().map(Arc::new).collect(),
            })
            .collect();

        Ok(adj_out_routes)
    }

    fn handle_get_peers_stream(&self, tx: mpsc::UnboundedSender<GetPeersResponse>) {
        for (addr, entry) in self.peers.iter() {
            let peer = GetPeersResponse {
                address: addr.to_string(),
                asn: entry.asn,
                state: entry.state,
                admin_state: entry.admin_state,
                configured: entry.configured,
            };
            if tx.send(peer).is_err() {
                break;
            }
        }
    }

    fn get_established_peers(&self) -> Vec<(IpAddr, &PeerInfo)> {
        self.peers
            .iter()
            .filter(|(_, peer_info)| peer_info.state == BgpState::Established)
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

        info!(&self.logger, "BMP task added", "addr" => &addr.to_string());

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
            info!(&self.logger, "BMP task removed", "addr" => &addr.to_string());
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
        announced: &[(IpNetwork, Arc<Path>)],
    ) {
        // Send withdrawals if any
        if !withdrawn.is_empty() {
            let update = UpdateMessage::new_withdraw(withdrawn.to_vec());
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
                    batch.path.origin,
                    batch.path.as_path.clone(),
                    batch.path.next_hop,
                    batch.prefixes,
                    batch.path.local_pref,
                    batch.path.med,
                    batch.path.atomic_aggregate,
                    batch.path.communities.clone(),
                    batch.path.unknown_attrs.clone(),
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
            let Some(peer_tx) = &peer_info.peer_tx else {
                continue;
            };
            let Some(asn) = peer_info.asn else {
                continue;
            };
            let Some(bgp_id) = peer_info.bgp_id else {
                continue;
            };

            let (tx, rx) = oneshot::channel();
            if peer_tx.send(PeerOp::GetStatistics(tx)).is_err() {
                continue;
            }

            if let Ok(peer_stats) = rx.await {
                stats.push(BmpPeerStats {
                    peer_ip,
                    peer_as: asn as u32,
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
        set_type: String,
        name: String,
        set_data: crate::server::DefinedSetData,
        replace: bool,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        use crate::policy::sets::{AsPathSet, CommunitySet, NeighborSet, PrefixMatch, PrefixSet};
        use regex::Regex;
        use std::net::IpAddr;
        use std::str::FromStr;

        // Clone current defined sets (clone-on-write pattern)
        let mut new_sets = (*self.defined_sets).clone();

        // Check if set already exists (if not replace)
        let exists = match set_type.as_str() {
            "prefix-set" => new_sets.prefix_sets.contains_key(&name),
            "as-path-set" => new_sets.as_path_sets.contains_key(&name),
            "community-set" => new_sets.community_sets.contains_key(&name),
            "neighbor-set" => new_sets.neighbor_sets.contains_key(&name),
            _ => {
                let _ = response.send(Err(format!("invalid set type: {}", set_type)));
                return;
            }
        };

        if exists && !replace {
            let _ = response.send(Err(format!("defined set '{}' already exists", name)));
            return;
        }

        // Add or update the set
        match set_type.as_str() {
            "prefix-set" => {
                if let crate::server::DefinedSetData::PrefixSet(prefixes) = set_data {
                    let mut prefix_matches = Vec::new();
                    for p in prefixes {
                        let pm_config = crate::config::PrefixMatchConfig {
                            prefix: p.prefix,
                            masklength_range: p.masklength_range,
                        };
                        match PrefixMatch::new(&pm_config) {
                            Ok(pm) => prefix_matches.push(pm),
                            Err(e) => {
                                let _ = response.send(Err(format!("invalid prefix: {}", e)));
                                return;
                            }
                        }
                    }
                    new_sets.prefix_sets.insert(
                        name.clone(),
                        PrefixSet {
                            name: name.clone(),
                            prefixes: prefix_matches,
                        },
                    );
                } else {
                    let _ = response.send(Err("mismatched set data type".to_string()));
                    return;
                }
            }
            "as-path-set" => {
                if let crate::server::DefinedSetData::AsPathSet(patterns) = set_data {
                    let mut regexes = Vec::new();
                    for pattern in &patterns {
                        match Regex::new(pattern) {
                            Ok(r) => regexes.push(r),
                            Err(e) => {
                                let _ = response.send(Err(format!(
                                    "invalid regex pattern '{}': {}",
                                    pattern, e
                                )));
                                return;
                            }
                        }
                    }
                    new_sets.as_path_sets.insert(
                        name.clone(),
                        AsPathSet {
                            name: name.clone(),
                            patterns: regexes,
                        },
                    );
                } else {
                    let _ = response.send(Err("mismatched set data type".to_string()));
                    return;
                }
            }
            "community-set" => {
                if let crate::server::DefinedSetData::CommunitySet(communities) = set_data {
                    let mut community_values = Vec::new();
                    for comm_str in &communities {
                        match parse_community_str(comm_str) {
                            Ok(val) => community_values.push(val),
                            Err(e) => {
                                let _ = response.send(Err(format!("invalid community: {}", e)));
                                return;
                            }
                        }
                    }
                    new_sets.community_sets.insert(
                        name.clone(),
                        CommunitySet {
                            name: name.clone(),
                            communities: community_values,
                        },
                    );
                } else {
                    let _ = response.send(Err("mismatched set data type".to_string()));
                    return;
                }
            }
            "neighbor-set" => {
                if let crate::server::DefinedSetData::NeighborSet(addresses) = set_data {
                    let mut neighbor_addrs = Vec::new();
                    for addr_str in &addresses {
                        match IpAddr::from_str(addr_str) {
                            Ok(addr) => neighbor_addrs.push(addr),
                            Err(e) => {
                                let _ = response.send(Err(format!("invalid IP address: {}", e)));
                                return;
                            }
                        }
                    }
                    new_sets.neighbor_sets.insert(
                        name.clone(),
                        NeighborSet {
                            name: name.clone(),
                            neighbors: neighbor_addrs,
                        },
                    );
                } else {
                    let _ = response.send(Err("mismatched set data type".to_string()));
                    return;
                }
            }
            _ => {
                let _ = response.send(Err(format!("invalid set type: {}", set_type)));
                return;
            }
        }

        // Replace the Arc (atomic update)
        self.defined_sets = Arc::new(new_sets);

        let _ = response.send(Ok(()));
    }

    fn handle_remove_defined_set(
        &mut self,
        set_type: String,
        name: String,
        all: bool,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        // Clone current defined sets (clone-on-write pattern)
        let mut new_sets = (*self.defined_sets).clone();

        if all {
            // Delete all sets of this type
            match set_type.as_str() {
                "prefix-set" => new_sets.prefix_sets.clear(),
                "as-path-set" => new_sets.as_path_sets.clear(),
                "community-set" => new_sets.community_sets.clear(),
                "neighbor-set" => new_sets.neighbor_sets.clear(),
                _ => {
                    let _ = response.send(Err(format!("invalid set type: {}", set_type)));
                    return;
                }
            }
            self.defined_sets = Arc::new(new_sets);
            let _ = response.send(Ok(()));
        } else {
            // Delete specific set
            let removed = match set_type.as_str() {
                "prefix-set" => new_sets.prefix_sets.remove(&name).is_some(),
                "as-path-set" => new_sets.as_path_sets.remove(&name).is_some(),
                "community-set" => new_sets.community_sets.remove(&name).is_some(),
                "neighbor-set" => new_sets.neighbor_sets.remove(&name).is_some(),
                _ => {
                    let _ = response.send(Err(format!("invalid set type: {}", set_type)));
                    return;
                }
            };

            if removed {
                self.defined_sets = Arc::new(new_sets);
                let _ = response.send(Ok(()));
            } else {
                let _ = response.send(Err(format!("defined set '{}' not found", name)));
            }
        }
    }

    fn handle_list_defined_sets(
        &self,
        set_type: Option<String>,
        name: Option<String>,
        response: oneshot::Sender<Vec<crate::server::DefinedSetInfoResponse>>,
    ) {
        use crate::server::{DefinedSetData, DefinedSetInfoResponse, PrefixMatchData};

        let mut results = Vec::new();

        // Collect prefix sets
        if set_type.is_none() || set_type.as_deref() == Some("prefix-set") {
            for (set_name, prefix_set) in &self.defined_sets.prefix_sets {
                if name.is_some() && name.as_ref() != Some(set_name) {
                    continue;
                }
                let prefixes = prefix_set
                    .prefixes
                    .iter()
                    .map(|pm| PrefixMatchData {
                        prefix: pm.network.to_string(),
                        masklength_range: if pm.min_len == pm.max_len {
                            None
                        } else {
                            Some(format!("{}..{}", pm.min_len, pm.max_len))
                        },
                    })
                    .collect();

                results.push(DefinedSetInfoResponse {
                    set_type: "prefix-set".to_string(),
                    name: set_name.clone(),
                    data: DefinedSetData::PrefixSet(prefixes),
                });
            }
        }

        // Collect neighbor sets
        if set_type.is_none() || set_type.as_deref() == Some("neighbor-set") {
            for (set_name, neighbor_set) in &self.defined_sets.neighbor_sets {
                if name.is_some() && name.as_ref() != Some(set_name) {
                    continue;
                }
                let addresses = neighbor_set
                    .neighbors
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect();

                results.push(DefinedSetInfoResponse {
                    set_type: "neighbor-set".to_string(),
                    name: set_name.clone(),
                    data: DefinedSetData::NeighborSet(addresses),
                });
            }
        }

        // Collect AS path sets
        if set_type.is_none() || set_type.as_deref() == Some("as-path-set") {
            for (set_name, as_path_set) in &self.defined_sets.as_path_sets {
                if name.is_some() && name.as_ref() != Some(set_name) {
                    continue;
                }
                let patterns = as_path_set
                    .patterns
                    .iter()
                    .map(|r| r.as_str().to_string())
                    .collect();

                results.push(DefinedSetInfoResponse {
                    set_type: "as-path-set".to_string(),
                    name: set_name.clone(),
                    data: DefinedSetData::AsPathSet(patterns),
                });
            }
        }

        // Collect community sets
        if set_type.is_none() || set_type.as_deref() == Some("community-set") {
            for (set_name, community_set) in &self.defined_sets.community_sets {
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

                results.push(DefinedSetInfoResponse {
                    set_type: "community-set".to_string(),
                    name: set_name.clone(),
                    data: DefinedSetData::CommunitySet(communities),
                });
            }
        }

        let _ = response.send(results);
    }

    fn handle_add_policy(
        &mut self,
        name: String,
        statements: Vec<crate::server::PolicyStatementConfig>,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        use crate::config::PolicyDefinitionConfig;
        use crate::policy::Policy;

        // Convert PolicyStatementConfig to StatementDefinitionConfig
        let mut stmt_defs = Vec::new();
        for stmt in statements {
            match self.policy_statement_config_to_definition(stmt) {
                Ok(def) => stmt_defs.push(def),
                Err(e) => {
                    let _ = response.send(Err(format!("invalid statement config: {}", e)));
                    return;
                }
            }
        }

        // Build PolicyDefinitionConfig
        let policy_def = PolicyDefinitionConfig {
            name: name.clone(),
            statements: stmt_defs,
        };

        // Build Policy from definition using current defined_sets
        match Policy::from_config(&policy_def, &self.defined_sets) {
            Ok(policy) => {
                self.policies.insert(name, Arc::new(policy));
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
        if self.policies.remove(&name).is_some() {
            let _ = response.send(Ok(()));
        } else {
            let _ = response.send(Err(format!("policy '{}' not found", name)));
        }
    }

    fn handle_list_policies(
        &self,
        name: Option<String>,
        response: oneshot::Sender<Vec<crate::server::PolicyInfoResponse>>,
    ) {
        use crate::server::PolicyInfoResponse;

        // Note: We can't easily reconstruct full PolicyInfoResponse from compiled Policy objects
        // because they don't store the original config. For now, return empty info.
        // Full implementation would require storing PolicyDefinitionConfig alongside Policy.

        let mut results = Vec::new();

        for policy_name in self.policies.keys() {
            if name.is_some() && name.as_ref() != Some(policy_name) {
                continue;
            }

            results.push(PolicyInfoResponse {
                name: policy_name.clone(),
                statements: vec![], // Cannot reconstruct from compiled Policy
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
            match self.policies.get(name) {
                Some(policy) => resolved_policies.push(policy.clone()),
                None => {
                    let _ = response.send(Err(format!("policy '{}' not found", name)));
                    return;
                }
            }
        }

        // Update peer's policy list
        match direction {
            crate::server::PolicyDirection::Import => {
                peer.import_policies = resolved_policies;
            }
            crate::server::PolicyDirection::Export => {
                peer.export_policies = resolved_policies;
            }
        }

        let _ = response.send(Ok(()));
    }

    // Helper method to convert PolicyStatementConfig to StatementDefinitionConfig
    fn policy_statement_config_to_definition(
        &self,
        stmt: crate::server::PolicyStatementConfig,
    ) -> Result<crate::config::StatementDefinitionConfig, String> {
        use crate::config::{
            ActionsDefinitionConfig, ConditionsDefinitionConfig, MatchOptionConfig,
            MatchSetRefConfig, StatementDefinitionConfig,
        };

        let conditions = stmt
            .conditions
            .unwrap_or(crate::server::PolicyConditionsConfig {
                match_prefix_set: None,
                match_neighbor_set: None,
                match_as_path_set: None,
                match_community_set: None,
                prefix: None,
                neighbor: None,
            });

        let conditions_def = ConditionsDefinitionConfig {
            match_prefix_set: conditions
                .match_prefix_set
                .map(|(name, opt)| MatchSetRefConfig {
                    set_name: name,
                    match_option: match opt.as_str() {
                        "any" => MatchOptionConfig::Any,
                        "all" => MatchOptionConfig::All,
                        "invert" => MatchOptionConfig::Invert,
                        _ => MatchOptionConfig::Any,
                    },
                }),
            match_neighbor_set: conditions.match_neighbor_set.map(|(name, opt)| {
                MatchSetRefConfig {
                    set_name: name,
                    match_option: match opt.as_str() {
                        "any" => MatchOptionConfig::Any,
                        "all" => MatchOptionConfig::All,
                        "invert" => MatchOptionConfig::Invert,
                        _ => MatchOptionConfig::Any,
                    },
                }
            }),
            match_as_path_set: conditions
                .match_as_path_set
                .map(|(name, opt)| MatchSetRefConfig {
                    set_name: name,
                    match_option: match opt.as_str() {
                        "any" => MatchOptionConfig::Any,
                        "all" => MatchOptionConfig::All,
                        "invert" => MatchOptionConfig::Invert,
                        _ => MatchOptionConfig::Any,
                    },
                }),
            match_community_set: conditions.match_community_set.map(|(name, opt)| {
                MatchSetRefConfig {
                    set_name: name,
                    match_option: match opt.as_str() {
                        "any" => MatchOptionConfig::Any,
                        "all" => MatchOptionConfig::All,
                        "invert" => MatchOptionConfig::Invert,
                        _ => MatchOptionConfig::Any,
                    },
                }
            }),
            prefix: conditions.prefix,
            neighbor: conditions.neighbor,
            has_asn: None,
            route_type: None,
            community: None,
        };

        let actions_def = stmt.actions.unwrap_or(crate::server::PolicyActionsConfig {
            accept: None,
            reject: None,
            local_pref: None,
            med: None,
            add_communities: vec![],
            remove_communities: vec![],
        });

        let actions = ActionsDefinitionConfig {
            local_pref: actions_def
                .local_pref
                .map(crate::config::LocalPrefActionConfig::Set),
            med: actions_def.med.map(crate::config::MedActionConfig::Set),
            community: if !actions_def.add_communities.is_empty()
                || !actions_def.remove_communities.is_empty()
            {
                Some(crate::config::CommunityActionConfig {
                    operation: if !actions_def.add_communities.is_empty() {
                        "add".to_string()
                    } else {
                        "remove".to_string()
                    },
                    communities: if !actions_def.add_communities.is_empty() {
                        actions_def.add_communities
                    } else {
                        actions_def.remove_communities
                    },
                })
            } else {
                None
            },
            accept: actions_def.accept,
            reject: actions_def.reject,
        };

        Ok(StatementDefinitionConfig {
            name: None,
            conditions: conditions_def,
            actions,
        })
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

/// Convert routes to UpdateMessages, batching by shared path attributes
fn routes_to_update_messages(routes: &[Route]) -> Vec<UpdateMessage> {
    // Convert routes to (prefix, path) tuples for batching
    let announcements: Vec<(IpNetwork, Arc<Path>)> = routes
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
                batch.path.origin,
                batch.path.as_path.clone(),
                batch.path.next_hop,
                batch.prefixes,
                batch.path.local_pref,
                batch.path.med,
                batch.path.atomic_aggregate,
                batch.path.communities.clone(),
                batch.path.unknown_attrs.clone(),
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
        if let (Some(asn), Some(bgp_id), Some(conn_info)) =
            (peer_info.asn, peer_info.bgp_id, &peer_info.conn_info)
        {
            let _ = task_tx.send(Arc::new(BmpOp::PeerUp {
                peer_ip: *peer_ip,
                peer_as: asn as u32,
                peer_bgp_id: bgp_id,
                local_address: conn_info.local_address,
                local_port: conn_info.local_port,
                remote_port: conn_info.remote_port,
                sent_open: conn_info.sent_open.clone(),
                received_open: conn_info.received_open.clone(),
            }));
        }
    }

    // Then send all RouteMonitoring messages
    for (peer_ip, peer_info) in established_peers {
        if let (Some(asn), Some(bgp_id), Some(peer_tx)) =
            (peer_info.asn, peer_info.bgp_id, &peer_info.peer_tx)
        {
            if let Ok(routes) = get_peer_adj_rib_in(peer_tx).await {
                let updates = routes_to_update_messages(&routes);
                for update in updates {
                    let _ = task_tx.send(Arc::new(BmpOp::RouteMonitoring {
                        peer_ip,
                        peer_as: asn as u32,
                        peer_bgp_id: bgp_id,
                        update,
                    }));
                }
            }
        }
    }
    let _ = response.send(Ok(()));
}
