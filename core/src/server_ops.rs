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
use crate::bgp::utils::IpNetwork;
use crate::config::PeerConfig;
use crate::peer::{BgpState, PeerOp};
use crate::policy::Policy;
use crate::rib::Route;
use crate::server::{
    AdminState, BgpServer, BmpOp, ConnectionInfo, ConnectionType, GetPeerResponse,
    GetPeersResponse, MgmtOp, PeerInfo, ServerOp,
};
use crate::types::PeerDownReason;
use crate::{error, info};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::sync::oneshot;

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
            MgmtOp::GetRoutes { response } => {
                self.handle_get_routes(response);
            }
            MgmtOp::GetServerInfo { response } => {
                let _ = response.send((self.local_addr, self.local_port));
            }
            MgmtOp::AddBmpServer { addr, response } => {
                self.handle_add_bmp_server(addr, response);
            }
            MgmtOp::RemoveBmpServer { addr, response } => {
                self.handle_remove_bmp_server(addr, response);
            }
            MgmtOp::GetBmpServers { response } => {
                self.handle_get_bmp_servers(response);
            }
        }
    }

    pub(crate) async fn handle_server_op(&mut self, op: ServerOp) {
        match op {
            ServerOp::PeerStateChanged { peer_ip, state } => {
                // Update session state
                if let Some(peer) = self.peers.get_mut(&peer_ip) {
                    peer.state = state;
                    info!("peer state changed", "peer_ip" => &peer_ip, "state" => format!("{:?}", state));

                    // Send BMP PeerUp when transitioning to Established
                    if state == BgpState::Established {
                        if let (Some(asn), Some(bgp_id), Some(conn_info)) =
                            (peer.asn, peer.bgp_id, &peer.conn_info)
                        {
                            let _ = self.bmp_tx.send(BmpOp::PeerUp {
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
                if let Some(peer) = self.peers.get_mut(&peer_ip) {
                    peer.asn = Some(asn);
                    peer.import_policy = Some(Policy::default_in(self.config.asn));
                    peer.export_policy = Some(Policy::default_out(self.config.asn, asn));
                    info!("peer handshake complete", "peer_ip" => &peer_ip, "asn" => asn);
                }
            }
            ServerOp::PeerUpdate {
                peer_ip,
                withdrawn,
                announced,
            } => {
                let peer = self.peers.get(&peer_ip).expect("peer should exist");

                if let Some(policy) = peer.policy_in() {
                    let changed_prefixes = self.loc_rib.update_from_peer(
                        peer_ip,
                        withdrawn,
                        announced,
                        |prefix, path| policy.accept(prefix, path),
                    );
                    info!("UPDATE processing complete", "peer_ip" => &peer_ip);

                    // Propagate changed routes to other peers
                    if !changed_prefixes.is_empty() {
                        self.propagate_routes(changed_prefixes, Some(peer_ip)).await;
                    }
                } else {
                    error!("received UPDATE before handshake complete", "peer_ip" => &peer_ip);
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
                    info!("peer session ended", "peer_ip" => &peer_ip);
                } else {
                    // Unconfigured peer: stop task and remove entirely
                    if let Some(peer_tx) = peer.peer_tx.take() {
                        let _ = peer_tx.send(PeerOp::ManualStop);
                    }
                    self.peers.remove(&peer_ip);
                    info!("unconfigured peer removed", "peer_ip" => &peer_ip, "total_peers" => self.peers.len());
                }

                // Notify Loc-RIB about disconnection and get affected prefixes
                let changed_prefixes = self.loc_rib.remove_routes_from_peer(peer_ip);

                // Propagate withdrawals to other peers
                if !changed_prefixes.is_empty() {
                    self.propagate_routes(changed_prefixes, Some(peer_ip)).await;
                }

                // BMP: Peer Down notification (only if session reached ESTABLISHED)
                if let Some((peer_as, peer_bgp_id)) = bmp_peer_info {
                    let _ = self.bmp_tx.send(BmpOp::PeerDown {
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
                    info!("collision: outgoing wins, dropping pending incoming", "peer_ip" => peer_ip.to_string());
                    drop(pending_stream);
                } else {
                    // Incoming wins - resolve_collision already closed outgoing
                    info!("collision: incoming wins, switching connection", "peer_ip" => peer_ip.to_string());
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
        info!("adding peer via request", "peer_addr" => &addr);

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

        info!("peer added", "peer_ip" => peer_ip.to_string(), "passive" => config.passive_mode, "total_peers" => self.peers.len());
        let _ = response.send(Ok(()));
    }

    async fn handle_remove_peer(
        &mut self,
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        info!("removing peer via request", "peer_ip" => &addr);

        // Parse the address to get IpAddr
        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        // Get peer entry (keep it in map for now to send BMP PeerDown)
        let entry = self.peers.get_mut(&peer_ip);

        if entry.is_none() {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        }

        let entry = entry.unwrap();

        // Send BMP PeerDown before removing peer (if session reached ESTABLISHED)
        if let (Some(asn), Some(bgp_id)) = (entry.asn, entry.bgp_id) {
            let _ = self.bmp_tx.send(BmpOp::PeerDown {
                peer_ip,
                peer_as: asn as u32,
                peer_bgp_id: bgp_id,
                reason: PeerDownReason::PeerDeConfigured,
            });
        }

        // Send graceful shutdown notification if peer_tx is active
        if let Some(peer_tx) = &entry.peer_tx {
            let _ = peer_tx.send(PeerOp::Shutdown(CeaseSubcode::PeerDeconfigured));
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
        info!("adding route via request", "prefix" => format!("{:?}", prefix), "next_hop" => next_hop.to_string());

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
        info!("removing route via request", "prefix" => format!("{:?}", prefix));

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

    fn handle_get_routes(&self, response: oneshot::Sender<Vec<crate::rib::Route>>) {
        let routes = self.loc_rib.get_all_routes();
        let _ = response.send(routes);
    }
}

/// Convert routes to UpdateMessages, batching by shared path attributes
fn routes_to_update_messages(routes: &[Route]) -> Vec<UpdateMessage> {
    use crate::peer::outgoing::batch_announcements_by_path;
    use std::sync::Arc;

    // Convert routes to (prefix, path) tuples for batching
    let announcements: Vec<(IpNetwork, Arc<crate::rib::Path>)> = routes
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

impl BgpServer {
    fn handle_add_bmp_server(&self, addr: String, response: oneshot::Sender<Result<(), String>>) {
        let sock_addr: SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(e) => {
                let _ = response.send(Err(format!("invalid BMP server address: {}", e)));
                return;
            }
        };

        // Collect all established peers' info
        let mut existing_peers = Vec::new();
        let mut peer_route_queries = Vec::new();
        for (peer_ip, peer_info) in &self.peers {
            if peer_info.state == BgpState::Established {
                if let (Some(asn), Some(bgp_id), Some(conn_info), Some(peer_tx)) = (
                    peer_info.asn,
                    peer_info.bgp_id,
                    &peer_info.conn_info,
                    &peer_info.peer_tx,
                ) {
                    existing_peers.push(BmpOp::PeerUp {
                        peer_ip: *peer_ip,
                        peer_as: asn as u32,
                        peer_bgp_id: bgp_id,
                        local_address: conn_info.local_address,
                        local_port: conn_info.local_port,
                        remote_port: conn_info.remote_port,
                        sent_open: conn_info.sent_open.clone(),
                        received_open: conn_info.received_open.clone(),
                    });

                    // Query this peer for routes asynchronously
                    let (routes_tx, routes_rx) = oneshot::channel();
                    let _ = peer_tx.send(PeerOp::GetAdjRibIn(routes_tx));
                    peer_route_queries.push((*peer_ip, asn as u32, bgp_id, routes_rx));
                }
            }
        }

        let (tx, rx) = oneshot::channel();
        let bmp_tx = self.bmp_tx.clone();
        let sys_name = self.config.sys_name();
        let sys_descr = self.config.sys_descr();

        // Send AddDestination
        let _ = bmp_tx.send(BmpOp::AddDestination {
            addr: sock_addr,
            sys_name,
            sys_descr,
            response: tx,
        });

        tokio::spawn(async move {
            match rx.await {
                Ok(Ok(())) => {
                    // After destination is added, send PeerUp for existing peers
                    for peer_up in existing_peers {
                        let _ = bmp_tx.send(peer_up);
                    }

                    // Collect routes from each peer and send RouteMonitoring
                    for (peer_ip, peer_as, peer_bgp_id, routes_rx) in peer_route_queries {
                        if let Ok(routes) = routes_rx.await {
                            let updates = routes_to_update_messages(&routes);
                            for update in updates {
                                let _ = bmp_tx.send(BmpOp::RouteMonitoring {
                                    peer_ip,
                                    peer_as,
                                    peer_bgp_id,
                                    update,
                                });
                            }
                        }
                    }
                    let _ = response.send(Ok(()));
                }
                Ok(Err(e)) => {
                    let _ = response.send(Err(e));
                }
                Err(_) => {
                    let _ = response.send(Err("BMP sender task not responding".to_string()));
                }
            }
        });
    }

    fn handle_remove_bmp_server(
        &self,
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        let sock_addr: SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(e) => {
                let _ = response.send(Err(format!("invalid BMP server address: {}", e)));
                return;
            }
        };

        let (tx, rx) = oneshot::channel();
        let _ = self.bmp_tx.send(BmpOp::RemoveDestination {
            addr: sock_addr,
            response: tx,
        });

        tokio::spawn(async move {
            match rx.await {
                Ok(Ok(())) => {
                    let _ = response.send(Ok(()));
                }
                Ok(Err(e)) => {
                    let _ = response.send(Err(e));
                }
                Err(_) => {
                    let _ = response.send(Err("BMP sender task not responding".to_string()));
                }
            }
        });
    }

    fn handle_get_bmp_servers(&self, response: oneshot::Sender<Vec<String>>) {
        let (tx, rx) = oneshot::channel();
        let _ = self.bmp_tx.send(BmpOp::GetDestinations { response: tx });

        tokio::spawn(async move {
            match rx.await {
                Ok(addrs) => {
                    let _ = response.send(addrs);
                }
                Err(_) => {
                    let _ = response.send(Vec::new());
                }
            }
        });
    }
}
