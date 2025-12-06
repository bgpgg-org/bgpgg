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
use crate::bgp::msg_update::{AsPathSegment, Origin};
use crate::bgp::utils::IpNetwork;
use crate::config::Config;
use crate::fsm::BgpState;
use crate::net::{create_and_bind_tcp_socket, ipv4_from_sockaddr};
use crate::peer::{MaxPrefixSetting, Peer, PeerOp, PeerStatistics};
use crate::policy::Policy;
use crate::propagate::{
    send_announcements_to_peer, send_withdrawals_to_peer, should_propagate_to_peer,
};
use crate::rib::rib_loc::LocRib;
use crate::{error, info};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

// Management operations that can be sent to the BGP server
pub enum MgmtOp {
    AddPeer {
        addr: String,
        max_prefix_setting: Option<MaxPrefixSetting>,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemovePeer {
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    DisablePeer {
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    EnablePeer {
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    AddRoute {
        prefix: IpNetwork,
        next_hop: Ipv4Addr,
        origin: Origin,
        as_path: Vec<AsPathSegment>,
        local_pref: Option<u32>,
        med: Option<u32>,
        atomic_aggregate: bool,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemoveRoute {
        prefix: IpNetwork,
        response: oneshot::Sender<Result<(), String>>,
    },
    GetPeers {
        response: oneshot::Sender<Vec<(String, Option<u16>, BgpState, bool)>>,
    },
    GetPeer {
        addr: String,
        response: oneshot::Sender<Option<(String, Option<u16>, BgpState, bool, PeerStatistics)>>,
    },
    GetRoutes {
        response: oneshot::Sender<Vec<crate::rib::Route>>,
    },
    GetServerInfo {
        response: oneshot::Sender<(Ipv4Addr, u16)>,
    },
}

// Server operations sent from peer tasks to the main server loop
pub enum ServerOp {
    PeerStateChanged {
        peer_ip: String,
        state: BgpState,
    },
    PeerHandshakeComplete {
        peer_ip: String,
        asn: u16,
    },
    PeerUpdate {
        peer_ip: String,
        withdrawn: Vec<IpNetwork>,
        announced: Vec<(IpNetwork, crate::rib::Path)>,
    },
    PeerDisconnected {
        peer_ip: String,
    },
}

/// Peer configuration and state stored in server's HashMap.
/// The peer address is the HashMap key, not stored here.
pub struct PeerInfo {
    pub remote_addr: Option<SocketAddr>,
    pub admin_down: bool,
    pub configured: bool,
    pub asn: Option<u16>,
    pub import_policy: Option<Policy>,
    pub export_policy: Option<Policy>,
    pub max_prefix_setting: Option<MaxPrefixSetting>,
    pub state: BgpState,
    pub peer_tx: Option<mpsc::UnboundedSender<PeerOp>>,
}

impl PeerInfo {
    pub async fn get_statistics(&self) -> Option<PeerStatistics> {
        let peer_tx = self.peer_tx.as_ref()?;
        let (tx, rx) = oneshot::channel();
        peer_tx.send(PeerOp::GetStatistics(tx)).ok()?;
        rx.await.ok()
    }

    pub fn policy_in(&self) -> Option<&Policy> {
        self.import_policy.as_ref()
    }

    pub fn policy_out(&self) -> Option<&Policy> {
        self.export_policy.as_ref()
    }
}

pub struct BgpServer {
    peers: HashMap<String, PeerInfo>,
    loc_rib: LocRib,
    config: Config,
    local_bgp_id: u32,
    local_addr: Ipv4Addr,
    local_port: u16,
    pub mgmt_tx: mpsc::Sender<MgmtOp>,
    mgmt_rx: mpsc::Receiver<MgmtOp>,
    op_tx: mpsc::UnboundedSender<ServerOp>,
    op_rx: mpsc::UnboundedReceiver<ServerOp>,
}

impl BgpServer {
    pub fn new(config: Config) -> Self {
        let local_bgp_id = u32::from(config.router_id);
        let sock_addr: SocketAddr = config.listen_addr.parse().expect("invalid listen_addr");
        let local_addr = match sock_addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => panic!("IPv6 listen_addr not supported"),
        };

        let (mgmt_tx, mgmt_rx) = mpsc::channel(100);
        let (op_tx, op_rx) = mpsc::unbounded_channel();

        BgpServer {
            peers: HashMap::new(),
            loc_rib: LocRib::new(),
            config,
            local_bgp_id,
            local_addr,
            local_port: sock_addr.port(),
            mgmt_tx,
            mgmt_rx,
            op_tx,
            op_rx,
        }
    }

    pub async fn run(mut self) {
        info!("BGP server starting", "listen_addr" => &self.config.listen_addr);

        let listener = TcpListener::bind(&self.config.listen_addr).await.unwrap();
        self.local_port = listener.local_addr().unwrap().port();

        let local_addr = SocketAddr::new(self.local_addr.into(), 0);
        let local_asn = self.config.asn;
        let local_bgp_id = self.local_bgp_id;
        let hold_time = self.config.hold_time_secs as u16;

        loop {
            tokio::select! {
                // Handle incoming BGP connections
                Ok((stream, _)) = listener.accept() => {
                    self.accept_peer(stream, local_asn, local_bgp_id, hold_time).await;
                }

                // Handle management requests
                Some(req) = self.mgmt_rx.recv() => {
                    self.handle_mgmt_op(req, local_addr).await;
                }

                // Handle server operations from peers
                Some(op) = self.op_rx.recv() => {
                    self.handle_server_op(op).await;
                }
            }
        }
    }

    async fn accept_peer(
        &mut self,
        stream: TcpStream,
        local_asn: u16,
        local_bgp_id: u32,
        local_hold_time: u16,
    ) {
        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!("failed to get peer address", "error" => e.to_string());
                return;
            }
        };

        // Extract just the IP address (no port) to use as peer identifier
        let peer_ip = peer_addr.ip().to_string();

        info!("new peer connection", "peer_ip" => &peer_ip);

        let local_ip = match stream.local_addr().ok().and_then(ipv4_from_sockaddr) {
            Some(ip) => ip,
            None => {
                error!("failed to get local IPv4 address");
                return;
            }
        };

        let (tcp_rx, tcp_tx) = stream.into_split();

        // Create channel for server -> peer communication
        let (peer_tx, peer_rx) = mpsc::unbounded_channel();
        let server_tx = self.op_tx.clone();

        // Create peer task in Connect state
        let peer = Peer::new(
            peer_ip.clone(),
            tcp_tx,
            tcp_rx,
            peer_rx,
            server_tx,
            local_asn,
            local_hold_time,
            local_bgp_id,
            local_ip,
            None, // No max_prefix for incoming connections
        );

        let initial_state = peer.state();

        // Add dynamic peer (configured = false, will be removed on disconnect)
        let entry = PeerInfo {
            remote_addr: None,
            admin_down: false,
            configured: false,
            asn: None,
            import_policy: None,
            export_policy: None,
            max_prefix_setting: None,
            state: initial_state,
            peer_tx: Some(peer_tx),
        };

        self.peers.insert(peer_ip.clone(), entry);
        info!("peer added", "peer_ip" => &peer_ip, "state" => format!("{:?}", initial_state), "total_peers" => self.peers.len());

        // Spawn peer task - handshake happens inside run()
        tokio::spawn(peer.run());
    }

    async fn handle_mgmt_op(&mut self, req: MgmtOp, local_addr: SocketAddr) {
        match req {
            MgmtOp::AddPeer {
                addr,
                max_prefix_setting,
                response,
            } => {
                self.handle_add_peer(addr, max_prefix_setting, response, local_addr)
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
        }
    }

    async fn handle_server_op(&mut self, op: ServerOp) {
        match op {
            ServerOp::PeerStateChanged { peer_ip, state } => {
                // Update session state
                if let Some(peer) = self.peers.get_mut(&peer_ip) {
                    peer.state = state;
                    info!("peer state changed", "peer_ip" => &peer_ip, "state" => format!("{:?}", state));
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
                        peer_ip.clone(),
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
            ServerOp::PeerDisconnected { peer_ip } => {
                // Check if peer is configured or dynamic
                let should_remove = self
                    .peers
                    .get(&peer_ip)
                    .map(|p| !p.configured)
                    .unwrap_or(true);

                if should_remove {
                    // Dynamic peer: remove entirely
                    self.peers.remove(&peer_ip);
                    info!("dynamic peer removed", "peer_ip" => &peer_ip, "total_peers" => self.peers.len());
                } else {
                    // Configured peer: clear session but keep peer
                    if let Some(peer) = self.peers.get_mut(&peer_ip) {
                        peer.peer_tx = None;
                        peer.state = BgpState::Idle;
                    }
                    info!("peer session ended", "peer_ip" => &peer_ip);
                }

                // Notify Loc-RIB about disconnection and get affected prefixes
                let changed_prefixes = self.loc_rib.remove_routes_from_peer(peer_ip.clone());

                // Propagate withdrawals to other peers
                if !changed_prefixes.is_empty() {
                    self.propagate_routes(changed_prefixes, Some(peer_ip)).await;
                }
            }
        }
    }

    async fn handle_add_peer(
        &mut self,
        addr: String,
        max_prefix_setting: Option<MaxPrefixSetting>,
        response: oneshot::Sender<Result<(), String>>,
        local_addr: SocketAddr,
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

        // Create socket, bind to local address, and connect to peer
        let stream = match create_and_bind_tcp_socket(local_addr, peer_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!("failed to connect to peer", "peer_addr" => peer_addr, "error" => e.to_string());
                let _ = response.send(Err(format!("failed to connect: {}", e)));
                return;
            }
        };

        let peer_ip = peer_addr.ip().to_string();
        info!("connected to peer", "peer_ip" => &peer_ip);

        let (tcp_rx, tcp_tx) = stream.into_split();

        let local_asn = self.config.asn;
        let local_bgp_id = self.local_bgp_id;
        let local_hold_time = self.config.hold_time_secs as u16;
        let local_ip = ipv4_from_sockaddr(local_addr).expect("local_addr must be IPv4");

        // Create channel for server -> peer communication
        let (peer_tx, peer_rx) = mpsc::unbounded_channel();
        let server_tx = self.op_tx.clone();

        // Create peer task in Connect state
        let peer = Peer::new(
            peer_ip.clone(),
            tcp_tx,
            tcp_rx,
            peer_rx,
            server_tx,
            local_asn,
            local_hold_time,
            local_bgp_id,
            local_ip,
            max_prefix_setting,
        );

        let initial_state = peer.state();

        // Add configured peer (configured = true, persists on disconnect)
        let entry = PeerInfo {
            remote_addr: Some(peer_addr),
            admin_down: false,
            configured: true,
            asn: None,
            import_policy: None,
            export_policy: None,
            max_prefix_setting,
            state: initial_state,
            peer_tx: Some(peer_tx),
        };

        self.peers.insert(peer_ip.clone(), entry);
        info!("peer added", "peer_ip" => &peer_ip, "state" => format!("{:?}", initial_state), "total_peers" => self.peers.len());

        // Connection successful, send response
        let _ = response.send(Ok(()));

        // Spawn peer task - handshake happens inside run()
        tokio::spawn(peer.run());
    }

    async fn handle_remove_peer(
        &mut self,
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        info!("removing peer via request", "peer_ip" => &addr);

        // Remove entry from map
        let entry = self.peers.remove(&addr);

        if entry.is_none() {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        }

        // Send graceful shutdown notification if peer_tx is active
        let entry = entry.unwrap();
        if let Some(peer_tx) = entry.peer_tx {
            let _ = peer_tx.send(PeerOp::Shutdown(CeaseSubcode::PeerDeconfigured));
        }

        // Notify Loc-RIB to remove routes from this peer
        let changed_prefixes = self.loc_rib.remove_routes_from_peer(addr.clone());

        // Propagate route changes (withdrawals or new best paths) to all remaining peers
        self.propagate_routes(
            changed_prefixes,
            None, // Don't exclude any peer since the removed peer is already gone
        )
        .await;

        let _ = response.send(Ok(()));
    }

    fn handle_disable_peer(&mut self, addr: String, response: oneshot::Sender<Result<(), String>>) {
        let Some(entry) = self.peers.get_mut(&addr) else {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        };

        entry.admin_down = true;

        // Shutdown active session if exists
        if let Some(peer_tx) = &entry.peer_tx {
            let _ = peer_tx.send(PeerOp::Shutdown(CeaseSubcode::AdministrativeShutdown));
        }

        let _ = response.send(Ok(()));
    }

    fn handle_enable_peer(&mut self, addr: String, response: oneshot::Sender<Result<(), String>>) {
        let Some(entry) = self.peers.get_mut(&addr) else {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        };

        entry.admin_down = false;
        // TODO: Initiate reconnection if configured peer with no active session
        let _ = response.send(Ok(()));
    }

    async fn handle_add_route(
        &mut self,
        prefix: IpNetwork,
        next_hop: Ipv4Addr,
        origin: Origin,
        as_path: Vec<AsPathSegment>,
        local_pref: Option<u32>,
        med: Option<u32>,
        atomic_aggregate: bool,
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

    fn handle_get_peers(
        &self,
        response: oneshot::Sender<Vec<(String, Option<u16>, BgpState, bool)>>,
    ) {
        let peers: Vec<(String, Option<u16>, BgpState, bool)> = self
            .peers
            .iter()
            .map(|(addr, entry)| (addr.clone(), entry.asn, entry.state, entry.admin_down))
            .collect();
        let _ = response.send(peers);
    }

    async fn handle_get_peer(
        &self,
        addr: String,
        response: oneshot::Sender<Option<(String, Option<u16>, BgpState, bool, PeerStatistics)>>,
    ) {
        let Some(entry) = self.peers.get(&addr) else {
            let _ = response.send(None);
            return;
        };

        let stats = entry.get_statistics().await.unwrap_or_default();

        let _ = response.send(Some((
            addr,
            entry.asn,
            entry.state,
            entry.admin_down,
            stats,
        )));
    }

    fn handle_get_routes(&self, response: oneshot::Sender<Vec<crate::rib::Route>>) {
        let routes = self.loc_rib.get_all_routes();
        let _ = response.send(routes);
    }

    /// Propagate route changes to all established peers (except the originating peer)
    /// If originating_peer is None, propagates to all peers (used for locally originated routes)
    async fn propagate_routes(
        &mut self,
        changed_prefixes: Vec<IpNetwork>,
        originating_peer: Option<String>,
    ) {
        let local_asn = self.config.asn;

        // For each changed prefix, determine what to send
        let mut to_announce = Vec::new();
        let mut to_withdraw = Vec::new();

        for prefix in changed_prefixes {
            if let Some(best_path) = self.loc_rib.get_best_path(&prefix) {
                // We have a best path - prepare announcement
                to_announce.push((prefix, best_path.clone()));
            } else {
                // No path exists - prepare withdrawal
                to_withdraw.push(prefix);
            }
        }

        // Send updates to all established peers (except the originating peer)
        for (peer_addr, entry) in self.peers.iter() {
            if !should_propagate_to_peer(peer_addr, entry.state, &originating_peer) {
                continue;
            }

            // Need active peer_tx to send updates
            let Some(peer_tx) = &entry.peer_tx else {
                continue;
            };

            // Get peer ASN, default to local ASN if not yet known
            let peer_asn = entry.asn.unwrap_or(local_asn);

            // Export policy should always be Some for Established peers
            if let Some(export_policy) = entry.policy_out() {
                send_withdrawals_to_peer(peer_addr, peer_tx, &to_withdraw);
                send_announcements_to_peer(
                    peer_addr,
                    peer_tx,
                    &to_announce,
                    local_asn,
                    peer_asn,
                    self.local_addr,
                    export_policy,
                );
            } else {
                error!("export policy not set for established peer", "peer_ip" => peer_addr);
            }
        }
    }
}
