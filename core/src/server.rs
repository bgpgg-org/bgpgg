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

use crate::bgp::msg_update::{AsPathSegment, Origin};
use crate::bgp::utils::IpNetwork;
use crate::config::Config;
use crate::fsm::BgpState;
use crate::net::{create_and_bind_tcp_socket, ipv4_from_sockaddr};
use crate::peer::{Peer, PeerOp, PeerStatistics};
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
        response: oneshot::Sender<Result<(), String>>,
    },
    RemovePeer {
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
        response: oneshot::Sender<Vec<(String, Option<u16>, BgpState)>>,
    },
    GetPeer {
        addr: String,
        response: oneshot::Sender<Option<(String, Option<u16>, BgpState, PeerStatistics)>>,
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

// Information about a peer
pub struct PeerInfo {
    pub addr: String,
    pub asn: Option<u16>,
    pub state: BgpState,
    pub peer_tx: mpsc::UnboundedSender<PeerOp>,
    pub import_policy: Option<Policy>,
    pub export_policy: Option<Policy>,
}

impl PeerInfo {
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

        // Create peer in Connect state - it owns the handshake
        let server_tx = self.op_tx.clone();
        let (peer, peer_tx) = Peer::new(
            peer_ip.clone(),
            tcp_tx,
            tcp_rx,
            server_tx,
            local_asn,
            local_hold_time,
            local_bgp_id,
            local_ip,
        );

        // Add to HashMap IMMEDIATELY - asn is None until handshake completes
        let peer_info = PeerInfo {
            addr: peer_ip.clone(),
            asn: None, // Will be set when ServerOp::PeerHandshakeComplete received
            state: peer.state(),
            peer_tx: peer_tx.clone(),
            import_policy: None, // Will be set when ServerOp::PeerHandshakeComplete received
            export_policy: None, // Will be set when ServerOp::PeerHandshakeComplete received
        };

        self.peers.insert(peer_ip.clone(), peer_info);
        info!("peer added", "peer_ip" => &peer_ip, "state" => format!("{:?}", peer.state()), "total_peers" => self.peers.len());

        // Spawn peer task - handshake happens inside run()
        tokio::spawn(peer.run());
    }

    async fn handle_mgmt_op(&mut self, req: MgmtOp, local_addr: SocketAddr) {
        match req {
            MgmtOp::AddPeer { addr, response } => {
                self.handle_add_peer(addr, response, local_addr).await;
            }
            MgmtOp::RemovePeer { addr, response } => {
                self.handle_remove_peer(addr, response).await;
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
                // Update peer state in the HashMap
                if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
                    peer_info.state = state;
                    info!("peer state changed", "peer_ip" => &peer_ip, "state" => format!("{:?}", state));
                }
            }
            ServerOp::PeerHandshakeComplete { peer_ip, asn } => {
                // Update peer ASN and initialize policies in the HashMap
                if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
                    peer_info.asn = Some(asn);
                    peer_info.import_policy = Some(Policy::default_in(self.config.asn));
                    peer_info.export_policy = Some(Policy::default_out(self.config.asn, asn));
                    info!("peer handshake complete", "peer_ip" => &peer_ip, "asn" => asn);
                }
            }
            ServerOp::PeerUpdate {
                peer_ip,
                withdrawn,
                announced,
            } => {
                let peer_info = self.peers.get(&peer_ip).expect("peer should exist");

                if let Some(policy) = peer_info.policy_in() {
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
                // Remove peer from the map
                self.peers.remove(&peer_ip);
                info!("peer disconnected", "peer_ip" => &peer_ip, "total_peers" => self.peers.len());

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

        // Create peer in Connect state - it owns the handshake
        let server_tx = self.op_tx.clone();
        let (peer, peer_tx) = Peer::new(
            peer_ip.clone(),
            tcp_tx,
            tcp_rx,
            server_tx,
            local_asn,
            local_hold_time,
            local_bgp_id,
            local_ip,
        );

        // Add to HashMap IMMEDIATELY - asn is None until handshake completes
        let peer_info = PeerInfo {
            addr: peer_ip.clone(),
            asn: None, // Will be set when ServerOp::PeerHandshakeComplete received
            state: peer.state(),
            peer_tx: peer_tx.clone(),
            import_policy: None, // Will be set when ServerOp::PeerHandshakeComplete received
            export_policy: None, // Will be set when ServerOp::PeerHandshakeComplete received
        };

        self.peers.insert(peer_ip.clone(), peer_info);
        info!("peer added", "peer_ip" => &peer_ip, "state" => format!("{:?}", peer.state()), "total_peers" => self.peers.len());

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

        // Remove peer from map
        let removed = self.peers.remove(&addr).is_some();

        if !removed {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
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

    fn handle_get_peers(&self, response: oneshot::Sender<Vec<(String, Option<u16>, BgpState)>>) {
        let peer_info: Vec<(String, Option<u16>, BgpState)> = self
            .peers
            .values()
            .map(|p| (p.addr.clone(), p.asn, p.state))
            .collect();
        let _ = response.send(peer_info);
    }

    async fn handle_get_peer(
        &self,
        addr: String,
        response: oneshot::Sender<Option<(String, Option<u16>, BgpState, PeerStatistics)>>,
    ) {
        // Get peer info from HashMap
        let peer_info = self.peers.get(&addr);

        if let Some(peer) = peer_info {
            // Query statistics from peer task
            let (stats_tx, stats_rx) = oneshot::channel();
            if peer.peer_tx.send(PeerOp::GetStatistics(stats_tx)).is_ok() {
                // Wait for statistics response
                if let Ok(statistics) = stats_rx.await {
                    let result = Some((peer.addr.clone(), peer.asn, peer.state, statistics));
                    let _ = response.send(result);
                    return;
                }
            }
        }

        // Peer not found or query failed
        let _ = response.send(None);
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
        for (peer_addr, peer_info) in self.peers.iter() {
            if !should_propagate_to_peer(peer_addr, peer_info.state, &originating_peer) {
                continue;
            }

            // Get peer ASN, default to local ASN if not yet known (shouldn't happen in Established state)
            let peer_asn = peer_info.asn.unwrap_or(local_asn);

            // Export policy should always be Some for Established peers
            if let Some(export_policy) = peer_info.policy_out() {
                send_withdrawals_to_peer(peer_addr, &peer_info.peer_tx, &to_withdraw);
                send_announcements_to_peer(
                    peer_addr,
                    &peer_info.peer_tx,
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
