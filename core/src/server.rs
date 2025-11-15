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

use crate::bgp::msg_update::{Origin, UpdateMessage};
use crate::bgp::utils::IpNetwork;
use crate::config::Config;
use crate::fsm::BgpState;
use crate::net::create_and_bind_tcp_socket;
use crate::peer::Peer;
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
    AnnounceRoute {
        prefix: IpNetwork,
        next_hop: Ipv4Addr,
        origin: Origin,
        response: oneshot::Sender<Result<(), String>>,
    },
    WithdrawRoute {
        prefix: IpNetwork,
        response: oneshot::Sender<Result<(), String>>,
    },
    GetPeers {
        response: oneshot::Sender<Vec<(String, u16, BgpState)>>,
    },
    GetPeer {
        addr: String,
        response: oneshot::Sender<Option<(String, u16, BgpState, crate::peer::PeerStatistics)>>,
    },
    GetRoutes {
        response: oneshot::Sender<Vec<crate::rib::Route>>,
    },
}

// Messages that can be sent to a peer task
pub enum PeerMessage {
    SendUpdate(UpdateMessage),
}

// Information about an established peer
pub struct PeerHandle {
    pub addr: String,
    pub asn: u16,
    pub state: BgpState,
    pub statistics: crate::peer::PeerStatistics,
    pub message_tx: mpsc::UnboundedSender<PeerMessage>,
}

// Server operations sent from peer tasks to the main server loop
pub enum ServerOp {
    PeerEstablished {
        peer_ip: String,
        asn: u16,
        handle: PeerHandle,
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

pub struct BgpServer {
    pub peers: HashMap<String, PeerHandle>,
    pub loc_rib: LocRib,
    pub request_tx: mpsc::Sender<MgmtOp>,
    pub server_op_tx: mpsc::UnboundedSender<ServerOp>,
    config: Config,
    local_bgp_id: u32,
    request_rx: mpsc::Receiver<MgmtOp>,
    server_op_rx: mpsc::UnboundedReceiver<ServerOp>,
}

impl BgpServer {
    pub fn new(config: Config) -> Self {
        // Convert the configured router_id (Ipv4Addr) to u32 for BGP identifier
        let local_bgp_id = u32::from(config.router_id);

        let (req_tx, req_rx) = mpsc::channel(100);
        let (server_op_tx, server_op_rx) = mpsc::unbounded_channel();
        let peers = HashMap::new();
        let loc_rib = LocRib::new(config.asn);

        BgpServer {
            peers,
            loc_rib,
            request_tx: req_tx,
            server_op_tx,
            config,
            local_bgp_id,
            request_rx: req_rx,
            server_op_rx,
        }
    }

    pub async fn run(mut self) {
        let addr = self.config.listen_addr.clone();
        info!("BGP server starting", "listen_addr" => addr);

        let listener = TcpListener::bind(&addr).await.unwrap();

        // Get local bind address for outgoing connections
        let local_addr = self
            .config
            .get_local_addr()
            .expect("invalid listen address");
        let local_asn = self.config.asn;
        let local_bgp_id = self.local_bgp_id;
        let hold_time = self.config.hold_time_secs as u16;
        let server_op_tx = self.server_op_tx.clone();

        loop {
            tokio::select! {
                // Handle incoming BGP connections
                Ok((stream, _)) = listener.accept() => {
                    Self::accept_peer(stream, server_op_tx.clone(), local_asn, local_bgp_id, hold_time).await;
                }

                // Handle management requests
                Some(req) = self.request_rx.recv() => {
                    self.handle_mgmt_op(req, local_addr).await;
                }

                // Handle server operations from peers
                Some(op) = self.server_op_rx.recv() => {
                    self.handle_server_op(op).await;
                }
            }
        }
    }

    async fn accept_peer(
        stream: TcpStream,
        server_op_tx: mpsc::UnboundedSender<ServerOp>,
        local_asn: u16,
        local_bgp_id: u32,
        hold_time: u16,
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

        let (read_half, write_half) = stream.into_split();

        tokio::spawn(Peer::run(
            peer_ip,
            read_half,
            write_half,
            local_asn,
            hold_time,
            local_bgp_id,
            server_op_tx,
        ));
    }

    async fn handle_mgmt_op(&mut self, req: MgmtOp, local_addr: SocketAddr) {
        match req {
            MgmtOp::AddPeer { addr, response } => {
                self.handle_add_peer(addr, response, local_addr).await;
            }
            MgmtOp::RemovePeer { addr, response } => {
                self.handle_remove_peer(addr, response).await;
            }
            MgmtOp::AnnounceRoute {
                prefix,
                next_hop,
                origin,
                response,
            } => {
                self.handle_announce_route(prefix, next_hop, origin, response)
                    .await;
            }
            MgmtOp::WithdrawRoute { prefix, response } => {
                self.handle_withdraw_route(prefix, response).await;
            }
            MgmtOp::GetPeers { response } => {
                self.handle_get_peers(response);
            }
            MgmtOp::GetPeer { addr, response } => {
                self.handle_get_peer(addr, response);
            }
            MgmtOp::GetRoutes { response } => {
                self.handle_get_routes(response);
            }
        }
    }

    async fn handle_server_op(&mut self, op: ServerOp) {
        match op {
            ServerOp::PeerEstablished {
                peer_ip,
                asn,
                handle,
            } => {
                self.peers.insert(peer_ip.clone(), handle);
                info!("peer established", "peer_ip" => &peer_ip, "peer_asn" => asn, "total_peers" => self.peers.len());
            }
            ServerOp::PeerUpdate {
                peer_ip,
                withdrawn,
                announced,
            } => {
                let changed_prefixes =
                    self.loc_rib
                        .update_from_peer(peer_ip.clone(), withdrawn, announced);
                info!("UPDATE processing complete", "peer_ip" => &peer_ip);

                // Propagate changed routes to other peers
                if !changed_prefixes.is_empty() {
                    self.propagate_routes(changed_prefixes, Some(peer_ip)).await;
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

        // Connection successful, send response
        let _ = response.send(Ok(()));

        // Split the stream before spawning
        let (read_half, write_half) = stream.into_split();

        // Spawn peer task to handle the connection
        let server_op_tx = self.server_op_tx.clone();
        let local_asn = self.config.asn;
        let local_bgp_id = self.local_bgp_id;
        let hold_time = self.config.hold_time_secs as u16;

        tokio::spawn(Peer::run(
            peer_ip,
            read_half,
            write_half,
            local_asn,
            hold_time,
            local_bgp_id,
            server_op_tx,
        ));
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

    async fn handle_announce_route(
        &mut self,
        prefix: IpNetwork,
        next_hop: Ipv4Addr,
        origin: Origin,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        info!("announcing route via request", "prefix" => format!("{:?}", prefix), "next_hop" => next_hop.to_string());

        // Add route to Loc-RIB as locally originated
        self.loc_rib.add_local_route(prefix, next_hop, origin);

        // Propagate to all peers using the common propagation logic
        self.propagate_routes(vec![prefix], None).await;

        let _ = response.send(Ok(()));
    }

    async fn handle_withdraw_route(
        &mut self,
        prefix: IpNetwork,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        info!("withdrawing route via request", "prefix" => format!("{:?}", prefix));

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

    fn handle_get_peers(&self, response: oneshot::Sender<Vec<(String, u16, BgpState)>>) {
        let peer_info: Vec<(String, u16, BgpState)> = self
            .peers
            .values()
            .map(|p| (p.addr.clone(), p.asn, p.state))
            .collect();
        let _ = response.send(peer_info);
    }

    fn handle_get_peer(
        &self,
        addr: String,
        response: oneshot::Sender<Option<(String, u16, BgpState, crate::peer::PeerStatistics)>>,
    ) {
        let peer_info = self
            .peers
            .get(&addr)
            .map(|p| (p.addr.clone(), p.asn, p.state, p.statistics.clone()));
        let _ = response.send(peer_info);
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
        for (peer_addr, handle) in self.peers.iter() {
            if !should_propagate_to_peer(peer_addr, handle, &originating_peer) {
                continue;
            }

            send_withdrawals_to_peer(handle, &to_withdraw);
            send_announcements_to_peer(handle, &to_announce, local_asn);
        }
    }
}
