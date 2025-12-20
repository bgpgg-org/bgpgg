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

use crate::bgp::msg::Message;
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotifcationMessage};
use crate::bgp::msg_update::{AsPathSegment, Origin};
use crate::bgp::utils::IpNetwork;
use crate::config::{Config, PeerConfig};
use crate::fsm::BgpState;
use crate::net::peer_ip;
use crate::peer::{Peer, PeerOp, PeerStatistics};
use crate::policy::Policy;
use crate::propagate::{
    send_announcements_to_peer, send_withdrawals_to_peer, should_propagate_to_peer,
};
use crate::rib::rib_loc::LocRib;
use crate::{error, info};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

/// TCP connection initiator for collision detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    Incoming,
    Outgoing,
}

/// Administrative state of a peer, controls auto-reconnect behavior.
/// Follows GoBGP's approach: only reconnect when Up.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum AdminState {
    /// Normal operation, auto-reconnect enabled
    #[default]
    Up,
    /// Manually disabled by admin
    Down,
    /// Disabled due to prefix limit exceeded
    PrefixLimitReached,
}

// Management operations that can be sent to the BGP server
pub enum MgmtOp {
    AddPeer {
        addr: String,
        config: PeerConfig,
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
        response: oneshot::Sender<Vec<(String, Option<u16>, BgpState, AdminState, bool)>>,
    },
    GetPeer {
        addr: String,
        response: oneshot::Sender<
            Option<(
                String,
                Option<u16>,
                BgpState,
                AdminState,
                bool,
                PeerStatistics,
            )>,
        >,
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
        peer_ip: IpAddr,
        state: BgpState,
    },
    PeerHandshakeComplete {
        peer_ip: IpAddr,
        asn: u16,
    },
    /// Sent when peer receives OPEN message, for collision detection (RFC 4271 Section 6.8)
    OpenReceived {
        peer_ip: IpAddr,
        bgp_id: u32,
        conn_type: ConnectionType,
    },
    PeerUpdate {
        peer_ip: IpAddr,
        withdrawn: Vec<IpNetwork>,
        announced: Vec<(IpNetwork, crate::rib::Path)>,
    },
    PeerDisconnected {
        peer_ip: IpAddr,
    },
    /// Set peer's admin state (e.g., when max prefix limit exceeded)
    SetAdminState {
        peer_ip: IpAddr,
        state: AdminState,
    },
}

/// Peer configuration and state stored in server's HashMap.
/// The peer IP is the HashMap key.
pub struct PeerInfo {
    pub admin_state: AdminState,
    /// true if explicitly configured, false if accepted via accept_unconfigured_peers
    pub configured: bool,
    /// Port for reconnection (configured peers only)
    pub port: Option<u16>,
    pub asn: Option<u16>,
    /// BGP Identifier from OPEN message, used for collision detection (RFC 4271 Section 6.8)
    pub bgp_id: Option<u32>,
    pub import_policy: Option<Policy>,
    pub export_policy: Option<Policy>,
    pub state: BgpState,
    pub peer_tx: Option<mpsc::UnboundedSender<PeerOp>>,
    /// Per-peer session configuration
    pub config: PeerConfig,
}

impl PeerInfo {
    pub fn new(
        port: Option<u16>,
        configured: bool,
        config: PeerConfig,
        peer_tx: Option<mpsc::UnboundedSender<PeerOp>>,
    ) -> Self {
        Self {
            admin_state: AdminState::Up,
            configured,
            port,
            asn: None,
            bgp_id: None,
            import_policy: None,
            export_policy: None,
            state: BgpState::Idle,
            peer_tx,
            config,
        }
    }

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
    peers: HashMap<IpAddr, PeerInfo>,
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

    /// Check if a peer should be accepted.
    fn should_accept_peer(&self, peer_ip: IpAddr) -> bool {
        let is_configured = self.peers.contains_key(&peer_ip);
        is_configured || self.config.accept_unconfigured_peers
    }

    /// Resolve connection collision per RFC 4271 6.8.
    /// Returns true if new connection should be rejected. Closes existing connection if it loses.
    fn resolve_collision(&mut self, peer_ip: IpAddr, conn_type: ConnectionType) -> bool {
        let Some(peer) = self.peers.get(&peer_ip) else {
            return false; // No existing peer, accept
        };
        // Only check collision if peer has an active TCP connection (OpenSent or later)
        if matches!(
            peer.state,
            BgpState::Idle | BgpState::Connect | BgpState::Active
        ) {
            return false; // No active connection, accept
        }

        // RFC 4271 8.1.1 Option 5: CollisionDetectEstablishedState
        if peer.state == BgpState::Established && !peer.config.collision_detect_established_state {
            info!("collision: ignoring in Established state", "peer_ip" => peer_ip.to_string());
            return true; // Reject new connection
        }

        // RFC 4271 6.8: Compare BGP Identifiers
        // local < remote: close local-initiated, keep remote-initiated
        // local >= remote: close remote-initiated, keep local-initiated
        let dominated = match conn_type {
            ConnectionType::Incoming => peer.bgp_id.map_or(true, |id| self.local_bgp_id >= id),
            ConnectionType::Outgoing => peer.bgp_id.map_or(false, |id| self.local_bgp_id < id),
        };

        if dominated {
            info!("collision: rejecting new connection", "peer_ip" => peer_ip.to_string());
            return true; // Reject new connection
        }

        // We win: close existing connection, accept new
        info!("collision: closing existing", "peer_ip" => peer_ip.to_string());
        if let Some(peer) = self.peers.get_mut(&peer_ip) {
            if let Some(tx) = peer.peer_tx.take() {
                let _ = tx.send(PeerOp::Shutdown(
                    CeaseSubcode::ConnectionCollisionResolution,
                ));
            }
        }
        false // Accept new connection
    }

    pub async fn run(mut self) {
        info!("BGP server starting", "listen_addr" => &self.config.listen_addr);

        let listener = TcpListener::bind(&self.config.listen_addr).await.unwrap();
        self.local_port = listener.local_addr().unwrap().port();

        let bind_addr = SocketAddr::new(self.local_addr.into(), 0);
        self.init_configured_peers(bind_addr);

        loop {
            tokio::select! {
                // Handle incoming BGP connections
                Ok((stream, _)) = listener.accept() => {
                    self.accept_peer(stream).await;
                }

                // Handle management requests
                Some(req) = self.mgmt_rx.recv() => {
                    self.handle_mgmt_op(req, bind_addr).await;
                }

                // Handle server operations from peers
                Some(op) = self.op_rx.recv() => {
                    self.handle_server_op(op).await;
                }
            }
        }
    }

    /// Initialize configured peers from config and spawn their tasks.
    fn init_configured_peers(&mut self, bind_addr: SocketAddr) {
        for peer_cfg in &self.config.peers.clone() {
            let Ok(peer_addr) = peer_cfg.address.parse::<SocketAddr>() else {
                error!("invalid peer address in config", "addr" => &peer_cfg.address);
                continue;
            };
            let peer_ip = peer_addr.ip();
            let config = peer_cfg.clone();
            let passive = config.passive_mode;
            let allow_auto_start = config.allow_automatic_start();

            let peer_tx = self.spawn_peer(peer_addr, config.clone(), bind_addr);

            let entry = PeerInfo::new(Some(peer_addr.port()), true, config, Some(peer_tx.clone()));
            self.peers.insert(peer_ip, entry);

            // RFC 4271: AutomaticStart for configured peers (if allowed)
            if allow_auto_start {
                if passive {
                    let _ = peer_tx.send(PeerOp::AutomaticStartPassive);
                } else {
                    let _ = peer_tx.send(PeerOp::AutomaticStart);
                }
            }
            info!("configured peer", "peer_ip" => peer_ip.to_string(), "passive" => passive);
        }
    }

    /// Spawn a new Peer task in Idle state
    fn spawn_peer(
        &self,
        addr: SocketAddr,
        config: PeerConfig,
        bind_addr: SocketAddr,
    ) -> mpsc::UnboundedSender<PeerOp> {
        let (peer_tx, peer_rx) = mpsc::unbounded_channel();

        let peer = Peer::new(
            addr.ip(),
            addr.port(),
            peer_rx,
            self.op_tx.clone(),
            self.config.asn,
            self.config.hold_time_secs as u16,
            self.local_bgp_id,
            bind_addr,
            config,
            self.config.connect_retry_secs,
        );

        tokio::spawn(async move {
            peer.run().await;
        });

        peer_tx
    }

    async fn accept_peer(&mut self, mut stream: TcpStream) {
        let Some(peer_ip) = peer_ip(&stream) else {
            error!("failed to get peer address");
            return;
        };

        info!("new peer connection", "peer_ip" => peer_ip.to_string());

        if !self.should_accept_peer(peer_ip) {
            info!("rejecting unconfigured peer", "peer_ip" => peer_ip.to_string());
            let notif = NotifcationMessage::new(
                BgpError::Cease(CeaseSubcode::ConnectionRejected),
                Vec::new(),
            );
            let _ = stream.write_all(&notif.serialize()).await;
            return;
        }

        if self.resolve_collision(peer_ip, ConnectionType::Incoming) {
            return;
        }

        self.accept_incoming_connection(stream, peer_ip);
        info!("peer added", "peer_ip" => peer_ip.to_string(), "state" => "Idle", "total_peers" => self.peers.len());
    }

    /// Accept an incoming TCP connection and create/update peer entry.
    fn accept_incoming_connection(&mut self, stream: TcpStream, peer_ip: IpAddr) {
        // Check if peer exists and has an active task
        let (config, existed) = match self.peers.get(&peer_ip) {
            Some(existing) => {
                if let Some(peer_tx) = &existing.peer_tx {
                    // Send connection to existing peer task
                    let (tcp_rx, tcp_tx) = stream.into_split();
                    let _ = peer_tx.send(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx });
                    return;
                }
                (existing.config.clone(), true)
            }
            None => (PeerConfig::default(), false),
        };

        let Some(peer_tx) = self.spawn_peer_from_stream(stream, peer_ip, config.clone()) else {
            return;
        };

        if existed {
            let existing = self.peers.get_mut(&peer_ip).unwrap();
            existing.peer_tx = Some(peer_tx);
            existing.state = BgpState::Idle;
        } else {
            self.peers
                .insert(peer_ip, PeerInfo::new(None, false, config, Some(peer_tx)));
        }
    }

    /// Create a peer from a connected stream and spawn a task.
    /// Returns None if AllowAutomaticStart is false (RFC 4271 8.1.1).
    fn spawn_peer_from_stream(
        &self,
        stream: TcpStream,
        peer_ip: IpAddr,
        config: PeerConfig,
    ) -> Option<mpsc::UnboundedSender<PeerOp>> {
        // RFC 4271 8.1.1: AllowAutomaticStart must be true for automatic events
        if !config.allow_automatic_start() {
            info!("rejecting incoming: AllowAutomaticStart is false", "peer_ip" => peer_ip.to_string());
            return None;
        }

        let local_addr = stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::new(self.local_addr.into(), 0));

        let (tcp_rx, tcp_tx) = stream.into_split();

        let peer_tx = self.spawn_peer(SocketAddr::new(peer_ip, 0), config.clone(), local_addr);

        // RFC 4271 8.2.2: Send appropriate start event based on PassiveTcpEstablishment
        if config.passive_mode {
            // Event 5: AutomaticStartPassive -> Active
            let _ = peer_tx.send(PeerOp::AutomaticStartPassive);
        } else {
            // Event 3: AutomaticStart -> Connect
            let _ = peer_tx.send(PeerOp::AutomaticStart);
        }

        let _ = peer_tx.send(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx });

        Some(peer_tx)
    }

    async fn handle_mgmt_op(&mut self, req: MgmtOp, bind_addr: SocketAddr) {
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
            ServerOp::OpenReceived {
                peer_ip,
                bgp_id,
                conn_type,
            } => {
                self.handle_open_received(peer_ip, bgp_id, conn_type);
            }
            ServerOp::PeerDisconnected { peer_ip } => {
                let Some(peer) = self.peers.get_mut(&peer_ip) else {
                    return;
                };

                if peer.configured {
                    // Configured peer: update state, Peer task handles reconnection internally
                    peer.state = BgpState::Idle;
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
                let changed_prefixes = self.loc_rib.remove_routes_from_peer(peer_ip.clone());

                // Propagate withdrawals to other peers
                if !changed_prefixes.is_empty() {
                    self.propagate_routes(changed_prefixes, Some(peer_ip)).await;
                }
            }
            ServerOp::SetAdminState { peer_ip, state } => {
                if let Some(peer) = self.peers.get_mut(&peer_ip) {
                    peer.admin_state = state;
                }
            }
        }
    }

    /// Handle OPEN message received - store BGP ID (RFC 4271 6.8)
    ///
    /// Note: Collision detection for incoming is handled in accept_peer.
    /// Outgoing collision detection requires tracking parallel connections
    /// which is not currently implemented.
    fn handle_open_received(&mut self, peer_ip: IpAddr, bgp_id: u32, _conn_type: ConnectionType) {
        if let Some(peer) = self.peers.get_mut(&peer_ip) {
            peer.bgp_id = Some(bgp_id);
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
            PeerInfo::new(
                Some(peer_addr.port()),
                true,
                config.clone(),
                Some(peer_tx.clone()),
            ),
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

        // Remove entry from map
        let entry = self.peers.remove(&peer_ip);

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
        response: oneshot::Sender<Vec<(String, Option<u16>, BgpState, AdminState, bool)>>,
    ) {
        let peers: Vec<(String, Option<u16>, BgpState, AdminState, bool)> = self
            .peers
            .iter()
            .map(|(addr, entry)| {
                (
                    addr.to_string(),
                    entry.asn,
                    entry.state,
                    entry.admin_state,
                    entry.configured,
                )
            })
            .collect();
        let _ = response.send(peers);
    }

    async fn handle_get_peer(
        &self,
        addr: String,
        response: oneshot::Sender<
            Option<(
                String,
                Option<u16>,
                BgpState,
                AdminState,
                bool,
                PeerStatistics,
            )>,
        >,
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

        let _ = response.send(Some((
            addr,
            entry.asn,
            entry.state,
            entry.admin_state,
            entry.configured,
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
        originating_peer: Option<IpAddr>,
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
            if !should_propagate_to_peer(*peer_addr, entry.state, originating_peer) {
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
                send_withdrawals_to_peer(*peer_addr, peer_tx, &to_withdraw);
                send_announcements_to_peer(
                    *peer_addr,
                    peer_tx,
                    &to_announce,
                    local_asn,
                    peer_asn,
                    self.local_addr,
                    export_policy,
                );
            } else {
                error!("export policy not set for established peer", "peer_ip" => peer_addr.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_info() -> PeerInfo {
        PeerInfo::new(None, true, PeerConfig::default(), None)
    }

    fn make_server(accept_unconfigured_peers: bool) -> BgpServer {
        let config = Config::new(
            65000,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            180,
            accept_unconfigured_peers,
        );
        BgpServer::new(config)
    }

    #[test]
    fn test_should_accept_peer() {
        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Unconfigured peer with accept_unconfigured_peers=false -> reject
        let server = make_server(false);
        assert!(!server.should_accept_peer(peer_ip));

        // Unconfigured peer with accept_unconfigured_peers=true -> accept
        let server = make_server(true);
        assert!(server.should_accept_peer(peer_ip));

        // Configured peer -> accept regardless of accept_unconfigured_peers
        let mut server = make_server(false);
        server.peers.insert(peer_ip, peer_info());
        assert!(server.should_accept_peer(peer_ip));
    }
}
