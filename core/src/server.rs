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
use crate::{debug, error, info};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

/// Per-peer session configuration.
/// Includes RFC 4271 Section 8.1 optional attributes and other peer settings.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// IdleHoldTime - delay before automatic restart (RFC 4271 8.1.1)
    pub idle_hold_time: Duration,
    /// AllowAutomaticStart - enable automatic restart after disconnect (RFC 4271 8.1.1)
    pub allow_automatic_start: bool,
    /// Maximum prefix limit settings
    pub max_prefix: Option<MaxPrefixSetting>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_hold_time: Duration::from_secs(30),
            allow_automatic_start: true,
            max_prefix: None,
        }
    }
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
        session_config: SessionConfig,
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
        peer_ip: String,
        state: BgpState,
    },
    PeerHandshakeComplete {
        peer_ip: String,
        asn: u16,
    },
    /// Sent when peer receives OPEN message, for collision detection (RFC 4271 Section 6.8)
    OpenReceived {
        peer_ip: String,
        bgp_id: u32,
    },
    PeerUpdate {
        peer_ip: String,
        withdrawn: Vec<IpNetwork>,
        announced: Vec<(IpNetwork, crate::rib::Path)>,
    },
    PeerDisconnected {
        peer_ip: String,
    },
    /// Set peer's admin state (e.g., when max prefix limit exceeded)
    SetAdminState {
        peer_ip: String,
        state: AdminState,
    },
    /// Outbound connection succeeded (from connector task)
    OutboundConnected {
        peer_addr: SocketAddr,
        stream: TcpStream,
    },
}

/// Peer configuration and state stored in server's HashMap.
/// The peer IP is the HashMap key.
pub struct PeerInfo {
    pub admin_state: AdminState,
    /// true if accepted from incoming connection, not explicitly configured
    pub dynamic: bool,
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
    pub session_config: SessionConfig,
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

/// Spawns an outbound connector task that attempts to connect to a peer.
/// On success, sends OutboundConnected back to the server.
/// Retries with ConnectRetryTimer on failure.
fn spawn_outbound_connector(
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    connect_retry_secs: u64,
    idle_hold_time: Duration,
    server_tx: mpsc::UnboundedSender<ServerOp>,
) {
    tokio::spawn(async move {
        // IdleHoldTimer - wait before first connection attempt (RFC 4271 8.1.1)
        if !idle_hold_time.is_zero() {
            debug!("waiting idle hold time", "peer_addr" => peer_addr, "secs" => idle_hold_time.as_secs());
            tokio::time::sleep(idle_hold_time).await;
            if server_tx.is_closed() {
                return;
            }
        }

        let retry_duration = Duration::from_secs(connect_retry_secs);

        loop {
            debug!("attempting outbound connection", "peer_addr" => peer_addr);

            match create_and_bind_tcp_socket(local_addr, peer_addr).await {
                Ok(stream) => {
                    info!("outbound connection established", "peer_addr" => peer_addr);
                    let _ = server_tx.send(ServerOp::OutboundConnected { peer_addr, stream });
                    return; // Task completes, server will spawn new one if peer disconnects
                }
                Err(e) => {
                    debug!("outbound connection failed, will retry",
                           "peer_addr" => peer_addr, "error" => e.to_string(),
                           "retry_secs" => connect_retry_secs);
                }
            }

            // ConnectRetryTimer - wait before next attempt
            tokio::time::sleep(retry_duration).await;

            // Check if server channel is closed (server shutdown)
            if server_tx.is_closed() {
                return;
            }
        }
    });
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

        loop {
            tokio::select! {
                // Handle incoming BGP connections
                Ok((stream, _)) = listener.accept() => {
                    self.accept_peer(stream).await;
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

    async fn accept_peer(&mut self, stream: TcpStream) {
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

        // RFC 4271 Section 6.8: Connection Collision Detection
        if let Some(existing) = self.peers.get_mut(&peer_ip) {
            if existing.peer_tx.is_some() {
                // Compare BGP IDs: if local >= remote, reject incoming
                let dominated = existing.bgp_id.map_or(true, |id| self.local_bgp_id >= id);
                if dominated {
                    info!("collision: rejecting incoming", "peer_ip" => &peer_ip);
                    return;
                }
                // local < remote: close existing, accept incoming
                info!("collision: closing existing", "peer_ip" => &peer_ip);
                if let Some(tx) = existing.peer_tx.take() {
                    let _ = tx.send(PeerOp::Shutdown(
                        CeaseSubcode::ConnectionCollisionResolution,
                    ));
                }
            }
        }

        let (peer_tx, initial_state) = self.spawn_peer_from_stream(stream, &peer_ip, None);

        // Add dynamic peer (will be removed on disconnect)
        let entry = PeerInfo {
            admin_state: AdminState::Up,
            dynamic: true,
            port: None,
            asn: None,
            bgp_id: None,
            import_policy: None,
            export_policy: None,
            state: initial_state,
            peer_tx: Some(peer_tx),
            session_config: SessionConfig::default(),
        };

        self.peers.insert(peer_ip.clone(), entry);
        info!("peer added", "peer_ip" => &peer_ip, "state" => format!("{:?}", initial_state), "total_peers" => self.peers.len());
    }

    async fn handle_mgmt_op(&mut self, req: MgmtOp, local_addr: SocketAddr) {
        match req {
            MgmtOp::AddPeer {
                addr,
                session_config,
                response,
            } => {
                self.handle_add_peer(addr, session_config, response, local_addr)
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
            ServerOp::OpenReceived { peer_ip, bgp_id } => {
                self.handle_open_received(peer_ip, bgp_id);
            }
            ServerOp::PeerDisconnected { peer_ip } => {
                // Ignore stale disconnect if a new connection is already active
                // (peer_tx exists and is NOT closed means there's a live new connection)
                if self
                    .peers
                    .get(&peer_ip)
                    .and_then(|p| p.peer_tx.as_ref())
                    .map_or(false, |tx| !tx.is_closed())
                {
                    debug!("ignoring stale disconnect", "peer_ip" => &peer_ip);
                    return;
                }

                // Check if peer is configured or dynamic
                let default_config = SessionConfig::default();
                let (is_dynamic, admin_state, port, session_config) = self
                    .peers
                    .get(&peer_ip)
                    .map(|p| (p.dynamic, p.admin_state, p.port, p.session_config.clone()))
                    .unwrap_or((true, AdminState::Up, None, default_config));

                if is_dynamic {
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

                    // AutomaticStart: spawn connector only if enabled and AdminState::Up
                    if session_config.allow_automatic_start && admin_state == AdminState::Up {
                        if let Some(port) = port {
                            if let Ok(peer_addr) =
                                format!("{}:{}", peer_ip, port).parse::<SocketAddr>()
                            {
                                let local_addr = SocketAddr::new(self.local_addr.into(), 0);
                                spawn_outbound_connector(
                                    peer_addr,
                                    local_addr,
                                    self.config.connect_retry_secs,
                                    session_config.idle_hold_time,
                                    self.op_tx.clone(),
                                );
                            }
                        }
                    }
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
            ServerOp::OutboundConnected { peer_addr, stream } => {
                self.handle_outbound_connected(peer_addr, stream).await;
            }
        }
    }

    /// Handle OPEN message received - store BGP ID (RFC 4271 Section 6.8)
    fn handle_open_received(&mut self, peer_ip: String, bgp_id: u32) {
        if let Some(peer) = self.peers.get_mut(&peer_ip) {
            peer.bgp_id = Some(bgp_id);
        }
    }

    async fn handle_add_peer(
        &mut self,
        addr: String,
        session_config: SessionConfig,
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

        // RFC 4271 Section 6.8: Connection Collision Detection
        if let Some(existing) = self.peers.get_mut(&peer_ip) {
            if existing.peer_tx.is_some() {
                // local >= remote: keep outgoing (local initiated), close incoming
                // local < remote: keep incoming (remote initiated), abort outgoing
                let dominated = existing.bgp_id.map_or(false, |id| self.local_bgp_id < id);
                if dominated {
                    info!("collision: aborting outgoing", "peer_ip" => &peer_ip);
                    let _ = response.send(Ok(()));
                    return;
                }
                // local >= remote (or unknown): close existing, continue with outgoing
                info!("collision: closing existing", "peer_ip" => &peer_ip);
                if let Some(tx) = existing.peer_tx.take() {
                    let _ = tx.send(PeerOp::Shutdown(
                        CeaseSubcode::ConnectionCollisionResolution,
                    ));
                }
            }
        }

        let (peer_tx, initial_state) =
            self.spawn_peer_from_stream(stream, &peer_ip, session_config.max_prefix);

        // Add configured peer (persists on disconnect)
        let entry = PeerInfo {
            admin_state: AdminState::Up,
            dynamic: false,
            port: Some(peer_addr.port()),
            asn: None,
            bgp_id: None,
            import_policy: None,
            export_policy: None,
            state: initial_state,
            peer_tx: Some(peer_tx),
            session_config,
        };

        self.peers.insert(peer_ip.clone(), entry);
        info!("peer added", "peer_ip" => &peer_ip, "state" => format!("{:?}", initial_state), "total_peers" => self.peers.len());

        // Connection successful, send response
        let _ = response.send(Ok(()));
    }

    /// Handle successful outbound connection from connector task
    async fn handle_outbound_connected(&mut self, peer_addr: SocketAddr, stream: TcpStream) {
        let peer_ip = peer_addr.ip().to_string();

        // Extract info we need, checking peer exists and is valid
        let (admin_state, has_active_conn, bgp_id, max_prefix) = match self.peers.get(&peer_ip) {
            Some(p) => (
                p.admin_state,
                p.peer_tx.as_ref().map_or(false, |tx| !tx.is_closed()),
                p.bgp_id,
                p.session_config.max_prefix,
            ),
            None => {
                debug!("ignoring outbound connection for removed peer", "peer_ip" => &peer_ip);
                return;
            }
        };

        if admin_state != AdminState::Up {
            debug!("ignoring outbound connection for non-Up peer", "peer_ip" => &peer_ip, "state" => format!("{:?}", admin_state));
            return;
        }

        // Collision detection: if there's already an active connection, compare BGP IDs
        if has_active_conn {
            let dominated = bgp_id.map_or(false, |id| self.local_bgp_id < id);
            if dominated {
                info!("collision: aborting outbound", "peer_ip" => &peer_ip);
                return;
            }
            // We win: close existing, continue with outbound
            info!("collision: closing existing", "peer_ip" => &peer_ip);
            if let Some(peer) = self.peers.get_mut(&peer_ip) {
                if let Some(tx) = peer.peer_tx.take() {
                    let _ = tx.send(PeerOp::Shutdown(
                        CeaseSubcode::ConnectionCollisionResolution,
                    ));
                }
            }
        }

        let (peer_tx, state) = self.spawn_peer_from_stream(stream, &peer_ip, max_prefix);

        // Update existing peer entry
        if let Some(entry) = self.peers.get_mut(&peer_ip) {
            entry.peer_tx = Some(peer_tx);
            entry.state = state;
            entry.asn = None;
            entry.bgp_id = None;
        }

        info!("outbound peer connected", "peer_ip" => &peer_ip, "state" => format!("{:?}", state));
    }

    /// Common helper to create and spawn a peer from a connected stream.
    /// Returns (peer_tx, initial_state).
    fn spawn_peer_from_stream(
        &self,
        stream: TcpStream,
        peer_ip: &str,
        max_prefix_setting: Option<MaxPrefixSetting>,
    ) -> (mpsc::UnboundedSender<PeerOp>, BgpState) {
        let local_ip = stream
            .local_addr()
            .ok()
            .and_then(ipv4_from_sockaddr)
            .unwrap_or(self.local_addr);

        let (tcp_rx, tcp_tx) = stream.into_split();
        let (peer_tx, peer_rx) = mpsc::unbounded_channel();

        let peer = Peer::new(
            peer_ip.to_string(),
            tcp_tx,
            tcp_rx,
            peer_rx,
            self.op_tx.clone(),
            self.config.asn,
            self.config.hold_time_secs as u16,
            self.local_bgp_id,
            local_ip,
            max_prefix_setting,
        );

        let state = peer.state();
        tokio::spawn(peer.run());

        (peer_tx, state)
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

        entry.admin_state = AdminState::Down;

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

        entry.admin_state = AdminState::Up;
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
        response: oneshot::Sender<Vec<(String, Option<u16>, BgpState, AdminState, bool)>>,
    ) {
        let peers: Vec<(String, Option<u16>, BgpState, AdminState, bool)> = self
            .peers
            .iter()
            .map(|(addr, entry)| {
                (
                    addr.clone(),
                    entry.asn,
                    entry.state,
                    entry.admin_state,
                    entry.dynamic,
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
        let Some(entry) = self.peers.get(&addr) else {
            let _ = response.send(None);
            return;
        };

        let stats = entry.get_statistics().await.unwrap_or_default();

        let _ = response.send(Some((
            addr,
            entry.asn,
            entry.state,
            entry.admin_state,
            entry.dynamic,
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
