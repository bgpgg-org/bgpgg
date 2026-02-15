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
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::msg_update::{AsPathSegment, NextHopAddr, Origin, UpdateMessage};
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::bmp::destination::{BmpDestination, BmpTcpClient};
use crate::bmp::task::BmpTask;
use crate::config::{Config, PeerConfig};
use crate::log::{error, info};
use crate::net::IpNetwork;
use crate::net::{bind_addr_from_ip, peer_ip};
use crate::peer::outgoing::{
    send_addpath_withdrawals_to_peer, send_announcements_to_peer, send_withdrawals_to_peer,
    should_propagate_to_peer,
};
use crate::peer::BgpState;
use crate::peer::{LocalConfig, Peer, PeerCapabilities, PeerOp, PeerStatistics};
use crate::policy::{DefinedSetType, Policy, PolicyContext};
use crate::rib::rib_loc::LocRib;
use crate::rib::{Path, Route, RouteDelta};
use crate::types::PeerDownReason;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

/// Errors that can occur during server initialization or operation.
#[derive(Debug)]
pub enum ServerError {
    InvalidListenAddr(String),
    BindError(io::Error),
    IoError(io::Error),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::InvalidListenAddr(addr) => write!(f, "Invalid listen address: {}", addr),
            ServerError::BindError(e) => write!(f, "Failed to bind listener: {}", e),
            ServerError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for ServerError {}

/// TCP connection initiator for collision detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    Incoming,
    Outgoing,
}

/// Administrative state of a peer, controls auto-reconnect behavior.
/// Only reconnect when Up.
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

/// Reset type for peer reset operations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResetType {
    SoftIn,  // Send ROUTE_REFRESH to peer
    SoftOut, // Resend our routes
    Soft,    // Both
    Hard,    // Send CEASE/ADMINISTRATIVE_RESET and reconnect
}

#[derive(Debug, Clone)]
pub struct GetPeersResponse {
    pub address: String,
    pub asn: Option<u32>,
    pub state: BgpState,
    pub admin_state: AdminState,
    pub import_policies: Vec<String>,
    pub export_policies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GetPeerResponse {
    pub address: String,
    pub asn: Option<u32>,
    pub state: BgpState,
    pub admin_state: AdminState,
    pub import_policies: Vec<String>,
    pub export_policies: Vec<String>,
    pub statistics: PeerStatistics,
}

#[derive(Debug, Clone)]
pub struct BmpPeerStats {
    pub peer_ip: IpAddr,
    pub peer_as: u32,
    pub peer_bgp_id: u32,
    pub adj_rib_in_count: u64,
}

/// Policy direction (import or export)
#[derive(Debug, Clone, Copy)]
pub enum PolicyDirection {
    Import,
    Export,
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
    ResetPeer {
        addr: String,
        reset_type: ResetType,
        afi: Option<Afi>,
        safi: Option<Safi>,
        response: oneshot::Sender<Result<(), String>>,
    },
    AddRoute {
        prefix: IpNetwork,
        next_hop: NextHopAddr,
        origin: Origin,
        as_path: Vec<AsPathSegment>,
        local_pref: Option<u32>,
        med: Option<u32>,
        atomic_aggregate: bool,
        communities: Vec<u32>,
        extended_communities: Vec<u64>,
        large_communities: Vec<crate::bgp::msg_update_types::LargeCommunity>,
        originator_id: Option<std::net::Ipv4Addr>,
        cluster_list: Vec<std::net::Ipv4Addr>,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemoveRoute {
        prefix: IpNetwork,
        response: oneshot::Sender<Result<(), String>>,
    },
    GetPeers {
        response: oneshot::Sender<Vec<GetPeersResponse>>,
    },
    GetPeer {
        addr: String,
        response: oneshot::Sender<Option<GetPeerResponse>>,
    },
    GetRoutes {
        rib_type: Option<i32>,
        peer_address: Option<String>,
        response: oneshot::Sender<Result<Vec<Route>, String>>,
    },
    GetRoutesStream {
        rib_type: Option<i32>,
        peer_address: Option<String>,
        tx: mpsc::UnboundedSender<Route>,
    },
    GetPeersStream {
        tx: mpsc::UnboundedSender<GetPeersResponse>,
    },
    GetServerInfo {
        response: oneshot::Sender<(IpAddr, u16, u64)>,
    },
    AddBmpServer {
        addr: SocketAddr,
        statistics_timeout: Option<u64>,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemoveBmpServer {
        addr: SocketAddr,
        response: oneshot::Sender<Result<(), String>>,
    },
    GetBmpServers {
        response: oneshot::Sender<Vec<String>>,
    },
    // Policy Management
    AddDefinedSet {
        set: DefinedSetConfig,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemoveDefinedSet {
        set_type: DefinedSetType,
        name: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    ListDefinedSets {
        set_type: Option<DefinedSetType>,
        name: Option<String>,
        response: oneshot::Sender<Vec<DefinedSetConfig>>,
    },
    AddPolicy {
        name: String,
        statements: Vec<crate::config::StatementConfig>,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemovePolicy {
        name: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    ListPolicies {
        name: Option<String>,
        response: oneshot::Sender<Vec<PolicyInfoResponse>>,
    },
    SetPolicyAssignment {
        peer_addr: IpAddr,
        direction: PolicyDirection,
        policy_names: Vec<String>,
        default_action: Option<crate::policy::PolicyResult>,
        response: oneshot::Sender<Result<(), String>>,
    },
}

// Helper types for policy management operations
pub use crate::config::DefinedSetConfig;

#[derive(Debug, Clone)]
pub struct PolicyInfoResponse {
    pub name: String,
    pub statements: Vec<crate::config::StatementConfig>,
}

// Server operations sent from peer tasks to the main server loop
pub enum ServerOp {
    PeerStateChanged {
        peer_ip: IpAddr,
        state: BgpState,
        conn_type: ConnectionType,
    },
    PeerHandshakeComplete {
        peer_ip: IpAddr,
        asn: u32,
        conn_type: ConnectionType,
    },
    /// Sent when peer receives OPEN message, for collision detection (RFC 4271 Section 6.8)
    OpenReceived {
        peer_ip: IpAddr,
        bgp_id: u32,
        conn_type: ConnectionType,
    },
    /// Connection info sent when peer establishes
    PeerConnectionInfo {
        peer_ip: IpAddr,
        local_address: IpAddr,
        local_port: u16,
        remote_port: u16,
        sent_open: OpenMessage,
        received_open: OpenMessage,
        negotiated_capabilities: PeerCapabilities,
        conn_type: ConnectionType,
    },
    PeerUpdate {
        peer_ip: IpAddr,
        withdrawn: Vec<IpNetwork>,
        announced: Vec<(IpNetwork, Arc<Path>)>,
    },
    PeerDisconnected {
        peer_ip: IpAddr,
        reason: PeerDownReason,
        gr_afi_safis: Vec<crate::bgp::multiprotocol::AfiSafi>,
        conn_type: ConnectionType,
    },
    /// Set peer's admin state (e.g., when max prefix limit exceeded)
    SetAdminState { peer_ip: IpAddr, state: AdminState },
    /// Route Refresh request from peer
    RouteRefresh {
        peer_ip: IpAddr,
        afi: Afi,
        safi: Safi,
    },
    /// Graceful Restart timer expired for a peer (RFC 4724)
    GracefulRestartTimerExpired { peer_ip: IpAddr },
    /// Graceful Restart completed for a peer (all EORs received)
    GracefulRestartComplete {
        peer_ip: IpAddr,
        afi_safi: crate::bgp::multiprotocol::AfiSafi,
    },
    /// Server signals peer that loc-rib has been sent
    LocalRibSent {
        peer_ip: IpAddr,
        afi_safi: crate::bgp::multiprotocol::AfiSafi,
    },
    /// Query BMP statistics for all established peers
    GetBmpStatistics {
        response: oneshot::Sender<Vec<BmpPeerStats>>,
    },
}

// BMP operations sent from server to BMP sender task
pub enum BmpOp {
    PeerUp {
        peer_ip: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        local_address: IpAddr,
        local_port: u16,
        remote_port: u16,
        sent_open: OpenMessage,
        received_open: OpenMessage,
        use_4byte_asn: bool,
    },
    PeerDown {
        peer_ip: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        reason: PeerDownReason,
        use_4byte_asn: bool,
    },
    RouteMonitoring {
        peer_ip: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        update: UpdateMessage,
    },
}

/// BMP task tracking info (one per BMP destination)
pub struct BmpTaskInfo {
    pub addr: SocketAddr,
    pub statistics_timeout: Option<u64>,
    pub task_tx: mpsc::UnboundedSender<Arc<BmpOp>>,
}

impl BmpTaskInfo {
    pub fn new(
        addr: SocketAddr,
        statistics_timeout: Option<u64>,
        task_tx: mpsc::UnboundedSender<Arc<BmpOp>>,
    ) -> Self {
        Self {
            addr,
            statistics_timeout,
            task_tx,
        }
    }
}

/// Connection info (stored only while peer is Established)
#[derive(Clone)]
pub struct ConnectionInfo {
    pub sent_open: OpenMessage,
    pub received_open: OpenMessage,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
}

/// Connection-specific state.
/// Direction is determined by which slot (outgoing/incoming) contains this state.
#[derive(Default)]
pub struct ConnectionState {
    pub peer_tx: Option<mpsc::UnboundedSender<PeerOp>>,
    pub state: BgpState,
    pub asn: Option<u32>,
    pub bgp_id: Option<u32>,
    pub conn_info: Option<ConnectionInfo>,
    pub capabilities: Option<PeerCapabilities>,
}

impl ConnectionState {
    pub fn new(peer_tx: Option<mpsc::UnboundedSender<PeerOp>>) -> Self {
        Self {
            peer_tx,
            state: BgpState::Idle,
            asn: None,
            bgp_id: None,
            conn_info: None,
            capabilities: None,
        }
    }
}

/// Peer configuration and state stored in server's HashMap.
/// The peer IP is the HashMap key.
///
/// Connection slots: Direction is determined by which slot a connection occupies
/// (outgoing vs incoming), not by a conn_type field.
pub struct PeerInfo {
    pub admin_state: AdminState,
    pub import_policies: Vec<Arc<Policy>>,
    pub export_policies: Vec<Arc<Policy>>,
    /// Per-peer session configuration
    pub config: PeerConfig,
    /// Outgoing connection slot (we initiated)
    pub outgoing: Option<ConnectionState>,
    /// Incoming connection slot (peer initiated)
    pub incoming: Option<ConnectionState>,
    /// Per-peer adj-rib-out: tracks routes actually exported to this peer.
    /// Key: (prefix, local_path_id), Value: the exported path (post-policy).
    pub adj_rib_out: HashMap<(IpNetwork, u32), Arc<Path>>,
}

impl PeerInfo {
    pub fn new(
        config: PeerConfig,
        peer_tx: Option<mpsc::UnboundedSender<PeerOp>>,
        conn_type: Option<ConnectionType>,
    ) -> Self {
        let conn_state = ConnectionState::new(peer_tx);
        let (outgoing, incoming) = match conn_type {
            Some(ConnectionType::Outgoing) => (Some(conn_state), None),
            Some(ConnectionType::Incoming) => (None, Some(conn_state)),
            None => (None, None),
        };
        Self {
            admin_state: AdminState::Up,
            import_policies: Vec::new(),
            export_policies: Vec::new(),
            config,
            outgoing,
            incoming,
            adj_rib_out: HashMap::new(),
        }
    }

    /// Get the established connection (only one can be Established)
    pub fn established_conn(&self) -> Option<&ConnectionState> {
        [self.outgoing.as_ref(), self.incoming.as_ref()]
            .into_iter()
            .flatten()
            .find(|c| c.state == BgpState::Established)
    }

    /// Get reference to slot by connection type
    pub fn slot(&self, conn_type: ConnectionType) -> Option<&ConnectionState> {
        match conn_type {
            ConnectionType::Outgoing => self.outgoing.as_ref(),
            ConnectionType::Incoming => self.incoming.as_ref(),
        }
    }

    /// Get mutable reference to slot by connection type
    pub fn slot_mut(&mut self, conn_type: ConnectionType) -> &mut Option<ConnectionState> {
        match conn_type {
            ConnectionType::Outgoing => &mut self.outgoing,
            ConnectionType::Incoming => &mut self.incoming,
        }
    }

    /// Get connection state. Returns the most-progressed connection during collision.
    pub fn max_state(&self) -> (Option<u32>, BgpState) {
        // Prefer established
        if let Some(conn) = self.established_conn() {
            return (conn.asn, conn.state);
        }
        // Pick most-progressed during collision
        [self.outgoing.as_ref(), self.incoming.as_ref()]
            .into_iter()
            .flatten()
            .max_by_key(|c| c.state as u8)
            .map(|c| (c.asn, c.state))
            .unwrap_or((None, BgpState::Idle))
    }

    /// Send operation to all active peer tasks (both incoming and outgoing slots)
    pub fn send_to_all(&self, mut make_op: impl FnMut() -> PeerOp) {
        for conn in [&self.outgoing, &self.incoming].into_iter().flatten() {
            if let Some(peer_tx) = &conn.peer_tx {
                let _ = peer_tx.send(make_op());
            }
        }
    }

    /// Find any connection with a peer_tx (for handing off incoming connections)
    pub fn any_peer_tx(&self) -> Option<&mpsc::UnboundedSender<PeerOp>> {
        // Check outgoing first (passive mode typically has outgoing task waiting)
        self.outgoing
            .as_ref()
            .and_then(|c| c.peer_tx.as_ref())
            .or_else(|| self.incoming.as_ref().and_then(|c| c.peer_tx.as_ref()))
    }

    pub async fn get_statistics(&self) -> Option<PeerStatistics> {
        let peer_tx = self.established_conn()?.peer_tx.as_ref()?;
        let (tx, rx) = oneshot::channel();
        peer_tx.send(PeerOp::GetStatistics(tx)).ok()?;
        rx.await.ok()
    }

    pub fn policy_in(&self) -> &[Arc<Policy>] {
        &self.import_policies
    }

    pub fn policy_out(&self) -> &[Arc<Policy>] {
        &self.export_policies
    }
}

pub struct BgpServer {
    pub(crate) peers: HashMap<IpAddr, PeerInfo>,
    pub(crate) loc_rib: LocRib,
    pub(crate) config: Config,
    pub(crate) policy_ctx: PolicyContext,
    local_bgp_id: u32,
    pub(crate) local_addr: IpAddr,
    pub(crate) local_port: u16,
    pub mgmt_tx: mpsc::Sender<MgmtOp>,
    mgmt_rx: mpsc::Receiver<MgmtOp>,
    op_tx: mpsc::UnboundedSender<ServerOp>,
    op_rx: mpsc::UnboundedReceiver<ServerOp>,
    pub(crate) bmp_tasks: HashMap<SocketAddr, BmpTaskInfo>,
}

impl BgpServer {
    pub fn new(config: Config) -> Result<Self, ServerError> {
        let local_bgp_id = u32::from(config.router_id);
        let sock_addr: SocketAddr = config
            .listen_addr
            .parse()
            .map_err(|_| ServerError::InvalidListenAddr(config.listen_addr.clone()))?;
        let local_addr = sock_addr.ip();

        let (mgmt_tx, mgmt_rx) = mpsc::channel(100);
        let (op_tx, op_rx) = mpsc::unbounded_channel();

        let policy_ctx = PolicyContext::from_config(&config)
            .map_err(|e| ServerError::IoError(io::Error::new(io::ErrorKind::InvalidData, e)))?;

        Ok(BgpServer {
            peers: HashMap::new(),
            loc_rib: LocRib::new(),
            config,
            policy_ctx,
            local_bgp_id,
            local_addr,
            local_port: sock_addr.port(),
            mgmt_tx,
            mgmt_rx,
            op_tx,
            op_rx,
            bmp_tasks: HashMap::new(),
        })
    }

    /// Resolve import policies for a peer from config
    pub(crate) fn resolve_import_policies(&self, peer_config: &PeerConfig) -> Vec<Arc<Policy>> {
        let mut policies = vec![Arc::new(Policy::default_in())];

        // Append user-configured policies
        for name in &peer_config.import_policy {
            if let Some(policy) = self.policy_ctx.policies.get(name).cloned() {
                policies.push(policy);
            } else {
                error!(policy = name, "import policy not found");
            }
        }

        policies
    }

    /// Resolve export policies for a peer from config
    pub(crate) fn resolve_export_policies(&self, peer_config: &PeerConfig) -> Vec<Arc<Policy>> {
        let mut policies = vec![Arc::new(Policy::default_out())];

        // Append user-configured policies
        for name in &peer_config.export_policy {
            if let Some(policy) = self.policy_ctx.policies.get(name).cloned() {
                policies.push(policy);
            } else {
                error!(policy = name, "export policy not found");
            }
        }

        policies
    }

    /// Check if a peer should be accepted (must be pre-configured).
    fn should_accept_peer(&self, peer_ip: IpAddr) -> bool {
        self.peers.contains_key(&peer_ip)
    }

    pub async fn run(mut self) -> Result<(), ServerError> {
        info!(listen_addr = %self.config.listen_addr, "BGP server starting");

        let listener = TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(ServerError::BindError)?;
        self.local_port = listener.local_addr().map_err(ServerError::IoError)?.port();

        let bind_addr = bind_addr_from_ip(self.local_addr);
        self.init_configured_peers(bind_addr);
        self.init_configured_bmp_servers();

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
            let Ok(peer_addr) = peer_cfg.socket_addr() else {
                error!(addr = %peer_cfg.address, "invalid peer address in config");
                continue;
            };
            let peer_ip = peer_addr.ip();
            let config = peer_cfg.clone();
            let passive = config.passive_mode;
            let allow_auto_start = config.allow_automatic_start();

            // Passive mode peers only accept incoming connections
            let conn_type = if passive {
                ConnectionType::Incoming
            } else {
                ConnectionType::Outgoing
            };

            let peer_tx = self.spawn_peer(peer_addr, config.clone(), bind_addr, conn_type);

            // Create peer with connection in the appropriate slot
            let mut entry = PeerInfo::new(config, None, None);
            let conn_state = ConnectionState::new(Some(peer_tx.clone()));
            match conn_type {
                ConnectionType::Outgoing => entry.outgoing = Some(conn_state),
                ConnectionType::Incoming => entry.incoming = Some(conn_state),
            }
            self.peers.insert(peer_ip, entry);

            // RFC 4271: AutomaticStart for configured peers (if allowed)
            if allow_auto_start {
                if passive {
                    let _ = peer_tx.send(PeerOp::AutomaticStartPassive);
                } else {
                    let _ = peer_tx.send(PeerOp::AutomaticStart);
                }
            }
            info!(%peer_ip, passive, "configured peer");
        }
    }

    fn init_configured_bmp_servers(&mut self) {
        for bmp_cfg in &self.config.bmp_servers.clone() {
            let Ok(addr) = bmp_cfg.address.parse::<SocketAddr>() else {
                error!(addr = %bmp_cfg.address, "invalid BMP server address in config");
                continue;
            };

            let task_tx = self.spawn_bmp_task(addr, bmp_cfg.statistics_timeout);
            let task_info = BmpTaskInfo::new(addr, bmp_cfg.statistics_timeout, task_tx);
            self.bmp_tasks.insert(addr, task_info);

            info!(%addr, "configured BMP server");
        }
    }

    /// Spawn a new Peer task in Idle state
    pub(crate) fn spawn_peer(
        &self,
        addr: SocketAddr,
        config: PeerConfig,
        bind_addr: SocketAddr,
        conn_type: ConnectionType,
    ) -> mpsc::UnboundedSender<PeerOp> {
        let (peer_tx, peer_rx) = mpsc::unbounded_channel();

        let local_config = LocalConfig {
            asn: self.config.asn,
            bgp_id: Ipv4Addr::from(self.local_bgp_id.to_be_bytes()),
            hold_time: self.config.hold_time_secs as u16,
            addr: bind_addr,
            cluster_id: self.config.cluster_id(),
        };
        let peer = Peer::new(
            addr.ip(),
            addr.port(),
            peer_rx,
            self.op_tx.clone(),
            local_config,
            config,
            self.config.connect_retry_secs,
            conn_type,
        );

        tokio::spawn(async move {
            peer.run().await;
        });

        peer_tx
    }

    async fn accept_peer(&mut self, stream: TcpStream) {
        let Some(peer_ip) = peer_ip(&stream) else {
            error!("failed to get peer address");
            return;
        };

        info!(%peer_ip, "new peer connection");

        if !self.should_accept_peer(peer_ip) {
            info!(%peer_ip, "rejecting unconfigured peer");
            Self::send_rejection(stream);
            return;
        }

        // RFC 4271 6.8: Collision detection handled at OpenConfirm via check_collision()
        self.accept_incoming_connection(stream, peer_ip);
        info!(%peer_ip, state = "Idle", total_peers = self.peers.len(), "peer added");
    }

    /// Accept an incoming TCP connection for a configured peer.
    /// RFC 4271 6.8: If peer already has an active outgoing connection, this becomes
    /// a collision candidate in the incoming slot.
    /// Caller must ensure peer is pre-configured (via should_accept_peer check).
    pub(crate) fn accept_incoming_connection(&mut self, stream: TcpStream, peer_ip: IpAddr) {
        let Some(peer) = self.peers.get_mut(&peer_ip) else {
            // This should not happen - should_accept_peer should have rejected
            error!(%peer_ip, "accept_incoming_connection called for unconfigured peer");
            return;
        };

        // Passive mode with existing task: send connection to existing task
        if peer.config.passive_mode {
            if let Some(peer_tx) = peer
                .slot(ConnectionType::Incoming)
                .and_then(|c| c.peer_tx.as_ref())
            {
                let (tcp_rx, tcp_tx) = stream.into_split();
                let _ = peer_tx.send(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx });
                info!(%peer_ip, "sent incoming connection to passive peer");
                return;
            }
        }

        // Already have an incoming connection - reject third connection
        if peer.incoming.is_some() {
            info!(%peer_ip, "rejecting: incoming slot already occupied");
            Self::send_rejection(stream);
            return;
        }

        // Check if outgoing is Established with GR capability
        let outgoing_established = peer
            .outgoing
            .as_ref()
            .is_some_and(|out| out.state == BgpState::Established);
        let outgoing_has_gr = peer
            .outgoing
            .as_ref()
            .and_then(|out| out.capabilities.as_ref())
            .and_then(|caps| caps.graceful_restart.as_ref())
            .is_some_and(|gr| !gr.afi_safi_list.is_empty());

        // Handle Established outgoing connection
        if outgoing_established {
            if outgoing_has_gr {
                // RFC 4724: New connection from restarting peer - trigger GR
                info!(%peer_ip, "GR reconnection: closing stale Established, accepting new");
                if let Some(peer_tx) = peer.outgoing.as_ref().and_then(|out| out.peer_tx.clone()) {
                    let _ = peer_tx.send(PeerOp::ManualStop);
                }
                peer.outgoing = None;
            } else {
                info!(%peer_ip, "rejecting: outgoing already Established (no GR)");
                Self::send_rejection(stream);
                return;
            }
        }

        // Spawn incoming connection - let check_collision() decide winner
        let config = peer.config.clone();
        let (peer_tx, peer_rx) = mpsc::unbounded_channel();
        peer.incoming = Some(ConnectionState::new(Some(peer_tx.clone())));
        self.spawn_incoming_with_stream(peer_rx, &peer_tx, stream, peer_ip, config);
        info!(%peer_ip, "spawned incoming connection");
    }

    /// Send rejection notification in background task.
    /// Non-blocking to avoid stalling the server's event loop on socket writes.
    fn send_rejection(mut stream: TcpStream) {
        tokio::spawn(async move {
            let notif =
                NotificationMessage::new(BgpError::Cease(CeaseSubcode::ConnectionRejected), vec![]);
            let _ = stream.write_all(&notif.serialize()).await;
        });
    }

    /// Spawn incoming peer task with pre-created channel.
    ///
    /// Caller must set up the incoming slot with peer_tx BEFORE calling this,
    /// to avoid race where task sends PeerStateChanged before slot exists.
    fn spawn_incoming_with_stream(
        &self,
        peer_rx: mpsc::UnboundedReceiver<PeerOp>,
        peer_tx: &mpsc::UnboundedSender<PeerOp>,
        stream: TcpStream,
        peer_ip: IpAddr,
        config: PeerConfig,
    ) {
        // Use port 0 (ephemeral) so this peer can make outgoing connections if needed
        // (e.g., after collision resolution or hard reset when passive_mode=false).
        // Using stream.local_addr() would give us the server's listening port, which
        // would cause EADDRINUSE when trying to reconnect.
        let local_addr = bind_addr_from_ip(
            stream
                .local_addr()
                .map(|a| a.ip())
                .unwrap_or(self.local_addr),
        );

        let (tcp_rx, tcp_tx) = stream.into_split();

        let local_config = LocalConfig {
            asn: self.config.asn,
            bgp_id: Ipv4Addr::from(self.local_bgp_id.to_be_bytes()),
            hold_time: self.config.hold_time_secs as u16,
            addr: local_addr,
            cluster_id: self.config.cluster_id(),
        };
        let peer = Peer::new(
            peer_ip,
            config.port,
            peer_rx,
            self.op_tx.clone(),
            local_config,
            config.clone(),
            self.config.connect_retry_secs,
            ConnectionType::Incoming,
        );

        tokio::spawn(async move {
            peer.run().await;
        });

        // RFC 4271 8.2.2: Send start event only if AllowAutomaticStart is true
        // If false, FSM stays in Idle and will refuse the connection per RFC 4271 8.2.2
        if config.allow_automatic_start() {
            if config.passive_mode {
                let _ = peer_tx.send(PeerOp::AutomaticStartPassive);
            } else {
                let _ = peer_tx.send(PeerOp::AutomaticStart);
            }
        }

        // Always send TCP connection - let FSM decide what to do with it
        let _ = peer_tx.send(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx });
    }

    /// Spawn a BMP task for a destination
    pub(crate) fn spawn_bmp_task(
        &self,
        addr: SocketAddr,
        statistics_timeout: Option<u64>,
    ) -> mpsc::UnboundedSender<Arc<BmpOp>> {
        let (task_tx, task_rx) = mpsc::unbounded_channel();

        let destination = BmpDestination::TcpClient(BmpTcpClient::new(addr));

        let task = BmpTask::new(
            addr,
            destination,
            task_rx,
            self.op_tx.clone(),
            statistics_timeout,
        );

        let sys_name = self.config.sys_name();
        let sys_descr = self.config.sys_descr();

        tokio::spawn(async move {
            task.run(sys_name, sys_descr).await;
        });

        task_tx
    }

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
    /// RFC 4456 Route Reflector filtering is handled by compute_routes_for_peer based on:
    /// - path.source.is_rr_client(): whether source peer was an RR client
    /// - rr_client: whether peer is an RR client
    pub(crate) async fn propagate_routes(
        &mut self,
        delta: RouteDelta,
        originating_peer: Option<IpAddr>,
    ) {
        let local_asn = self.config.asn;
        let cluster_id = self.config.cluster_id();

        // For non-ADD-PATH peers: compute to_announce/to_withdraw from best_changed
        let mut to_announce = Vec::new();
        let mut to_withdraw = Vec::new();

        for prefix in &delta.best_changed {
            if let Some(best_path) = self.loc_rib.get_best_path(prefix) {
                to_announce.push((*prefix, best_path.clone()));
            } else {
                to_withdraw.push(*prefix);
            }
        }

        // Collect per-peer adj_rib_out updates so we can apply them after immutable iteration.
        // Each entry: (peer_addr, routes_sent, prefixes_withdrawn_fully, per_path_id_withdrawn)
        #[allow(clippy::type_complexity)]
        let mut adj_rib_updates: Vec<(
            IpAddr,
            Vec<(IpNetwork, Arc<Path>)>,
            Vec<IpNetwork>,
            Vec<(IpNetwork, u32)>,
        )> = Vec::new();

        // Send updates to all established peers (except the originating peer)
        for (peer_addr, entry) in self.peers.iter() {
            let Some(conn) = entry.established_conn() else {
                continue;
            };

            if !should_propagate_to_peer(*peer_addr, conn.state, originating_peer) {
                continue;
            }

            let Some(peer_tx) = &conn.peer_tx else {
                continue;
            };

            let peer_asn = conn.asn.unwrap_or(local_asn);
            let rr_client = entry.config.rr_client;

            let local_next_hop = conn
                .conn_info
                .as_ref()
                .map(|conn_info| conn_info.local_address)
                .unwrap_or(self.local_addr);

            let export_policies = entry.policy_out();
            if export_policies.is_empty() {
                error!(peer_ip = %peer_addr, "export policies not set for established peer");
                continue;
            }

            let peer_supports_4byte_asn = conn
                .capabilities
                .as_ref()
                .map(|caps| caps.supports_four_octet_asn())
                .unwrap_or(false);

            // Check ADD-PATH send negotiation
            let add_path_send = conn
                .capabilities
                .as_ref()
                .map(|caps| {
                    let ipv4_uni = AfiSafi {
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                    };
                    let ipv6_uni = AfiSafi {
                        afi: Afi::Ipv6,
                        safi: Safi::Unicast,
                    };
                    caps.add_path_send_negotiated(&ipv4_uni)
                        || caps.add_path_send_negotiated(&ipv6_uni)
                })
                .unwrap_or(false);

            if add_path_send {
                // ADD-PATH peer: diff all paths against adj_rib_out
                let mut addpath_to_announce = Vec::new();
                let mut addpath_to_withdraw = Vec::new();

                for prefix in &delta.changed {
                    let current_paths = self.loc_rib.get_all_paths(prefix);

                    // Collect adj_rib_out path IDs for this prefix
                    let adj_path_ids: Vec<u32> = entry
                        .adj_rib_out
                        .keys()
                        .filter(|(p, _)| p == prefix)
                        .map(|(_, pid)| *pid)
                        .collect();

                    // Announce all current paths (re-announce = implicit replace)
                    for path in &current_paths {
                        addpath_to_announce.push((*prefix, path.clone()));
                    }

                    // Withdraw paths in adj_rib_out but not in loc_rib
                    for pid in &adj_path_ids {
                        if !current_paths.iter().any(|p| p.local_path_id == Some(*pid)) {
                            addpath_to_withdraw.push((*prefix, *pid));
                        }
                    }
                }

                // Send ADD-PATH withdrawals (per path_id)
                if !addpath_to_withdraw.is_empty() {
                    send_addpath_withdrawals_to_peer(
                        *peer_addr,
                        peer_tx,
                        &addpath_to_withdraw,
                        peer_supports_4byte_asn,
                    );
                }

                // Send ADD-PATH announcements
                let sent = send_announcements_to_peer(
                    *peer_addr,
                    peer_tx,
                    &addpath_to_announce,
                    local_asn,
                    peer_asn,
                    local_next_hop,
                    export_policies,
                    peer_supports_4byte_asn,
                    rr_client,
                    cluster_id,
                    true, // add_path
                );

                adj_rib_updates.push((*peer_addr, sent, Vec::new(), addpath_to_withdraw));
            } else {
                // Non-ADD-PATH peer: use best_changed (original behavior)
                let peer_withdrawals: Vec<IpNetwork> = to_withdraw
                    .iter()
                    .filter(|prefix| entry.adj_rib_out.keys().any(|(p, _)| p == *prefix))
                    .cloned()
                    .collect();

                send_withdrawals_to_peer(
                    *peer_addr,
                    peer_tx,
                    &peer_withdrawals,
                    peer_supports_4byte_asn,
                );
                let sent = send_announcements_to_peer(
                    *peer_addr,
                    peer_tx,
                    &to_announce,
                    local_asn,
                    peer_asn,
                    local_next_hop,
                    export_policies,
                    peer_supports_4byte_asn,
                    rr_client,
                    cluster_id,
                    false, // add_path
                );

                adj_rib_updates.push((*peer_addr, sent, peer_withdrawals, Vec::new()));
            }
        }

        // Update adj_rib_out for each peer (mutable access)
        for (peer_addr, sent, withdrawn_prefixes, withdrawn_path_ids) in adj_rib_updates {
            if let Some(entry) = self.peers.get_mut(&peer_addr) {
                // Remove fully withdrawn prefixes (non-ADD-PATH)
                for prefix in &withdrawn_prefixes {
                    entry.adj_rib_out.retain(|(p, _), _| p != prefix);
                }
                // Remove per-path-id withdrawals (ADD-PATH)
                for (prefix, pid) in &withdrawn_path_ids {
                    entry.adj_rib_out.remove(&(*prefix, *pid));
                }
                // Insert sent routes
                for (prefix, path) in sent {
                    entry.adj_rib_out.insert(
                        (
                            prefix,
                            path.local_path_id.expect("loc-rib path must have ID"),
                        ),
                        path,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn peer_info() -> PeerInfo {
        PeerInfo::new(PeerConfig::default(), None, None)
    }

    fn make_server() -> BgpServer {
        let config = Config::new(65000, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 180);
        BgpServer::new(config).expect("valid config")
    }

    #[test]
    fn test_should_accept_peer() {
        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Unconfigured peer -> reject
        let server = make_server();
        assert!(!server.should_accept_peer(peer_ip));

        // Configured peer -> accept
        let mut server = make_server();
        server.peers.insert(peer_ip, peer_info());
        assert!(server.should_accept_peer(peer_ip));
    }
}
