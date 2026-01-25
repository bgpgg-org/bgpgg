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
use crate::bgp::multiprotocol::{Afi, Safi};
use crate::bmp::destination::{BmpDestination, BmpTcpClient};
use crate::bmp::task::BmpTask;
use crate::config::{Config, PeerConfig};
use crate::log::Logger;
use crate::net::IpNetwork;
use crate::net::{bind_addr_from_ip, peer_ip};
use crate::peer::outgoing::{
    send_announcements_to_peer, send_withdrawals_to_peer, should_propagate_to_peer,
};
use crate::peer::BgpState;
use crate::peer::{Peer, PeerCapabilities, PeerOp, PeerStatistics};
use crate::policy::{DefinedSetType, Policy, PolicyContext};
use crate::rib::rib_loc::LocRib;
use crate::rib::{Path, Route};
use crate::types::PeerDownReason;
use crate::{error, info};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
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
    pub configured: bool,
    pub import_policies: Vec<String>,
    pub export_policies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GetPeerResponse {
    pub address: String,
    pub asn: Option<u32>,
    pub state: BgpState,
    pub admin_state: AdminState,
    pub configured: bool,
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
    },
    PeerHandshakeComplete {
        peer_ip: IpAddr,
        asn: u32,
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
    },
    PeerUpdate {
        peer_ip: IpAddr,
        withdrawn: Vec<IpNetwork>,
        announced: Vec<(IpNetwork, Arc<Path>)>,
    },
    PeerDisconnected {
        peer_ip: IpAddr,
        reason: PeerDownReason,
    },
    /// Set peer's admin state (e.g., when max prefix limit exceeded)
    SetAdminState {
        peer_ip: IpAddr,
        state: AdminState,
    },
    /// Route Refresh request from peer
    RouteRefresh {
        peer_ip: IpAddr,
        afi: Afi,
        safi: Safi,
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

/// Peer configuration and state stored in server's HashMap.
/// The peer IP is the HashMap key.
pub struct PeerInfo {
    pub admin_state: AdminState,
    /// true if explicitly configured, false if accepted via accept_unconfigured_peers
    pub configured: bool,
    pub asn: Option<u32>,
    /// BGP Identifier from OPEN message, used for collision detection (RFC 4271 Section 6.8)
    pub bgp_id: Option<u32>,
    pub import_policies: Vec<Arc<Policy>>,
    pub export_policies: Vec<Arc<Policy>>,
    pub state: BgpState,
    pub peer_tx: Option<mpsc::UnboundedSender<PeerOp>>,
    /// Per-peer session configuration
    pub config: PeerConfig,
    /// Connection info (Some when Established, None otherwise)
    pub conn_info: Option<ConnectionInfo>,
    /// Negotiated capabilities (available when Established)
    pub negotiated_capabilities: Option<PeerCapabilities>,
}

impl PeerInfo {
    pub fn new(
        configured: bool,
        config: PeerConfig,
        peer_tx: Option<mpsc::UnboundedSender<PeerOp>>,
    ) -> Self {
        Self {
            admin_state: AdminState::Up,
            configured,
            asn: None,
            bgp_id: None,
            import_policies: Vec::new(),
            export_policies: Vec::new(),
            state: BgpState::Idle,
            peer_tx,
            config,
            conn_info: None,
            negotiated_capabilities: None,
        }
    }

    pub async fn get_statistics(&self) -> Option<PeerStatistics> {
        let peer_tx = self.peer_tx.as_ref()?;
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
    pub(crate) logger: Arc<Logger>,
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

        let log_level = config.parse_log_level();
        let logger = Arc::new(Logger::new(log_level));

        let policy_ctx = PolicyContext::from_config(&config)
            .map_err(|e| ServerError::IoError(io::Error::new(io::ErrorKind::InvalidData, e)))?;

        Ok(BgpServer {
            peers: HashMap::new(),
            loc_rib: LocRib::new(logger.clone()),
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
            logger,
        })
    }

    /// Resolve import policies for a peer from config
    pub(crate) fn resolve_import_policies(&self, peer_config: &PeerConfig) -> Vec<Arc<Policy>> {
        // Always start with default_in policy (AS-loop prevention, etc.)
        let mut policies = vec![Arc::new(Policy::default_in(self.config.asn))];

        // Append user-configured policies
        for name in &peer_config.import_policy {
            if let Some(policy) = self.policy_ctx.policies.get(name).cloned() {
                policies.push(policy);
            } else {
                error!(&self.logger, "import policy not found", "policy" => name);
            }
        }

        policies
    }

    /// Resolve export policies for a peer from config
    pub(crate) fn resolve_export_policies(
        &self,
        peer_config: &PeerConfig,
        peer_asn: u32,
    ) -> Vec<Arc<Policy>> {
        // Always start with default_out policy (iBGP reflection prevention, etc.)
        let mut policies = vec![Arc::new(Policy::default_out(self.config.asn, peer_asn))];

        // Append user-configured policies
        for name in &peer_config.export_policy {
            if let Some(policy) = self.policy_ctx.policies.get(name).cloned() {
                policies.push(policy);
            } else {
                error!(&self.logger, "export policy not found", "policy" => name);
            }
        }

        policies
    }

    /// Check if a peer should be accepted.
    fn should_accept_peer(&self, peer_ip: IpAddr) -> bool {
        let is_configured = self.peers.contains_key(&peer_ip);
        is_configured || self.config.accept_unconfigured_peers
    }

    /// Resolve connection collision per RFC 4271 6.8.
    /// Returns true if new connection should be rejected. Closes existing connection if it loses.
    pub(crate) fn resolve_collision(&mut self, peer_ip: IpAddr, conn_type: ConnectionType) -> bool {
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
            info!(&self.logger, "collision: ignoring in Established state", "peer_ip" => peer_ip.to_string());
            return true; // Reject new connection
        }

        // RFC 4271 6.8: If BGP ID unknown, accept connection
        // Peer task will resolve collision after OPEN messages are exchanged
        if peer.bgp_id.is_none() {
            return false; // Accept - defer to peer task
        }

        // RFC 4271 6.8: Compare BGP Identifiers
        // local < remote: close local-initiated, keep remote-initiated
        // local >= remote: close remote-initiated, keep local-initiated
        let dominated = match conn_type {
            ConnectionType::Incoming => self.local_bgp_id >= peer.bgp_id.unwrap(),
            ConnectionType::Outgoing => self.local_bgp_id < peer.bgp_id.unwrap(),
        };

        if dominated {
            info!(&self.logger, "collision: rejecting new connection", "peer_ip" => peer_ip.to_string());
            return true; // Reject new connection
        }

        // We win: close existing connection, accept new
        info!(&self.logger, "collision: closing existing", "peer_ip" => peer_ip.to_string());
        if let Some(peer) = self.peers.get_mut(&peer_ip) {
            if let Some(tx) = peer.peer_tx.take() {
                let _ = tx.send(PeerOp::Shutdown(
                    CeaseSubcode::ConnectionCollisionResolution,
                ));
            }
        }
        false // Accept new connection
    }

    pub async fn run(mut self) -> Result<(), ServerError> {
        info!(&self.logger, "BGP server starting", "listen_addr" => &self.config.listen_addr);

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
            let Ok(peer_addr) = peer_cfg.address.parse::<SocketAddr>() else {
                error!(&self.logger, "invalid peer address in config", "addr" => &peer_cfg.address);
                continue;
            };
            let peer_ip = peer_addr.ip();
            let config = peer_cfg.clone();
            let passive = config.passive_mode;
            let allow_auto_start = config.allow_automatic_start();

            let peer_tx = self.spawn_peer(peer_addr, config.clone(), bind_addr);

            let entry = PeerInfo::new(true, config, Some(peer_tx.clone()));
            self.peers.insert(peer_ip, entry);

            // RFC 4271: AutomaticStart for configured peers (if allowed)
            if allow_auto_start {
                if passive {
                    let _ = peer_tx.send(PeerOp::AutomaticStartPassive);
                } else {
                    let _ = peer_tx.send(PeerOp::AutomaticStart);
                }
            }
            info!(&self.logger, "configured peer", "peer_ip" => peer_ip.to_string(), "passive" => passive);
        }
    }

    fn init_configured_bmp_servers(&mut self) {
        for bmp_cfg in &self.config.bmp_servers.clone() {
            let Ok(addr) = bmp_cfg.address.parse::<SocketAddr>() else {
                error!(&self.logger, "invalid BMP server address in config", "addr" => &bmp_cfg.address);
                continue;
            };

            let task_tx = self.spawn_bmp_task(addr, bmp_cfg.statistics_timeout);
            let task_info = BmpTaskInfo::new(addr, bmp_cfg.statistics_timeout, task_tx);
            self.bmp_tasks.insert(addr, task_info);

            info!(&self.logger, "configured BMP server", "addr" => addr.to_string());
        }
    }

    /// Spawn a new Peer task in Idle state
    pub(crate) fn spawn_peer(
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
            self.logger.clone(),
        );

        tokio::spawn(async move {
            peer.run().await;
        });

        peer_tx
    }

    async fn accept_peer(&mut self, mut stream: TcpStream) {
        let Some(peer_ip) = peer_ip(&stream) else {
            error!(&self.logger, "failed to get peer address");
            return;
        };

        info!(&self.logger, "new peer connection", "peer_ip" => peer_ip.to_string());

        if !self.should_accept_peer(peer_ip) {
            info!(&self.logger, "rejecting unconfigured peer", "peer_ip" => peer_ip.to_string());
            let notif = NotificationMessage::new(
                BgpError::Cease(CeaseSubcode::ConnectionRejected),
                Vec::new(),
            );
            let _ = stream.write_all(&notif.serialize()).await;
            return;
        }

        // RFC 4271 6.8: Collision detection will be handled when OPENs are received
        if self.resolve_collision(peer_ip, ConnectionType::Incoming) {
            return;
        }

        self.accept_incoming_connection(stream, peer_ip);
        info!(&self.logger, "peer added", "peer_ip" => peer_ip.to_string(), "state" => "Idle", "total_peers" => self.peers.len());
    }

    /// Accept an incoming TCP connection and create/update peer entry.
    pub(crate) fn accept_incoming_connection(&mut self, stream: TcpStream, peer_ip: IpAddr) {
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
                .insert(peer_ip, PeerInfo::new(false, config, Some(peer_tx)));
        }
    }

    /// Create a peer from a connected stream and spawn a task.
    /// Returns None if AllowAutomaticStart is false (RFC 4271 8.1.1).
    pub(crate) fn spawn_peer_from_stream(
        &self,
        stream: TcpStream,
        peer_ip: IpAddr,
        config: PeerConfig,
    ) -> Option<mpsc::UnboundedSender<PeerOp>> {
        // RFC 4271 8.1.1: AllowAutomaticStart must be true for automatic events
        if !config.allow_automatic_start() {
            info!(&self.logger, "rejecting incoming: AllowAutomaticStart is false", "peer_ip" => peer_ip.to_string());
            return None;
        }

        let local_addr = stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::new(self.local_addr, 0));

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

    /// Spawn a BMP task for a destination
    pub(crate) fn spawn_bmp_task(
        &self,
        addr: SocketAddr,
        statistics_timeout: Option<u64>,
    ) -> mpsc::UnboundedSender<Arc<BmpOp>> {
        let (task_tx, task_rx) = mpsc::unbounded_channel();

        let destination = BmpDestination::TcpClient(BmpTcpClient::new(addr, self.logger.clone()));

        let task = BmpTask::new(
            addr,
            destination,
            task_rx,
            self.op_tx.clone(),
            statistics_timeout,
            self.logger.clone(),
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
    pub(crate) async fn propagate_routes(
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

            // Get local address used for this peering session (RFC 4271 5.1.3)
            // Falls back to router ID if connection info not available
            let local_next_hop = entry
                .conn_info
                .as_ref()
                .map(|conn_info| conn_info.local_address)
                .unwrap_or(self.local_addr);

            let export_policies = entry.policy_out();
            if !export_policies.is_empty() {
                let peer_supports_4byte_asn = entry
                    .negotiated_capabilities
                    .as_ref()
                    .map(|caps| caps.supports_four_octet_asn())
                    .unwrap_or(false);

                send_withdrawals_to_peer(
                    *peer_addr,
                    peer_tx,
                    &to_withdraw,
                    peer_supports_4byte_asn,
                    &self.logger,
                );
                send_announcements_to_peer(
                    *peer_addr,
                    peer_tx,
                    &to_announce,
                    local_asn,
                    peer_asn,
                    local_next_hop,
                    export_policies,
                    peer_supports_4byte_asn,
                    &self.logger,
                );
            } else {
                error!(&self.logger, "export policies not set for established peer", "peer_ip" => peer_addr.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn peer_info() -> PeerInfo {
        PeerInfo::new(true, PeerConfig::default(), None)
    }

    fn make_server(accept_unconfigured_peers: bool) -> BgpServer {
        let config = Config::new(
            65000,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            180,
            accept_unconfigured_peers,
        );
        BgpServer::new(config).expect("valid config")
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
