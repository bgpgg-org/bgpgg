// Copyright 2026 bgpgg Authors
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

pub(crate) mod ops;
pub(crate) mod ops_mgmt;
pub(crate) mod propagate;

use crate::bgp::msg::{AddPathMask, Message, MessageFormat, PRE_OPEN_FORMAT};
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::msg_update::UpdateMessage;
use crate::bgp::multiprotocol::AfiSafi;
use crate::bmp::destination::{BmpDestination, BmpTcpClient};
use crate::bmp::task::BmpTask;
use crate::config::{get_peer_llgr, Config, PeerConfig};
use crate::log::{error, info, warn};
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::net::apply_gtsm;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::net::apply_tcp_md5;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::net::set_ttl_max;
use crate::net::{bind_addr_from_ip, peer_ip};
use crate::peer::BgpState;
use crate::peer::{LocalConfig, Peer, PeerCapabilities, PeerOp, PeerStatistics};
use crate::policy::{Policy, PolicyContext};
use crate::rib::rib_in::AdjRibIn;
use crate::rib::rib_loc::LocRib;
use crate::rib::AdjRibOut;
use crate::rpki::manager::{RpkiOp, RtrCacheConfig, RtrManager};
use crate::rpki::vrp::VrpTable;
use crate::types::PeerDownReason;
use ops::ServerOp;
use ops_mgmt::MgmtOp;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

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
    pub config: PeerConfig,
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

// Re-exported from ops_mgmt where the handler lives

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

    pub fn supports_four_octet_asn(&self) -> bool {
        self.capabilities
            .as_ref()
            .is_some_and(|caps| caps.supports_four_octet_asn())
    }

    pub fn add_path_send_negotiated(&self, afi_safi: &AfiSafi) -> bool {
        self.capabilities
            .as_ref()
            .is_some_and(|caps| caps.add_path_send_negotiated(afi_safi))
    }

    pub fn add_path_receive_negotiated(&self, afi_safi: &AfiSafi) -> bool {
        self.capabilities
            .as_ref()
            .is_some_and(|caps| caps.add_path_receive_negotiated(afi_safi))
    }

    pub fn add_path_receive(&self) -> bool {
        self.capabilities
            .as_ref()
            .is_some_and(|caps| caps.add_path_receive())
    }

    /// Returns the negotiated multiprotocol AFI/SAFIs, or empty set if none negotiated.
    /// An empty set signals IPv4/Unicast-only fallback (RFC 4760).
    pub fn negotiated_afi_safis(&self) -> HashSet<AfiSafi> {
        self.capabilities
            .as_ref()
            .map(|caps| caps.multiprotocol.clone())
            .unwrap_or_default()
    }

    /// MessageFormat for encoding outgoing messages to this peer
    pub fn send_format(&self) -> MessageFormat {
        self.capabilities
            .as_ref()
            .map(|caps| caps.send_format(None))
            .unwrap_or(PRE_OPEN_FORMAT)
    }

    /// MessageFormat for parsing incoming messages from this peer
    pub fn receive_format(&self) -> MessageFormat {
        self.capabilities
            .as_ref()
            .map(|caps| caps.receive_format(None))
            .unwrap_or(PRE_OPEN_FORMAT)
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
    /// Per-peer adj-rib-in: routes received from this peer before import policy.
    pub adj_rib_in: AdjRibIn,
    /// Per-peer adj-rib-out: tracks routes actually exported to this peer.
    pub adj_rib_out: AdjRibOut,
    /// AFI/SAFIs disabled due to non-negotiated UPDATE (RFC 4760 Section 7)
    pub disabled_afi_safi: HashSet<AfiSafi>,
    /// RFC 9494: Running LLGR stale timers per AFI/SAFI
    pub llgr_timers: LlgrTimers,
}

/// Manages per-AFI/SAFI LLGR stale timers for a peer (RFC 9494).
#[derive(Default)]
pub struct LlgrTimers {
    timers: HashMap<AfiSafi, JoinHandle<()>>,
}

impl LlgrTimers {
    pub fn new() -> Self {
        Self {
            timers: HashMap::new(),
        }
    }

    /// Start a timer if not already running. Existing timers MUST NOT be updated (RFC 9494).
    pub fn run(
        &mut self,
        afi_safi: AfiSafi,
        llst: u32,
        peer_ip: IpAddr,
        server_tx: mpsc::UnboundedSender<ServerOp>,
    ) {
        self.timers.entry(afi_safi).or_insert_with(|| {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(llst as u64)).await;
                let _ = server_tx.send(ServerOp::LlgrTimerExpired { peer_ip, afi_safi });
            })
        });
    }

    /// Cancel a running timer. No-op if not running.
    pub fn cancel(&mut self, afi_safi: &AfiSafi) {
        if let Some(handle) = self.timers.remove(afi_safi) {
            handle.abort();
        }
    }

    /// AFI/SAFIs with running timers.
    pub fn afi_safis(&self) -> Vec<AfiSafi> {
        self.timers.keys().copied().collect()
    }
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
            adj_rib_in: AdjRibIn::new(),
            adj_rib_out: AdjRibOut::new(),
            disabled_afi_safi: HashSet::new(),
            llgr_timers: LlgrTimers::new(),
        }
    }

    /// Get the established connection (only one can be Established)
    pub fn established_conn(&self) -> Option<&ConnectionState> {
        [self.outgoing.as_ref(), self.incoming.as_ref()]
            .into_iter()
            .flatten()
            .find(|c| c.state == BgpState::Established)
    }

    /// Get mutable reference to the established connection
    pub fn established_conn_mut(&mut self) -> Option<&mut ConnectionState> {
        [self.outgoing.as_mut(), self.incoming.as_mut()]
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

    pub fn supports_4byte_asn(&self) -> bool {
        self.established_conn()
            .and_then(|c| c.capabilities.as_ref())
            .map(|caps| caps.supports_four_octet_asn())
            .unwrap_or(true)
    }

    pub fn add_path_receive_mask(&self) -> AddPathMask {
        self.established_conn()
            .map(|conn| conn.receive_format().add_path)
            .unwrap_or(AddPathMask::NONE)
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
    pub(crate) op_tx: mpsc::UnboundedSender<ServerOp>,
    op_rx: mpsc::UnboundedReceiver<ServerOp>,
    pub(crate) bmp_tasks: HashMap<SocketAddr, BmpTaskInfo>,
    /// Channel to send operations to the RtrManager (RPKI).
    pub(crate) rpki_tx: Option<mpsc::UnboundedSender<RpkiOp>>,
    /// RPKI VRP table for origin validation (RFC 6811).
    pub(crate) vrp_table: VrpTable,
    /// Raw fd of the listener socket, stored for TCP MD5 setup on new peers
    pub(crate) listener_fd: Option<i32>,
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
            rpki_tx: None,
            vrp_table: VrpTable::new(),
            listener_fd: None,
        })
    }

    /// Resolve import policies for a peer from config
    pub(crate) fn resolve_import_policies(&self, peer_config: &PeerConfig) -> Vec<Arc<Policy>> {
        let mut policies = Vec::new();

        // User policies run first
        for name in &peer_config.import_policy {
            if let Some(policy) = self.policy_ctx.policies.get(name).cloned() {
                policies.push(policy);
            } else {
                error!(policy = name, "import policy not found");
            }
        }

        // Unconditional accept as fallback
        policies.push(Arc::new(Policy::default_in()));

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

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    fn setup_listener_tcp_md5(&mut self, listener: &TcpListener) {
        let fd = listener.as_raw_fd();
        self.listener_fd = Some(fd);
        for peer_cfg in &self.config.peers {
            let Ok(addr) = peer_cfg.socket_addr() else {
                continue;
            };
            if let Some(key) = peer_cfg.read_md5_key() {
                if let Err(e) = apply_tcp_md5(fd, addr.ip(), &key) {
                    error!(peer = %addr, error = %e, "failed to set TCP MD5 on listener");
                }
            }
        }
    }

    pub async fn run(mut self) -> Result<(), ServerError> {
        info!(listen_addr = %self.config.listen_addr, "BGP server starting");

        let listener = TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(ServerError::BindError)?;
        self.local_port = listener.local_addr().map_err(ServerError::IoError)?.port();

        // Set outgoing TTL=255 on the listener so SYN-ACKs are sent with TTL=255.
        // Remote peers that enforce GTSM by setting IP_MINTTL before connect() will
        // otherwise drop our SYN-ACK (which arrives with the OS default TTL of 64).
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        if let Err(e) = set_ttl_max(listener.as_raw_fd(), self.local_addr) {
            warn!(error = %e, "failed to set TTL=255 on listener");
        }

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        self.setup_listener_tcp_md5(&listener);

        let bind_addr = bind_addr_from_ip(self.local_addr);
        self.init_configured_peers(bind_addr);
        self.init_configured_bmp_servers();
        self.init_configured_rpki_caches();

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

    fn init_configured_rpki_caches(&mut self) {
        if self.config.rpki_caches.is_empty() {
            return;
        }

        let rpki_tx = self.spawn_rtr_manager();

        for rpki_cfg in &self.config.rpki_caches.clone() {
            let Ok(addr) = rpki_cfg.address.parse::<SocketAddr>() else {
                error!(addr = %rpki_cfg.address, "invalid RPKI cache address in config");
                continue;
            };

            let cache_config = RtrCacheConfig {
                address: addr,
                preference: rpki_cfg.preference,
                retry_interval: rpki_cfg.retry_interval,
                refresh_interval: rpki_cfg.refresh_interval,
                expire_interval: rpki_cfg.expire_interval,
            };
            let _ = rpki_tx.send(RpkiOp::AddCache(cache_config));
            info!(%addr, "configured RPKI cache");
        }
    }

    fn spawn_rtr_manager(&mut self) -> mpsc::UnboundedSender<RpkiOp> {
        let (rpki_tx, rpki_rx) = mpsc::unbounded_channel();
        let manager = RtrManager::new(rpki_rx, self.op_tx.clone());

        tokio::spawn(async move {
            manager.run().await;
        });

        self.rpki_tx = Some(rpki_tx.clone());
        rpki_tx
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

        let llgr = get_peer_llgr(&self.config.llgr, &config.llgr);
        let local_config = LocalConfig {
            asn: self.config.asn,
            bgp_id: Ipv4Addr::from(self.local_bgp_id.to_be_bytes()),
            hold_time: self.config.hold_time_secs as u16,
            addr: bind_addr,
            cluster_id: self.config.cluster_id(),
            llgr,
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

        // Apply GTSM on the accepted socket if configured
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        if let Some(min_ttl) = peer.config.ttl_min {
            if let Err(e) = apply_gtsm(stream.as_raw_fd(), peer_ip, min_ttl) {
                warn!(%peer_ip, error = %e, "failed to apply GTSM on incoming connection");
            }
        }

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

        let llgr = get_peer_llgr(&self.config.llgr, &config.llgr);
        let local_config = LocalConfig {
            asn: self.config.asn,
            bgp_id: Ipv4Addr::from(self.local_bgp_id.to_be_bytes()),
            hold_time: self.config.hold_time_secs as u16,
            addr: local_addr,
            cluster_id: self.config.cluster_id(),
            llgr,
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
