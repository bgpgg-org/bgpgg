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

use crate::bgp::msg::BgpMessage;
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::multiprotocol::AfiSafi;
use crate::bgp::utils::ParserError;
use crate::config::PeerConfig;
use crate::log::Logger;
use crate::rib::rib_in::AdjRibIn;
use crate::rib::Route;
use crate::server::{ConnectionType, ServerOp};
use crate::types::PeerDownReason;
use crate::{debug, error, info};
use std::collections::HashSet;
use std::fmt;
use std::io::Error;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// BGP capabilities negotiated between peers
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerCapabilities {
    /// Multiprotocol extensions (RFC 4760)
    pub multiprotocol: HashSet<AfiSafi>,
    /// Route Refresh capability (RFC 2918)
    pub route_refresh: bool,
    /// Four-Octet ASN capability (RFC 6793)
    /// Contains the peer's 4-byte ASN if advertised
    pub four_octet_asn: Option<u32>,
}

impl PeerCapabilities {
    /// Check if a specific AFI/SAFI is negotiated
    pub fn supports_afi_safi(&self, afi_safi: &AfiSafi) -> bool {
        self.multiprotocol.contains(afi_safi)
    }

    /// Check if peer supports 4-byte ASNs (RFC 6793)
    pub fn supports_four_octet_asn(&self) -> bool {
        self.four_octet_asn.is_some()
    }
}

/// Parameters from received BGP OPEN message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpOpenParams {
    pub peer_asn: u32,
    pub peer_hold_time: u16,
    pub peer_bgp_id: u32,
    pub local_asn: u32,
    pub local_hold_time: u16,
    pub peer_capabilities: PeerCapabilities,
}

mod fsm;
mod incoming;
mod messages;
mod state_active;
mod state_connect;
mod state_established;
mod state_idle;
mod state_openconfirm;
mod state_opensent;
mod states;

pub mod outgoing;

// Re-export FSM types so they can be used from outside the peer module
pub use fsm::{BgpState, Fsm, FsmEvent, FsmTimers};

/// Errors that can occur during peer FSM event processing
#[derive(Debug)]
pub enum PeerError {
    /// FSM protocol error - unexpected event in current state
    FsmError,
    /// Automatic stop requested with cease subcode
    AutomaticStop(CeaseSubcode),
    /// BGP UPDATE message validation error
    UpdateError,
    /// I/O error during message send/receive
    IoError(Error),
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerError::FsmError => write!(f, "FSM protocol error"),
            PeerError::AutomaticStop(subcode) => write!(f, "automatic stop: {:?}", subcode),
            PeerError::UpdateError => write!(f, "UPDATE message error"),
            PeerError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl From<Error> for PeerError {
    fn from(e: Error) -> Self {
        PeerError::IoError(e)
    }
}

impl From<PeerError> for Error {
    fn from(e: PeerError) -> Self {
        match e {
            PeerError::IoError(io_err) => io_err,
            _ => Error::other(e.to_string()),
        }
    }
}

/// RFC 4271 8.1.1: Maximum IdleHoldTime for DampPeerOscillations backoff.
const MAX_IDLE_HOLD_TIME: Duration = Duration::from_secs(120);

/// Operations that can be sent to a peer task
pub enum PeerOp {
    SendUpdate(Vec<u8>),
    SendRouteRefresh {
        afi: crate::bgp::multiprotocol::Afi,
        safi: crate::bgp::multiprotocol::Safi,
    },
    GetStatistics(oneshot::Sender<PeerStatistics>),
    GetAdjRibIn(oneshot::Sender<Vec<Route>>),
    GetNegotiatedCapabilities(oneshot::Sender<PeerCapabilities>),
    /// Graceful shutdown - sends CEASE NOTIFICATION with given subcode and closes connection
    Shutdown(CeaseSubcode),
    /// Hard reset - sends CEASE/ADMINISTRATIVE_RESET, closes connection, but keeps task alive
    /// Peer will auto-reconnect after idle hold timer
    HardReset,
    /// RFC 4271 Event 1: ManualStart - admin starts the peer connection
    ManualStart,
    /// RFC 4271 Event 2: ManualStop - admin stops the peer connection
    ManualStop,
    /// RFC 4271 Event 3: AutomaticStart - system automatically starts (non-passive)
    AutomaticStart,
    /// RFC 4271 Event 4: ManualStart_with_PassiveTcpEstablishment
    ManualStartPassive,
    /// RFC 4271 Event 5: AutomaticStartPassive - system automatically starts (passive)
    AutomaticStartPassive,
    /// Incoming TCP connection accepted - peer should transition to OpenSent
    TcpConnectionAccepted {
        tcp_tx: OwnedWriteHalf,
        tcp_rx: OwnedReadHalf,
    },
}

/// Type of BGP session based on AS relationship
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    /// External BGP session (different AS)
    Ebgp,
    /// Internal BGP session (same AS)
    Ibgp,
}

/// Statistics for BGP messages
#[derive(Debug, Clone, Default)]
pub struct PeerStatistics {
    pub open_sent: u64,
    pub keepalive_sent: u64,
    pub update_sent: u64,
    pub notification_sent: u64,
    pub open_received: u64,
    pub keepalive_received: u64,
    pub update_received: u64,
    pub notification_received: u64,
    pub route_refresh_received: u64,
    pub route_refresh_sent: u64,
    pub adj_rib_in_count: u64,
}

/// TCP connection state - only present when connected
/// Spawns a dedicated read task to avoid tokio::select! cancellation issues
struct TcpConnection {
    tx: OwnedWriteHalf,
    msg_rx: mpsc::Receiver<Result<Vec<u8>, ParserError>>,
    read_task: JoinHandle<()>,
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        // Abort read task when connection is dropped
        self.read_task.abort();
    }
}

impl TcpConnection {
    /// Creates a new TcpConnection and spawns a dedicated read task
    ///
    /// The read task runs `read_bgp_message_bytes` in a loop, sending raw bytes to a channel.
    /// This ensures the read operation cannot be cancelled mid-execution by tokio::select!,
    /// preventing TCP stream desynchronization.
    /// The Peer task will parse these bytes using negotiated capabilities.
    fn new(tx: OwnedWriteHalf, mut rx: OwnedReadHalf) -> Self {
        use crate::bgp::msg::read_bgp_message_bytes;

        let (msg_tx, msg_rx) = mpsc::channel(16);

        let read_task = tokio::spawn(async move {
            loop {
                match read_bgp_message_bytes(&mut rx).await {
                    Ok(bytes) => {
                        if msg_tx.send(Ok(bytes)).await.is_err() {
                            // Receiver dropped, exit cleanly
                            break;
                        }
                    }
                    Err(e) => {
                        // Send error and exit - connection will be torn down
                        let _ = msg_tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        });

        TcpConnection {
            tx,
            msg_rx,
            read_task,
        }
    }
}

pub struct Peer {
    pub addr: IpAddr,
    pub port: u16,
    pub fsm: Fsm,
    pub asn: Option<u32>,
    pub rib_in: AdjRibIn,
    pub session_type: Option<SessionType>,
    pub statistics: PeerStatistics,
    pub config: PeerConfig,
    /// TCP connection - None when disconnected (Idle/Connect/Active states)
    conn: Option<TcpConnection>,
    /// Temporary second connection during collision detection (RFC 4271 6.8)
    collision_conn: Option<TcpConnection>,
    peer_rx: mpsc::UnboundedReceiver<PeerOp>,
    server_tx: mpsc::UnboundedSender<ServerOp>,
    /// Local address for binding outbound connections
    local_addr: SocketAddr,
    /// ConnectRetryTime from global config (RFC 4271 8.1.2)
    connect_retry_secs: u64,
    /// Consecutive disconnect count for DampPeerOscillations backoff (RFC 4271 8.1.1)
    consecutive_down_count: u32,
    /// Connection type for collision detection
    conn_type: ConnectionType,
    logger: Arc<Logger>,
    /// True if ManualStop was received - disables auto-reconnect until ManualStart
    manually_stopped: bool,
    /// Timestamp when Established state was entered (for stability-based damping reset)
    established_at: Option<Instant>,
    /// RFC 4271 9.2.1.1: Last time we sent an UPDATE
    last_update_sent: Option<Instant>,
    /// Queued serialized UPDATE messages waiting for MRAI timer
    pending_updates: Vec<Vec<u8>>,
    /// MinRouteAdvertisementIntervalTimer from config
    mrai_interval: Duration,
    /// OPEN message sent to peer (for BMP PeerUp)
    sent_open: Option<OpenMessage>,
    /// OPEN message received from peer (for BMP PeerUp)
    received_open: Option<OpenMessage>,
    /// Negotiated capabilities with peer
    negotiated_capabilities: PeerCapabilities,
    /// AFI/SAFI pairs disabled due to errors (RFC 4760 Section 7)
    disabled_afi_safi: HashSet<crate::bgp::multiprotocol::AfiSafi>,
}

impl Peer {
    /// Create a new Peer in Idle state (RFC 4271 8.2.2).
    /// Peer starts without TCP connection - use ManualStart to initiate connection.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        addr: IpAddr,
        port: u16,
        peer_rx: mpsc::UnboundedReceiver<PeerOp>,
        server_tx: mpsc::UnboundedSender<ServerOp>,
        local_asn: u32,
        local_hold_time: u16,
        local_bgp_id: u32,
        local_addr: SocketAddr,
        config: PeerConfig,
        connect_retry_secs: u64,
        logger: Arc<Logger>,
    ) -> Self {
        let local_ip = local_addr.ip();
        Peer {
            addr,
            port,
            fsm: Fsm::new(
                local_asn,
                local_hold_time,
                local_bgp_id,
                local_ip,
                config.delay_open_time(),
                config.passive_mode,
            ),
            conn: None,
            collision_conn: None,
            asn: None,
            rib_in: AdjRibIn::new(),
            session_type: None,
            statistics: PeerStatistics::default(),
            mrai_interval: Duration::from_secs(
                config.min_route_advertisement_interval_secs.unwrap_or(0),
            ),
            last_update_sent: None,
            pending_updates: Vec::new(),
            config,
            peer_rx,
            server_tx,
            local_addr,
            connect_retry_secs,
            consecutive_down_count: 0,
            conn_type: ConnectionType::Outgoing,
            manually_stopped: false,
            established_at: None,
            sent_open: None,
            received_open: None,
            negotiated_capabilities: PeerCapabilities::default(),
            disabled_afi_safi: HashSet::new(),
            logger,
        }
    }

    /// Main peer task - handles the full lifecycle of a BGP peer.
    /// Runs forever, handling all FSM states including Idle, Connect, Active.
    pub async fn run(mut self) {
        let peer_ip = self.addr;
        debug!(&self.logger, "starting peer task", "peer_ip" => peer_ip.to_string());

        loop {
            match self.fsm.state() {
                BgpState::Idle => {
                    if self.handle_idle_state().await {
                        return; // Shutdown requested
                    }
                }
                BgpState::Connect => {
                    self.handle_connect_state().await;
                }
                BgpState::Active => {
                    self.handle_active_state().await;
                }
                BgpState::OpenSent | BgpState::OpenConfirm => {
                    if self.handle_open_states().await {
                        return; // Shutdown requested
                    }
                }
                BgpState::Established => {
                    if self.handle_established().await {
                        return; // Shutdown requested
                    }
                }
            }
        }
    }

    /// Disconnect TCP and transition FSM.
    fn disconnect(&mut self, apply_damping: bool, reason: PeerDownReason) {
        let had_connection = self.conn.is_some();
        self.conn = None;
        self.collision_conn = None;
        self.established_at = None;
        self.fsm.timers.stop_hold_timer();
        self.fsm.timers.stop_keepalive_timer();
        self.fsm.timers.stop_delay_open_timer();
        if had_connection {
            if apply_damping {
                self.consecutive_down_count += 1;
            }
            let _ = self.server_tx.send(ServerOp::PeerDisconnected {
                peer_ip: self.addr,
                reason,
            });
        }
    }

    /// Resolve connection collision per RFC 4271 Section 6.8.
    /// Called after OPEN is received on main connection.
    /// Compares BGP IDs and keeps the connection from the speaker with higher BGP ID.
    /// Returns true if connection was switched (caller should not process current OPEN).
    fn resolve_collision(&mut self, local_bgp_id: u32, remote_bgp_id: u32) -> bool {
        if self.collision_conn.is_none() {
            return false; // No collision
        }

        info!(&self.logger, "collision: resolving", "peer_ip" => self.addr.to_string(),
              "local_bgp_id" => format!("{}", std::net::Ipv4Addr::from(local_bgp_id)),
              "remote_bgp_id" => format!("{}", std::net::Ipv4Addr::from(remote_bgp_id)));

        // RFC 4271 6.8: Compare BGP IDs, keep connection from higher BGP ID speaker
        // conn_type tells us which connection initiated which way
        let keep_collision = if self.conn_type == ConnectionType::Outgoing {
            // conn is outgoing, collision_conn is incoming
            // Keep incoming (collision_conn) if local < remote
            local_bgp_id < remote_bgp_id
        } else {
            // conn is incoming, collision_conn would be outgoing (shouldn't happen in practice)
            // Keep outgoing (collision_conn) if local >= remote
            local_bgp_id >= remote_bgp_id
        };

        if keep_collision {
            // Switch to collision_conn
            info!(&self.logger, "collision: switching to collision connection", "peer_ip" => self.addr.to_string());
            self.conn = self.collision_conn.take();
            self.conn_type = if self.conn_type == ConnectionType::Outgoing {
                ConnectionType::Incoming
            } else {
                ConnectionType::Outgoing
            };
            true // Switched - caller should send OPEN on new connection
        } else {
            // Keep current conn, drop collision
            info!(&self.logger, "collision: keeping current connection", "peer_ip" => self.addr.to_string());
            self.collision_conn = None;
            false // Didn't switch - caller should continue processing
        }
    }

    /// Compute idle hold time with DampPeerOscillations backoff (RFC 4271 8.1.1).
    /// Returns None if automatic restart is disabled.
    fn get_idle_hold_time(&self) -> Option<Duration> {
        let cfg = &self.config;
        let base = Duration::from_secs(cfg.idle_hold_time_secs?);
        if !cfg.damp_peer_oscillations || self.consecutive_down_count == 0 {
            Some(base)
        } else {
            let exp = self.consecutive_down_count.min(6);
            let backoff = base * 2u32.pow(exp);
            Some(backoff.min(MAX_IDLE_HOLD_TIME))
        }
    }

    /// Notify server of state change.
    fn notify_state_change(&self) {
        let _ = self.server_tx.send(ServerOp::PeerStateChanged {
            peer_ip: self.addr,
            state: self.fsm.state(),
        });
    }

    /// Get current BGP state
    pub fn state(&self) -> BgpState {
        self.fsm.state()
    }

    /// Check if NOTIFICATION can be sent (RFC 4271 8.2.1.5).
    fn can_send_notification(&self) -> bool {
        self.conn.is_some()
            && (self.config.send_notification_without_open || self.statistics.open_sent > 0)
    }

    /// Parse BGP message from raw bytes received from TCP connection.
    ///
    /// RFC 4271 Section 4.1: BGP header is 19 bytes, message type at byte 18.
    ///
    /// # Arguments
    /// * `bytes` - Complete BGP message including header
    /// * `use_4byte_asn` - Whether to use 4-byte ASN encoding
    ///
    /// # Note on use_4byte_asn during OPEN exchange
    /// During OPEN message exchange, `use_4byte_asn` MUST be `false` because:
    /// - RFC 6793: OPEN messages always use 2-byte ASN encoding
    /// - If peer ASN > 65535, OPEN uses AS_TRANS (23456) and real ASN goes in capability
    /// - Only after OPEN negotiation can we determine if peer supports 4-byte ASNs
    /// - After negotiation, set `use_4byte_asn = negotiated_capabilities.supports_four_octet_asn()`
    fn parse_bgp_message(bytes: &[u8], use_4byte_asn: bool) -> Result<BgpMessage, ParserError> {
        let message_type = bytes[18];
        let body = bytes[19..].to_vec();
        BgpMessage::from_bytes(message_type, body, use_4byte_asn)
    }

    /// Convert BGP parse error to FSM event for error handling.
    ///
    /// RFC 4271 Events 21, 22: Different error types trigger different FSM events.
    fn parse_error_to_fsm_event(error: &ParserError) -> FsmEvent {
        if let Some(notif) = NotificationMessage::from_parser_error(error) {
            match notif.error() {
                BgpError::MessageHeaderError(_) => FsmEvent::BgpHeaderErr(notif),
                BgpError::OpenMessageError(_) => FsmEvent::BgpOpenMsgErr(notif),
                _ => FsmEvent::TcpConnectionFails,
            }
        } else {
            FsmEvent::TcpConnectionFails
        }
    }

    /// Handle received message during DelayOpen timer wait.
    ///
    /// Common logic for both Active and Connect states while waiting for DelayOpenTimer.
    /// Handles OPEN, NOTIFICATION, parse errors, and connection failures.
    ///
    /// RFC 4271 Section 8: DelayOpen optional session attribute allows delaying
    /// OPEN message to reduce resource consumption from connection collisions.
    async fn handle_delay_open_message(&mut self, result: Option<Result<Vec<u8>, ParserError>>) {
        match result {
            Some(Ok(bytes)) => {
                // RFC 6793: OPEN messages always use 2-byte ASN encoding
                match Self::parse_bgp_message(&bytes, false) {
                    Ok(BgpMessage::Open(open)) => {
                        debug!(&self.logger, "OPEN received while DelayOpen running", "peer_ip" => self.addr.to_string());
                        self.fsm.timers.stop_delay_open_timer();
                        let event = FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
                            peer_asn: open.asn,
                            peer_hold_time: open.hold_time,
                            local_asn: self.fsm.local_asn(),
                            local_hold_time: self.fsm.local_hold_time(),
                            peer_capabilities: PeerCapabilities::default(),
                            peer_bgp_id: open.bgp_identifier,
                        });
                        if let Err(e) = self.process_event(&event).await {
                            error!(&self.logger, "failed to send response to OPEN", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                            self.disconnect(true, PeerDownReason::LocalNoNotification(event));
                        }
                    }
                    Ok(BgpMessage::Notification(notif)) => {
                        self.handle_notification_received(&notif).await;
                    }
                    Ok(_) => {
                        error!(&self.logger, "unexpected message while waiting for DelayOpen", "peer_ip" => self.addr.to_string());
                        self.disconnect(true, PeerDownReason::RemoteNoNotification);
                    }
                    Err(e) => {
                        debug!(&self.logger, "parse error while waiting for DelayOpen", "peer_ip" => self.addr.to_string(), "error" => format!("{:?}", e));
                        let event = Self::parse_error_to_fsm_event(&e);
                        self.try_process_event(&event).await;
                    }
                }
            }
            Some(Err(e)) => {
                // Header validation error from read task
                debug!(&self.logger, "connection error while waiting for DelayOpen", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                let event = Self::parse_error_to_fsm_event(&e);
                self.try_process_event(&event).await;
            }
            None => {
                // Read task exited without error - connection failure
                debug!(&self.logger, "read task exited unexpectedly", "peer_ip" => self.addr.to_string());
                self.try_process_event(&FsmEvent::TcpConnectionFails).await;
            }
        }
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use crate::net::ipv4;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    pub async fn create_test_peer_with_state(state: BgpState) -> Peer {
        // Create a test TCP connection
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn task to accept connection and drain data
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (mut rx, _tx) = stream.into_split();
                let mut buf = vec![0u8; 4096];
                while rx.read(&mut buf).await.is_ok() {}
            }
        });

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (tcp_rx, tcp_tx) = client.into_split();

        // Create dummy channels for testing
        let (server_tx, _server_rx) = mpsc::unbounded_channel();
        let (_peer_tx, peer_rx) = mpsc::unbounded_channel();

        // Create peer directly for testing
        let local_ip = ipv4(127, 0, 0, 1);
        Peer {
            addr: addr.ip(),
            port: addr.port(),
            fsm: Fsm::with_state(state, 65000, 180, 0x01010101, local_ip, false),
            conn: Some(TcpConnection::new(tcp_tx, tcp_rx)),
            collision_conn: None,
            asn: Some(65001),
            rib_in: AdjRibIn::new(),
            session_type: Some(SessionType::Ebgp),
            statistics: PeerStatistics::default(),
            config: PeerConfig::default(),
            peer_rx,
            server_tx,
            local_addr: SocketAddr::new(local_ip, 0),
            connect_retry_secs: 120,
            consecutive_down_count: 0,
            conn_type: ConnectionType::Outgoing,
            manually_stopped: false,
            established_at: None,
            mrai_interval: Duration::from_secs(0),
            last_update_sent: None,
            pending_updates: Vec::new(),
            sent_open: None,
            received_open: None,
            negotiated_capabilities: PeerCapabilities::default(),
            disabled_afi_safi: HashSet::new(),
            logger: Arc::new(Logger::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;

    #[tokio::test]
    async fn test_get_idle_hold_time() {
        // (idle_hold_secs, damping, down_count, expected_secs)
        let cases = [
            (Some(30), true, 0, Some(30)),   // No downs -> base
            (Some(30), true, 1, Some(60)),   // 1 down -> 30*2
            (Some(30), true, 2, Some(120)),  // 2 downs -> 30*4, capped at 120
            (Some(30), true, 3, Some(120)),  // 3 downs -> 30*8=240, capped at 120
            (Some(30), false, 5, Some(30)),  // Damping disabled -> base
            (Some(10), true, 1, Some(20)),   // 10*2
            (Some(10), true, 3, Some(80)),   // 10*8
            (Some(10), true, 6, Some(120)),  // 10*64=640, capped at 120
            (Some(10), true, 10, Some(120)), // exp capped at 6 -> 10*64=640, capped at 120
            (None, true, 0, None),           // Disabled -> None
            (None, true, 5, None),           // Disabled with damping -> still None
        ];
        for (idle, damp, count, expected) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Idle).await;
            peer.config.idle_hold_time_secs = idle;
            peer.config.damp_peer_oscillations = damp;
            peer.consecutive_down_count = count;
            assert_eq!(
                peer.get_idle_hold_time(),
                expected.map(Duration::from_secs),
                "idle={:?}, damp={}, count={}",
                idle,
                damp,
                count
            );
        }
    }
}
