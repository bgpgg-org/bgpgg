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
use crate::bgp::msg_update::UpdateMessage;
use crate::config::PeerConfig;
use crate::debug;
use crate::rib::rib_in::AdjRibIn;
use crate::server::{ConnectionType, ServerOp};
use std::fmt;
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};

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
    SendUpdate(UpdateMessage),
    GetStatistics(oneshot::Sender<PeerStatistics>),
    /// Graceful shutdown - sends CEASE NOTIFICATION with given subcode and closes connection
    Shutdown(CeaseSubcode),
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
}

/// TCP connection state - only present when connected
struct TcpConnection {
    tx: OwnedWriteHalf,
    rx: OwnedReadHalf,
}

pub struct Peer {
    pub addr: IpAddr,
    pub port: u16,
    pub fsm: Fsm,
    pub asn: Option<u16>,
    pub rib_in: AdjRibIn,
    pub session_type: Option<SessionType>,
    pub statistics: PeerStatistics,
    pub config: PeerConfig,
    /// TCP connection - None when disconnected (Idle/Connect/Active states)
    conn: Option<TcpConnection>,
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
    /// True if ManualStop was received - disables auto-reconnect until ManualStart
    manually_stopped: bool,
    /// Timestamp when Established state was entered (for stability-based damping reset)
    established_at: Option<Instant>,
    /// RFC 4271 9.2.1.1: Last time we sent an UPDATE
    last_update_sent: Option<Instant>,
    /// Queued UPDATE messages waiting for MRAI timer
    pending_updates: Vec<UpdateMessage>,
    /// MinRouteAdvertisementIntervalTimer from config
    mrai_interval: Duration,
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
        local_asn: u16,
        local_hold_time: u16,
        local_bgp_id: u32,
        local_addr: SocketAddr,
        config: PeerConfig,
        connect_retry_secs: u64,
    ) -> Self {
        let local_ip = match local_addr.ip() {
            IpAddr::V4(ip) => ip,
            _ => Ipv4Addr::UNSPECIFIED,
        };
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
        }
    }

    /// Main peer task - handles the full lifecycle of a BGP peer.
    /// Runs forever, handling all FSM states including Idle, Connect, Active.
    pub async fn run(mut self) {
        let peer_ip = self.addr;
        debug!("starting peer task", "peer_ip" => peer_ip.to_string());

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
    fn disconnect(&mut self, apply_damping: bool) {
        let had_connection = self.conn.is_some();
        self.conn = None;
        self.established_at = None;
        self.fsm.timers.stop_hold_timer();
        self.fsm.timers.stop_keepalive_timer();
        self.fsm.timers.stop_delay_open_timer();
        if had_connection {
            if apply_damping {
                self.consecutive_down_count += 1;
            }
            let _ = self
                .server_tx
                .send(ServerOp::PeerDisconnected { peer_ip: self.addr });
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
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
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
        let local_ip = Ipv4Addr::new(127, 0, 0, 1);
        Peer {
            addr: addr.ip(),
            port: addr.port(),
            fsm: Fsm::with_state(state, 65000, 180, 0x01010101, local_ip, false),
            conn: Some(TcpConnection {
                tx: tcp_tx,
                rx: tcp_rx,
            }),
            asn: Some(65001),
            rib_in: AdjRibIn::new(),
            session_type: Some(SessionType::Ebgp),
            statistics: PeerStatistics::default(),
            config: PeerConfig::default(),
            peer_rx,
            server_tx,
            local_addr: SocketAddr::new(local_ip.into(), 0),
            connect_retry_secs: 120,
            consecutive_down_count: 0,
            conn_type: ConnectionType::Outgoing,
            manually_stopped: false,
            established_at: None,
            mrai_interval: Duration::from_secs(0),
            last_update_sent: None,
            pending_updates: Vec::new(),
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
