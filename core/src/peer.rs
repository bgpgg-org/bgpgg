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

use crate::bgp::msg::{read_bgp_message, BgpMessage, Message};
use crate::bgp::msg_keepalive::KeepAliveMessage;
use crate::bgp::msg_notification::{
    BgpError, CeaseSubcode, NotifcationMessage, UpdateMessageError,
};
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::msg_update::UpdateMessage;
use crate::bgp::utils::IpNetwork;
use crate::config::{MaxPrefixAction, PeerConfig};
use crate::fsm::{BgpState, Fsm, FsmEvent};
use crate::net::create_and_bind_tcp_socket;
use crate::rib::rib_in::AdjRibIn;
use crate::rib::{Path, RouteSource};
use crate::server::{ConnectionType, ServerOp};
use crate::{debug, error, info, warn};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};

/// RFC 4271 8.1.1: Maximum IdleHoldTime for DampPeerOscillations backoff.
const MAX_IDLE_HOLD_TIME: Duration = Duration::from_secs(120);

/// RFC 4271 8.2.2: Initial HoldTimer value when entering OpenSent state (4 minutes suggested).
const INITIAL_HOLD_TIME: Duration = Duration::from_secs(240);

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
}

impl Peer {
    /// Create a new Peer in Idle state (RFC 4271 8.2.2).
    /// Peer starts without TCP connection - use ManualStart to initiate connection.
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
            std::net::IpAddr::V4(ip) => ip,
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
                config.get_delay_open_time(),
            ),
            conn: None,
            asn: None,
            rib_in: AdjRibIn::new(),
            session_type: None,
            statistics: PeerStatistics::default(),
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
                BgpState::OpenSent | BgpState::OpenConfirm | BgpState::Established => {
                    if self.handle_open_and_established().await {
                        return; // Shutdown requested
                    }
                }
            }
        }
    }

    /// Handle Idle state - wait for ManualStart or AutomaticStart.
    /// Returns true if shutdown requested.
    async fn handle_idle_state(&mut self) -> bool {
        if self.config.passive_mode {
            self.handle_idle_state_passive().await
        } else {
            self.handle_idle_state_active().await
        }
    }

    /// Passive mode: wait for start event or IdleHoldTimer to transition to Active.
    /// RFC 4271 8.1.2: Event 7 (AutomaticStart_with_DampPeerOscillations_and_PassiveTcpEstablishment)
    /// and Event 13 (IdleHoldTimer_Expires) apply to passive peers.
    async fn handle_idle_state_passive(&mut self) -> bool {
        let idle_hold_time = self.get_idle_hold_time();
        let auto_reconnect = idle_hold_time.is_some() && !self.manually_stopped;
        let idle_hold_time = idle_hold_time.unwrap_or(Duration::ZERO);

        tokio::select! {
            op = self.peer_rx.recv() => {
                match op {
                    Some(PeerOp::ManualStartPassive) => {
                        debug!("ManualStartPassive received", "peer_ip" => self.addr.to_string());
                        self.manually_stopped = false;
                        self.try_process_event(&FsmEvent::ManualStartPassive).await;
                    }
                    Some(PeerOp::AutomaticStartPassive) => {
                        debug!("AutomaticStartPassive received", "peer_ip" => self.addr.to_string());
                        self.try_process_event(&FsmEvent::AutomaticStartPassive).await;
                    }
                    Some(PeerOp::Shutdown(_)) => return true,
                    Some(PeerOp::GetStatistics(response)) => {
                        let _ = response.send(self.statistics.clone());
                    }
                    Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                        // RFC 4271 8.2.2: In Idle state, refuse incoming connections
                        debug!("connection refused in Idle state", "peer_ip" => self.addr.to_string());
                        drop(tcp_tx);
                        drop(tcp_rx);
                    }
                    Some(_) => {}
                    None => return true,
                }
            }
            _ = tokio::time::sleep(idle_hold_time), if auto_reconnect => {
                // RFC 4271 Event 13: IdleHoldTimer_Expires -> Active
                debug!("IdleHoldTimer expired, AutomaticStartPassive", "peer_ip" => self.addr.to_string());
                self.try_process_event(&FsmEvent::AutomaticStartPassive).await;
            }
        }
        false
    }

    /// Non-passive mode: wait for ManualStart, AutomaticStart, or auto-reconnect timer.
    async fn handle_idle_state_active(&mut self) -> bool {
        let idle_hold_time = self.get_idle_hold_time();
        let auto_reconnect = idle_hold_time.is_some() && !self.manually_stopped;
        let idle_hold_time = idle_hold_time.unwrap_or(Duration::ZERO);

        tokio::select! {
            op = self.peer_rx.recv() => {
                match op {
                    Some(PeerOp::ManualStart) => {
                        debug!("ManualStart received", "peer_ip" => self.addr.to_string());
                        self.manually_stopped = false;
                        self.try_process_event(&FsmEvent::ManualStart).await;
                    }
                    Some(PeerOp::AutomaticStart) => {
                        debug!("AutomaticStart received", "peer_ip" => self.addr.to_string());
                        self.try_process_event(&FsmEvent::AutomaticStart).await;
                    }
                    Some(PeerOp::Shutdown(_)) => return true,
                    Some(PeerOp::GetStatistics(response)) => {
                        let _ = response.send(self.statistics.clone());
                    }
                    Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                        // RFC 4271 8.2.2: In Idle state, refuse incoming connections
                        debug!("connection refused in Idle state", "peer_ip" => self.addr.to_string());
                        drop(tcp_tx);
                        drop(tcp_rx);
                    }
                    Some(_) => {}
                    None => return true,
                }
            }
            _ = tokio::time::sleep(idle_hold_time), if auto_reconnect => {
                debug!("IdleHoldTimer expired, AutomaticStart", "peer_ip" => self.addr.to_string());
                self.try_process_event(&FsmEvent::AutomaticStart).await;
            }
        }
        false
    }

    /// Handle Connect state - attempt TCP connection or wait for DelayOpen timer.
    async fn handle_connect_state(&mut self) {
        if self.fsm.timers.delay_open_timer_running() {
            self.handle_connect_delay_open_wait().await;
        } else if self.conn.is_some() {
            // Have connection, start DelayOpen or transition to OpenSent
            if self.config.delay_open_time_secs.is_some() {
                self.fsm.timers.start_delay_open_timer();
            } else if let Err(e) = self.process_event(&FsmEvent::TcpConnectionConfirmed).await {
                error!("failed to send OPEN", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                self.disconnect(true);
            }
        } else {
            // No connection - first check if incoming connection is already queued
            // This prevents race where both peers connect simultaneously
            if let Ok(op) = self.peer_rx.try_recv() {
                match op {
                    PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx } => {
                        self.accept_connection(tcp_tx, tcp_rx).await;
                        return;
                    }
                    PeerOp::ManualStop => {
                        self.try_process_event(&FsmEvent::ManualStop).await;
                        return;
                    }
                    _ => {}
                }
            }

            // No queued incoming, attempt outgoing TCP connection
            let peer_addr = SocketAddr::new(self.addr, self.port);

            tokio::select! {
                result = create_and_bind_tcp_socket(self.local_addr, peer_addr) => {
                    match result {
                        Ok(stream) => {
                            info!("TCP connection established", "peer_ip" => self.addr.to_string());
                            let (rx, tx) = stream.into_split();
                            self.conn = Some(TcpConnection { tx, rx });
                            self.fsm.timers.stop_connect_retry();

                            if self.config.delay_open_time_secs.is_some() {
                                self.fsm.timers.start_delay_open_timer();
                            } else if let Err(e) = self.process_event(&FsmEvent::TcpConnectionConfirmed).await {
                                error!("failed to send OPEN", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                                self.disconnect(true);
                            }
                        }
                        Err(e) => {
                            debug!("TCP connection failed", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                            self.try_process_event(&FsmEvent::TcpConnectionFails).await;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(self.connect_retry_secs)) => {
                    debug!("ConnectRetryTimer expired", "peer_ip" => self.addr.to_string());
                    self.try_process_event(&FsmEvent::ConnectRetryTimerExpires).await;
                }
                op = self.peer_rx.recv() => {
                    match op {
                        Some(PeerOp::ManualStop) => {
                            self.try_process_event(&FsmEvent::ManualStop).await;
                        }
                        Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                            self.accept_connection(tcp_tx, tcp_rx).await;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Accept an incoming TCP connection in Connect or Active state.
    async fn accept_connection(&mut self, tcp_tx: OwnedWriteHalf, tcp_rx: OwnedReadHalf) {
        debug!("TcpConnectionAccepted", "peer_ip" => self.addr.to_string());
        self.conn = Some(TcpConnection {
            tx: tcp_tx,
            rx: tcp_rx,
        });
        self.conn_type = ConnectionType::Incoming;
        self.fsm.timers.stop_connect_retry();
        if self.config.delay_open_time_secs.is_some() {
            self.fsm.timers.start_delay_open_timer();
        } else if let Err(e) = self.process_event(&FsmEvent::TcpConnectionConfirmed).await {
            error!("failed to send OPEN", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
            self.disconnect(true);
        }
    }

    /// Wait for DelayOpen timer in Connect state (RFC 4271 8.2.2).
    /// Monitors both ConnectRetryTimer and DelayOpenTimer.
    async fn handle_connect_delay_open_wait(&mut self) {
        let conn = self.conn.as_mut().expect("connection should exist");
        let mut timer_interval = tokio::time::interval(Duration::from_millis(100));

        tokio::select! {
            result = read_bgp_message(&mut conn.rx) => {
                match result {
                    Ok(BgpMessage::Open(open)) => {
                        debug!("OPEN received while DelayOpen running", "peer_ip" => self.addr.to_string());
                        self.fsm.timers.stop_delay_open_timer();
                        if let Err(e) = self.process_event(&FsmEvent::BgpOpenReceived {
                            peer_asn: open.asn,
                            peer_hold_time: open.hold_time,
                            local_asn: self.fsm.local_asn(),
                            local_hold_time: self.fsm.local_hold_time(),
                            peer_bgp_id: open.bgp_identifier,
                        }).await {
                            error!("failed to send response to OPEN", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                            self.disconnect(true);
                        }
                    }
                    Ok(BgpMessage::Notification(_)) => {
                        // RFC 4271 Event 24: NOTIFICATION received with DelayOpenTimer running
                        debug!("NOTIFICATION received while DelayOpen running", "peer_ip" => self.addr.to_string());
                        self.try_process_event(&FsmEvent::NotificationReceived).await;
                    }
                    Ok(_) => {
                        error!("unexpected message while waiting for DelayOpen", "peer_ip" => self.addr.to_string());
                        self.disconnect(true);
                    }
                    Err(e) => {
                        debug!("connection error while waiting for DelayOpen", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                        // RFC 4271 Events 21, 22: Determine error type and send appropriate event
                        let event = if let Some(notif) = NotifcationMessage::from_parser_error(&e) {
                            match notif.error() {
                                BgpError::MessageHeaderError(_) => FsmEvent::BgpHeaderErr(notif),
                                BgpError::OpenMessageError(_) => FsmEvent::BgpOpenMsgErr(notif),
                                _ => FsmEvent::TcpConnectionFails,
                            }
                        } else {
                            FsmEvent::TcpConnectionFails
                        };
                        self.try_process_event(&event).await;
                    }
                }
            }
            _ = timer_interval.tick() => {
                // RFC 4271 8.2.2: Check ConnectRetryTimer first (Event 9 in Connect state)
                if self.fsm.timers.connect_retry_expired() {
                    debug!("ConnectRetryTimer expired in Connect while DelayOpen running", "peer_ip" => self.addr.to_string());
                    self.try_process_event(&FsmEvent::ConnectRetryTimerExpires).await;
                } else if self.fsm.timers.delay_open_timer_expired() {
                    debug!("DelayOpen timer expired", "peer_ip" => self.addr.to_string());
                    if let Err(e) = self.process_event(&FsmEvent::DelayOpenTimerExpires).await {
                        error!("failed to send OPEN", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                        self.disconnect(true);
                    }
                }
            }
            op = self.peer_rx.recv() => {
                match op {
                    Some(PeerOp::ManualStop) => {
                        self.try_process_event(&FsmEvent::ManualStop).await;
                    }
                    Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                        debug!("closing duplicate incoming connection", "peer_ip" => self.addr.to_string());
                        drop(tcp_tx);
                        drop(tcp_rx);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Handle Active state - listen for incoming connections.
    async fn handle_active_state(&mut self) {
        if self.fsm.timers.delay_open_timer_running() {
            self.handle_active_delay_open_wait().await;
        } else {
            // Wait for incoming connection
            let retry_time = Duration::from_secs(self.connect_retry_secs);

            tokio::select! {
                _ = tokio::time::sleep(retry_time) => {
                    debug!("ConnectRetryTimer expired in Active", "peer_ip" => self.addr.to_string());
                    self.try_process_event(&FsmEvent::ConnectRetryTimerExpires).await;
                }
                op = self.peer_rx.recv() => {
                    match op {
                        Some(PeerOp::ManualStop) => {
                            self.try_process_event(&FsmEvent::ManualStop).await;
                        }
                        Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                            self.accept_connection(tcp_tx, tcp_rx).await;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Wait for DelayOpen timer in Active state (RFC 4271 8.2.2).
    /// Does not monitor ConnectRetryTimer.
    async fn handle_active_delay_open_wait(&mut self) {
        let conn = self.conn.as_mut().expect("connection should exist");
        let mut timer_interval = tokio::time::interval(Duration::from_millis(100));

        tokio::select! {
            result = read_bgp_message(&mut conn.rx) => {
                match result {
                    Ok(BgpMessage::Open(open)) => {
                        debug!("OPEN received while DelayOpen running", "peer_ip" => self.addr.to_string());
                        self.fsm.timers.stop_delay_open_timer();
                        if let Err(e) = self.process_event(&FsmEvent::BgpOpenReceived {
                            peer_asn: open.asn,
                            peer_hold_time: open.hold_time,
                            local_asn: self.fsm.local_asn(),
                            local_hold_time: self.fsm.local_hold_time(),
                            peer_bgp_id: open.bgp_identifier,
                        }).await {
                            error!("failed to send response to OPEN", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                            self.disconnect(true);
                        }
                    }
                    Ok(BgpMessage::Notification(_)) => {
                        // RFC 4271 Event 24: NOTIFICATION received with DelayOpenTimer running
                        debug!("NOTIFICATION received while DelayOpen running", "peer_ip" => self.addr.to_string());
                        self.try_process_event(&FsmEvent::NotificationReceived).await;
                    }
                    Ok(_) => {
                        error!("unexpected message while waiting for DelayOpen", "peer_ip" => self.addr.to_string());
                        self.disconnect(true);
                    }
                    Err(e) => {
                        debug!("connection error while waiting for DelayOpen", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                        // RFC 4271 Events 21, 22: Determine error type and send appropriate event
                        let event = if let Some(notif) = NotifcationMessage::from_parser_error(&e) {
                            match notif.error() {
                                BgpError::MessageHeaderError(_) => FsmEvent::BgpHeaderErr(notif),
                                BgpError::OpenMessageError(_) => FsmEvent::BgpOpenMsgErr(notif),
                                _ => FsmEvent::TcpConnectionFails,
                            }
                        } else {
                            FsmEvent::TcpConnectionFails
                        };
                        self.try_process_event(&event).await;
                    }
                }
            }
            _ = timer_interval.tick() => {
                if self.fsm.timers.delay_open_timer_expired() {
                    debug!("DelayOpen timer expired", "peer_ip" => self.addr.to_string());
                    if let Err(e) = self.process_event(&FsmEvent::DelayOpenTimerExpires).await {
                        error!("failed to send OPEN", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                        self.disconnect(true);
                    }
                }
            }
            op = self.peer_rx.recv() => {
                match op {
                    Some(PeerOp::ManualStop) => {
                        self.try_process_event(&FsmEvent::ManualStop).await;
                    }
                    Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                        debug!("closing duplicate incoming connection", "peer_ip" => self.addr.to_string());
                        drop(tcp_tx);
                        drop(tcp_rx);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Handle connected states (OpenSent, OpenConfirm, Established).
    /// Returns true if shutdown requested.
    async fn handle_open_and_established(&mut self) -> bool {
        let peer_ip = self.addr;

        // Timer interval for hold/keepalive checks
        let mut timer_interval = tokio::time::interval(Duration::from_millis(500));

        loop {
            let conn = match self.conn.as_mut() {
                Some(c) => c,
                None => {
                    // Connection lost, transition back to Idle
                    self.try_process_event(&FsmEvent::TcpConnectionFails).await;
                    return false;
                }
            };

            tokio::select! {
                result = read_bgp_message(&mut conn.rx) => {
                    match result {
                        Ok(message) => {
                            if let Err(e) = self.handle_received_message(message, peer_ip).await {
                                error!("error processing message", "peer_ip" => peer_ip.to_string(), "error" => e.to_string());
                                self.disconnect(true);
                                return false;
                            }
                        }
                        Err(e) => {
                            error!("error reading message", "peer_ip" => peer_ip.to_string(), "error" => format!("{:?}", e));
                            if let Some(notif) = NotifcationMessage::from_parser_error(&e) {
                                let _ = self.send_notification(notif).await;
                            }
                            self.disconnect(true);
                            return false;
                        }
                    }
                }

                Some(msg) = self.peer_rx.recv() => {
                    match msg {
                        PeerOp::SendUpdate(update_msg) => {
                            if let Err(e) = self.send_update(update_msg).await {
                                error!("failed to send UPDATE", "peer_ip" => peer_ip.to_string(), "error" => e.to_string());
                                self.disconnect(true);
                                return false;
                            }
                        }
                        PeerOp::GetStatistics(response) => {
                            let _ = response.send(self.statistics.clone());
                        }
                        PeerOp::Shutdown(subcode) => {
                            // Server-initiated: kill task
                            info!("shutdown requested", "peer_ip" => peer_ip.to_string());
                            let notif = NotifcationMessage::new(BgpError::Cease(subcode), Vec::new());
                            let _ = self.send_notification(notif).await;
                            return true;
                        }
                        PeerOp::ManualStop => {
                            info!("ManualStop received", "peer_ip" => peer_ip.to_string());
                            self.try_process_event(&FsmEvent::ManualStop).await;
                            return false;
                        }
                        PeerOp::ManualStart
                        | PeerOp::ManualStartPassive
                        | PeerOp::AutomaticStart
                        | PeerOp::AutomaticStartPassive
                        | PeerOp::TcpConnectionAccepted { .. } => {
                            // Ignored when connected
                        }
                    }
                }

                _ = timer_interval.tick() => {
                    // Hold timer check
                    if self.fsm.timers.hold_timer_expired() {
                        error!("hold timer expired", "peer_ip" => peer_ip.to_string());
                        let notif = NotifcationMessage::new(BgpError::HoldTimerExpired, vec![]);
                        let _ = self.send_notification(notif).await;
                        self.fsm.handle_event(&FsmEvent::HoldTimerExpires);
                        self.disconnect(true);
                        return false;
                    }

                    // Keepalive timer check
                    if self.fsm.timers.keepalive_timer_expired() {
                        if let Err(e) = self.process_event(&FsmEvent::KeepaliveTimerExpires).await {
                            error!("failed to send keepalive", "peer_ip" => peer_ip.to_string(), "error" => e.to_string());
                            self.disconnect(true);
                            return false;
                        }
                    }
                }
            }

            // Check if we transitioned out of connected states
            match self.fsm.state() {
                BgpState::OpenSent | BgpState::OpenConfirm | BgpState::Established => {}
                _ => return false,
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
            return Some(base);
        }
        let exp = self.consecutive_down_count.min(6);
        let backoff = base * 2u32.pow(exp);
        Some(backoff.min(MAX_IDLE_HOLD_TIME))
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

    /// Process FSM event, transition state, and execute associated actions.
    async fn process_event(&mut self, event: &FsmEvent) -> Result<(), io::Error> {
        let old_state = self.fsm.state();
        let (new_state, fsm_error) = self.fsm.handle_event(event);

        // Handle state-specific actions based on transitions
        match (old_state, new_state, event) {
            // RFC 4271 8.2.2: Initialize resources and start ConnectRetryTimer when leaving Idle
            (BgpState::Idle, BgpState::Connect, _) | (BgpState::Idle, BgpState::Active, _) => {
                self.fsm.reset_connect_retry_counter();
                self.fsm.timers.start_connect_retry();
            }

            // RFC 4271 8.2.2: ConnectRetryTimer expires in Connect state
            (BgpState::Connect, BgpState::Connect, FsmEvent::ConnectRetryTimerExpires) => {
                self.disconnect(true);
                self.fsm.timers.stop_delay_open_timer();
                self.fsm.timers.start_connect_retry();
            }

            // RFC 4271 8.2.2 Event 18: TcpConnectionFails with DelayOpenTimer running -> Active
            (BgpState::Connect, BgpState::Active, FsmEvent::TcpConnectionFails) => {
                self.disconnect(true);
                self.fsm.timers.stop_delay_open_timer();
                self.fsm.timers.start_connect_retry();
            }

            // RFC 4271 8.2.2 Event 18: TcpConnectionFails without DelayOpenTimer -> Idle
            (BgpState::Connect, BgpState::Idle, FsmEvent::TcpConnectionFails) => {
                self.disconnect(true);
                self.fsm.timers.stop_connect_retry();
                self.fsm.reset_connect_retry_counter();
            }

            // RFC 4271 Events 21, 22: BGP header/OPEN message errors -> Idle
            (BgpState::Connect, BgpState::Idle, FsmEvent::BgpHeaderErr(ref notif))
            | (BgpState::Connect, BgpState::Idle, FsmEvent::BgpOpenMsgErr(ref notif))
            | (BgpState::Active, BgpState::Idle, FsmEvent::BgpHeaderErr(ref notif))
            | (BgpState::Active, BgpState::Idle, FsmEvent::BgpOpenMsgErr(ref notif)) => {
                // RFC 4271: (optionally) send NOTIFICATION if SendNOTIFICATIONwithoutOPEN is TRUE
                let _ = self.send_notification(notif.clone()).await;
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.disconnect(true);
                self.fsm.increment_connect_retry_counter();
            }

            // RFC 4271 Event 24: NOTIFICATION received -> Idle
            (BgpState::Connect, BgpState::Idle, FsmEvent::NotificationReceived)
            | (BgpState::Active, BgpState::Idle, FsmEvent::NotificationReceived) => {
                self.fsm.timers.stop_connect_retry();
                let delay_open_was_running = self.fsm.timers.delay_open_timer_running();
                self.fsm.timers.stop_delay_open_timer();
                // RFC 4271: apply damping and increment counter only if DelayOpenTimer was NOT running
                self.disconnect(!delay_open_was_running);
                if !delay_open_was_running {
                    self.fsm.increment_connect_retry_counter();
                }
            }

            // RFC 4271 8.2.2: ManualStop in Connect state
            (BgpState::Connect, BgpState::Idle, FsmEvent::ManualStop) => {
                self.disconnect(true);
                self.manually_stopped = true;
                self.fsm.reset_connect_retry_counter();
                self.fsm.timers.stop_connect_retry();
            }

            // RFC 4271 8.2.2: ManualStop in Active state
            (BgpState::Active, BgpState::Idle, FsmEvent::ManualStop) => {
                // Conditionally send NOTIFICATION if DelayOpenTimer is running
                if self.fsm.timers.delay_open_timer_running()
                    && self.config.send_notification_without_open
                {
                    let notif = NotifcationMessage::new(
                        BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
                        Vec::new(),
                    );
                    let _ = self.send_notification(notif).await;
                }
                self.disconnect(true);
                self.manually_stopped = true;
                self.fsm.reset_connect_retry_counter();
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
            }

            // RFC 4271 8.2.2: ManualStop in session states - send CEASE notification
            (BgpState::OpenSent, BgpState::Idle, FsmEvent::ManualStop)
            | (BgpState::OpenConfirm, BgpState::Idle, FsmEvent::ManualStop)
            | (BgpState::Established, BgpState::Idle, FsmEvent::ManualStop) => {
                self.manually_stopped = true;
                let notif = NotifcationMessage::new(
                    BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
                    Vec::new(),
                );
                let _ = self.send_notification(notif).await;
                self.disconnect(true);
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
            }

            // DelayOpenTimer expires -> send OPEN
            (BgpState::Connect, BgpState::OpenSent, FsmEvent::DelayOpenTimerExpires)
            | (BgpState::Active, BgpState::OpenSent, FsmEvent::DelayOpenTimerExpires) => {
                self.fsm.timers.stop_delay_open_timer();
                self.fsm.timers.set_initial_hold_time(INITIAL_HOLD_TIME);
                self.fsm.timers.start_hold_timer();
                self.send_open().await?;
            }

            // Entering OpenSent - send OPEN message
            (BgpState::Connect, BgpState::OpenSent, FsmEvent::TcpConnectionConfirmed)
            | (BgpState::Active, BgpState::OpenSent, FsmEvent::TcpConnectionConfirmed) => {
                self.fsm.timers.set_initial_hold_time(INITIAL_HOLD_TIME);
                self.fsm.timers.start_hold_timer();
                self.send_open().await?;
            }

            // Received OPEN while in Connect with DelayOpen - send OPEN + KEEPALIVE (RFC 4271 8.2.1.3)
            (
                BgpState::Connect,
                BgpState::OpenConfirm,
                &FsmEvent::BgpOpenReceived {
                    peer_asn,
                    peer_hold_time,
                    local_asn,
                    local_hold_time,
                    ..
                },
            ) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.send_open().await?;
                self.enter_open_confirm(peer_asn, peer_hold_time, local_asn, local_hold_time)
                    .await?;
            }

            // Entering OpenConfirm from OpenSent - send KEEPALIVE
            (
                BgpState::OpenSent,
                BgpState::OpenConfirm,
                &FsmEvent::BgpOpenReceived {
                    peer_asn,
                    peer_hold_time,
                    local_asn,
                    local_hold_time,
                    ..
                },
            ) => {
                self.enter_open_confirm(peer_asn, peer_hold_time, local_asn, local_hold_time)
                    .await?;
            }

            // In OpenConfirm or Established - handle keepalive timer expiry
            (_, BgpState::OpenConfirm, FsmEvent::KeepaliveTimerExpires)
            | (_, BgpState::Established, FsmEvent::KeepaliveTimerExpires) => {
                self.send_keepalive().await?;
            }

            // Received keepalive in OpenConfirm - entering Established
            (BgpState::OpenConfirm, BgpState::Established, FsmEvent::BgpKeepaliveReceived) => {
                self.fsm.timers.reset_hold_timer();
                self.established_at = Some(Instant::now());
            }

            // In Established - reset hold timer on keepalive/update
            (BgpState::Established, BgpState::Established, FsmEvent::BgpKeepaliveReceived)
            | (BgpState::Established, BgpState::Established, FsmEvent::BgpUpdateReceived) => {
                self.fsm.timers.reset_hold_timer();
                // Reset damping counter after connection stable for one hold period (RFC 4271 8.1.2)
                if let Some(established_at) = self.established_at {
                    let stability_threshold = self.fsm.timers.hold_time;
                    if established_at.elapsed() >= stability_threshold
                        && self.consecutive_down_count > 0
                    {
                        self.consecutive_down_count = 0;
                        debug!("reset damping counter after stable connection",
                            "peer_ip" => self.addr.to_string());
                    }
                }
            }

            // AutomaticStop: set admin state based on reason
            (_, BgpState::Idle, FsmEvent::AutomaticStop(subcode)) => {
                let admin_state = match subcode {
                    CeaseSubcode::MaxPrefixesReached => {
                        crate::server::AdminState::PrefixLimitReached
                    }
                    _ => crate::server::AdminState::Down,
                };
                let _ = self.server_tx.send(ServerOp::SetAdminState {
                    peer_ip: self.addr,
                    state: admin_state,
                });
            }

            _ => {}
        }

        // Notify server of state change after all actions complete
        if old_state != new_state {
            self.notify_state_change();
        }

        // Send NOTIFICATION and return error if FSM returned an error
        if let Some(error) = fsm_error {
            let notif = NotifcationMessage::new(error, vec![]);
            let _ = self.send_notification(notif).await;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "FSM error"));
        }

        Ok(())
    }

    /// Process FSM event and log any errors.
    async fn try_process_event(&mut self, event: &FsmEvent) {
        if let Err(e) = self.process_event(event).await {
            error!("failed to process event",
                "peer_ip" => self.addr.to_string(),
                "event" => format!("{:?}", event),
                "error" => e.to_string());
        }
    }

    /// Send OPEN message to peer.
    async fn send_open(&mut self) -> Result<(), io::Error> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no TCP connection"))?;
        let open_msg = OpenMessage::new(
            self.fsm.local_asn(),
            self.fsm.local_hold_time(),
            self.fsm.local_bgp_id(),
        );
        conn.tx.write_all(&open_msg.serialize()).await?;
        self.statistics.open_sent += 1;
        info!("sent OPEN message", "peer_ip" => self.addr.to_string());
        Ok(())
    }

    /// Handle entering OpenConfirm state - negotiate timers, send KEEPALIVE, notify server
    async fn enter_open_confirm(
        &mut self,
        peer_asn: u16,
        peer_hold_time: u16,
        local_asn: u16,
        local_hold_time: u16,
    ) -> Result<(), io::Error> {
        // Set peer ASN and determine session type
        self.asn = Some(peer_asn);
        self.session_type = Some(if peer_asn == local_asn {
            SessionType::Ibgp
        } else {
            SessionType::Ebgp
        });

        // Negotiate hold time: use minimum (RFC 4271).
        let hold_time = local_hold_time.min(peer_hold_time);
        self.fsm.timers.set_negotiated_hold_time(hold_time);

        // Send KEEPALIVE message
        self.send_keepalive().await?;

        // RFC 4271 8.2.2: If negotiated hold time is non-zero, start timers.
        // If zero, timers are not started (connection stays up without heartbeats).
        if hold_time != 0 {
            self.fsm.timers.reset_hold_timer();
        } else {
            // Hold time is zero - ensure timers are stopped
            self.fsm.timers.stop_keepalive_timer();
            self.fsm.timers.stop_hold_timer();
        }

        info!("timers initialized", "peer_ip" => self.addr.to_string(), "hold_time" => hold_time);

        // Notify server that handshake is complete
        let _ = self.server_tx.send(ServerOp::PeerHandshakeComplete {
            peer_ip: self.addr,
            asn: peer_asn,
        });

        Ok(())
    }

    /// Send KEEPALIVE message and restart keepalive timer
    async fn send_keepalive(&mut self) -> Result<(), io::Error> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no TCP connection"))?;
        let keepalive_msg = KeepAliveMessage {};
        conn.tx.write_all(&keepalive_msg.serialize()).await?;
        self.statistics.keepalive_sent += 1;
        debug!("sent KEEPALIVE message", "peer_ip" => self.addr.to_string());
        self.fsm.timers.start_keepalive_timer();
        Ok(())
    }

    /// Send NOTIFICATION message (RFC 4271 Section 6.1)
    ///
    /// RFC 4271 8.2.1.5: SendNOTIFICATIONwithoutOPEN controls whether NOTIFICATION
    /// can be sent before OPEN. If disabled (default), NOTIFICATION is only sent
    /// after OPEN has been sent.
    async fn send_notification(&mut self, notif_msg: NotifcationMessage) -> Result<(), io::Error> {
        if !self.can_send_notification() {
            warn!("skipping NOTIFICATION", "peer_ip" => self.addr.to_string(), "error" => format!("{:?}", notif_msg.error()));
            return Ok(());
        }
        // Safe: can_send_notification checks conn.is_some()
        let conn = self.conn.as_mut().unwrap();
        conn.tx.write_all(&notif_msg.serialize()).await?;
        self.statistics.notification_sent += 1;
        warn!("sent NOTIFICATION", "peer_ip" => self.addr.to_string(), "error" => format!("{:?}", notif_msg.error()));
        Ok(())
    }

    /// Process a received BGP message from the TCP stream
    /// Returns Err if should disconnect (notification or processing error)
    async fn handle_received_message(
        &mut self,
        message: BgpMessage,
        peer_ip: IpAddr,
    ) -> Result<(), io::Error> {
        match &message {
            BgpMessage::Notification(_) => {
                let _ = self.handle_message(message).await;
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "notification received",
                ))
            }
            BgpMessage::Update(_) => {
                let delta = self.handle_message(message).await?;
                self.fsm.timers.reset_hold_timer();

                if let Some((withdrawn, announced)) = delta {
                    let _ = self.server_tx.send(ServerOp::PeerUpdate {
                        peer_ip,
                        withdrawn,
                        announced,
                    });
                }
                Ok(())
            }
            BgpMessage::KeepAlive(_) => {
                let _ = self.handle_message(message).await;
                self.fsm.timers.reset_hold_timer();
                Ok(())
            }
            BgpMessage::Open(_) => {
                let _ = self.handle_message(message).await;
                Ok(())
            }
        }
    }

    /// Process a BGP message and return route changes for Loc-RIB update if applicable
    /// Returns (withdrawn_prefixes, announced_routes) or None if not an UPDATE
    async fn handle_message(
        &mut self,
        message: BgpMessage,
    ) -> Result<Option<(Vec<IpNetwork>, Vec<(IpNetwork, Path)>)>, io::Error> {
        self.track_received_message(&message);

        // Process FSM event
        match &message {
            BgpMessage::Open(open_msg) => {
                // RFC 4271 6.8: Notify server for collision detection
                let _ = self.server_tx.send(ServerOp::OpenReceived {
                    peer_ip: self.addr,
                    bgp_id: open_msg.bgp_identifier,
                    conn_type: self.conn_type,
                });
                self.process_event(&FsmEvent::BgpOpenReceived {
                    peer_asn: open_msg.asn,
                    peer_hold_time: open_msg.hold_time,
                    peer_bgp_id: open_msg.bgp_identifier,
                    local_asn: self.fsm.local_asn(),
                    local_hold_time: self.fsm.local_hold_time(),
                })
                .await?;
            }
            BgpMessage::Update(_) => {
                self.process_event(&FsmEvent::BgpUpdateReceived).await?;
            }
            BgpMessage::KeepAlive(_) => {
                self.process_event(&FsmEvent::BgpKeepaliveReceived).await?;
            }
            BgpMessage::Notification(_) => {
                self.process_event(&FsmEvent::NotificationReceived).await?;
            }
        }

        // Process UPDATE message content
        if let BgpMessage::Update(update_msg) = message {
            match self.handle_update(update_msg) {
                Ok(delta) => Ok(Some(delta)),
                Err(BgpError::Cease(CeaseSubcode::MaxPrefixesReached)) => {
                    // RFC 4271 8.1.2: check allow_automatic_stop
                    if self.config.allow_automatic_stop {
                        self.process_event(&FsmEvent::AutomaticStop(
                            CeaseSubcode::MaxPrefixesReached,
                        ))
                        .await
                        .map(|_| None)
                    } else {
                        warn!("max prefix exceeded but allow_automatic_stop=false, continuing",
                              "peer_ip" => self.addr.to_string());
                        Ok(None)
                    }
                }
                Err(bgp_error) => {
                    let notif = NotifcationMessage::new(bgp_error, vec![]);
                    let _ = self.send_notification(notif).await;
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "UPDATE message validation failed",
                    ))
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Handle a BGP UPDATE message
    /// Returns (withdrawn_prefixes, announced_routes) - only what changed in THIS update
    fn handle_update(
        &mut self,
        update_msg: UpdateMessage,
    ) -> Result<(Vec<IpNetwork>, Vec<(IpNetwork, Path)>), BgpError> {
        // RFC 4271 Section 6.3: For eBGP, check that leftmost AS in AS_PATH equals peer AS.
        // If mismatch, MUST set error subcode to MalformedASPath.
        if self.session_type == Some(SessionType::Ebgp) {
            if let Some(leftmost_as) = update_msg.get_leftmost_as() {
                if let Some(peer_asn) = self.asn {
                    if leftmost_as != peer_asn {
                        warn!("AS_PATH first AS does not match peer AS",
                              "peer_ip" => self.addr.to_string(), "leftmost_as" => leftmost_as, "peer_asn" => peer_asn);
                        return Err(BgpError::UpdateMessageError(
                            UpdateMessageError::MalformedASPath,
                        ));
                    }
                }
            }
        }

        let withdrawn = self.process_withdrawals(&update_msg);
        let announced = self.process_announcements(&update_msg)?;
        Ok((withdrawn, announced))
    }

    /// Process withdrawn routes from an UPDATE message
    fn process_withdrawals(&mut self, update_msg: &UpdateMessage) -> Vec<IpNetwork> {
        let mut withdrawn = Vec::new();
        for prefix in update_msg.withdrawn_routes() {
            info!("withdrawing route", "prefix" => format!("{:?}", prefix), "peer_ip" => self.addr.to_string());
            self.rib_in.remove_route(*prefix);
            withdrawn.push(*prefix);
        }
        withdrawn
    }

    /// Check if adding new prefixes would exceed max prefix limit.
    /// Returns Ok(true) to proceed, Ok(false) to discard, Err to terminate.
    fn check_max_prefix_limit(&self, incoming_prefix_count: usize) -> Result<bool, BgpError> {
        let Some(setting) = self.config.max_prefix else {
            return Ok(true);
        };
        let current = self.rib_in.prefix_count();
        if current + incoming_prefix_count <= setting.limit as usize {
            return Ok(true);
        }
        match setting.action {
            MaxPrefixAction::Terminate => {
                warn!("max prefix limit exceeded",
                      "peer_ip" => self.addr.to_string(), "limit" => setting.limit, "current" => current);
                Err(BgpError::Cease(CeaseSubcode::MaxPrefixesReached))
            }
            MaxPrefixAction::Discard => {
                warn!("max prefix limit reached, discarding new prefixes",
                      "peer_ip" => self.addr.to_string(), "limit" => setting.limit, "current" => current);
                Ok(false)
            }
        }
    }

    fn process_announcements(
        &mut self,
        update_msg: &UpdateMessage,
    ) -> Result<Vec<(IpNetwork, Path)>, BgpError> {
        if !self.check_max_prefix_limit(update_msg.nlri_list().len())? {
            return Ok(Vec::new());
        }

        let mut announced = Vec::new();

        let source = RouteSource::from_session(
            self.session_type
                .expect("session_type must be set in Established state"),
            self.addr,
        );

        let Some(path) = Path::from_update_msg(update_msg, source) else {
            if !update_msg.nlri_list().is_empty() {
                warn!("UPDATE has NLRI but missing required attributes, skipping announcements", "peer_ip" => self.addr.to_string());
            }
            return Ok(announced);
        };

        // RFC 4271 5.1.3(a): NEXT_HOP must not be receiving speaker's IP
        if path.next_hop == self.fsm.local_addr() {
            warn!("rejecting UPDATE: NEXT_HOP is local address",
                  "next_hop" => path.next_hop.to_string(), "peer" => &self.addr);
            return Ok(announced);
        }

        for prefix in update_msg.nlri_list() {
            info!("adding route to Adj-RIB-In", "prefix" => format!("{:?}", prefix), "peer_ip" => self.addr.to_string(), "med" => format!("{:?}", path.med));
            self.rib_in.add_route(*prefix, path.clone());
            announced.push((*prefix, path.clone()));
        }

        Ok(announced)
    }

    fn track_received_message(&mut self, message: &BgpMessage) {
        match message {
            BgpMessage::Open(open_msg) => {
                self.statistics.open_received += 1;
                info!("received OPEN from peer", "peer_ip" => self.addr.to_string(), "asn" => open_msg.asn, "hold_time" => open_msg.hold_time);
            }
            BgpMessage::Update(_) => {
                self.statistics.update_received += 1;
                info!("received UPDATE", "peer_ip" => self.addr.to_string());
            }
            BgpMessage::KeepAlive(_) => {
                self.statistics.keepalive_received += 1;
                debug!("received KEEPALIVE", "peer_ip" => self.addr.to_string());
            }
            BgpMessage::Notification(notif_msg) => {
                self.statistics.notification_received += 1;
                warn!("received NOTIFICATION", "peer_ip" => self.addr.to_string(), "notification" => format!("{:?}", notif_msg));
            }
        }
    }

    /// Send UPDATE message and reset keepalive timer (RFC 4271 requirement)
    async fn send_update(&mut self, update_msg: UpdateMessage) -> Result<(), io::Error> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no TCP connection"))?;
        conn.tx.write_all(&update_msg.serialize()).await?;
        self.statistics.update_sent += 1;
        // RFC 4271: "Each time the local system sends a KEEPALIVE or UPDATE message,
        // it restarts its KeepaliveTimer"
        self.fsm.timers.reset_keepalive_timer();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg::Message;
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin, UpdateMessage};
    use crate::config::MaxPrefixSetting;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    async fn create_test_peer_with_state(state: BgpState) -> Peer {
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
            fsm: Fsm::with_state(state, 65000, 180, 0x01010101, local_ip),
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
        }
    }

    #[tokio::test]
    async fn test_state() {
        let peer = create_test_peer_with_state(BgpState::Idle).await;
        assert_eq!(peer.state(), BgpState::Idle);

        let peer = create_test_peer_with_state(BgpState::Connect).await;
        assert_eq!(peer.state(), BgpState::Connect);

        let peer = create_test_peer_with_state(BgpState::Established).await;
        assert_eq!(peer.state(), BgpState::Established);
    }

    #[tokio::test]
    async fn test_bgp_message_errors_in_connect_active() {
        use crate::bgp::msg_notification::{MessageHeaderError, OpenMessageError};

        // (state, event, send_notif_config, expected_notif_count)
        let cases = vec![
            (
                BgpState::Connect,
                BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
                false,
                0,
            ),
            (
                BgpState::Connect,
                BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber),
                true,
                1,
            ),
            (
                BgpState::Active,
                BgpError::MessageHeaderError(MessageHeaderError::BadMessageType),
                false,
                0,
            ),
            (
                BgpState::Active,
                BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber),
                true,
                1,
            ),
        ];

        for (state, error, send_notif, expected_notif) in cases {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.timers.start_connect_retry();
            peer.config.send_notification_without_open = send_notif;
            peer.config.damp_peer_oscillations = true;
            let initial_down_count = peer.consecutive_down_count;
            let notif = NotifcationMessage::new(error.clone(), vec![]);
            let event = match error {
                BgpError::MessageHeaderError(_) => FsmEvent::BgpHeaderErr(notif),
                BgpError::OpenMessageError(_) => FsmEvent::BgpOpenMsgErr(notif),
                _ => panic!("unexpected error type"),
            };

            peer.process_event(&event).await.unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.conn.is_none(), "TCP connection should be dropped");
            assert!(peer.fsm.timers.connect_retry_started.is_none());
            assert_eq!(peer.fsm.connect_retry_counter, 1);
            assert_eq!(peer.statistics.notification_sent, expected_notif);
            assert_eq!(
                peer.consecutive_down_count,
                initial_down_count + 1,
                "DampPeerOscillations should increment consecutive_down_count"
            );
        }
    }

    #[tokio::test]
    async fn test_notification_received_in_connect_active() {
        // RFC 4271 Event 24: NOTIFICATION behavior depends on DelayOpenTimer state
        // (state, delay_open_running, expected_down_count, expected_counter)
        let cases = vec![
            (BgpState::Connect, true, 0, 0), // DelayOpenTimer running -> no damping
            (BgpState::Connect, false, 1, 1), // DelayOpenTimer not running -> apply damping
            (BgpState::Active, true, 0, 0),  // DelayOpenTimer running -> no damping
            (BgpState::Active, false, 1, 1), // DelayOpenTimer not running -> apply damping
        ];

        for (state, delay_open_running, expected_down_count, expected_counter) in cases {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.timers.start_connect_retry();
            if delay_open_running {
                peer.fsm.timers.start_delay_open_timer();
            }
            peer.config.damp_peer_oscillations = true;

            peer.process_event(&FsmEvent::NotificationReceived)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.conn.is_none());
            assert!(peer.fsm.timers.connect_retry_started.is_none());
            assert!(!peer.fsm.timers.delay_open_timer_running());
            assert_eq!(
                peer.consecutive_down_count, expected_down_count,
                "{:?}, delay_open={}: damping",
                state, delay_open_running
            );
            assert_eq!(
                peer.fsm.connect_retry_counter, expected_counter,
                "{:?}, delay_open={}: counter",
                state, delay_open_running
            );
        }
    }

    #[tokio::test]
    async fn test_handle_update_first_as_validation() {
        // (session_type, peer_asn, first_as_in_path, should_pass)
        let cases = vec![
            (SessionType::Ebgp, 65001, 65002, false), // eBGP mismatch -> fail
            (SessionType::Ebgp, 65001, 65001, true),  // eBGP match -> pass
            (SessionType::Ibgp, 65001, 65002, true),  // iBGP mismatch -> pass (no check)
        ];

        for (session_type, peer_asn, first_as, should_pass) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.session_type = Some(session_type);
            peer.asn = Some(peer_asn);

            let update = UpdateMessage::new(
                Origin::IGP,
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![first_as],
                }],
                Ipv4Addr::new(10, 0, 0, 1),
                vec![],
                None,
                None,
                false,
                vec![],
            );

            let result = peer.handle_update(update);
            assert_eq!(
                result.is_ok(),
                should_pass,
                "{:?} peer_asn={} first_as={}",
                session_type,
                peer_asn,
                first_as
            );
        }
    }

    #[tokio::test]
    async fn test_max_prefix() {
        // (max_prefix, initial, new, expected_ok, expected_rib, desc)
        let cases: Vec<(Option<MaxPrefixSetting>, usize, usize, bool, usize, &str)> = vec![
            // No limit: all prefixes accepted
            (None, 0, 10, true, 10, "no limit set"),
            // Under limit: accepted
            (
                Some(MaxPrefixSetting {
                    limit: 5,
                    action: MaxPrefixAction::Terminate,
                }),
                0,
                3,
                true,
                3,
                "under limit",
            ),
            // Exactly at limit: accepted
            (
                Some(MaxPrefixSetting {
                    limit: 5,
                    action: MaxPrefixAction::Terminate,
                }),
                0,
                5,
                true,
                5,
                "at limit",
            ),
            // Over limit with Terminate: error, no prefixes added
            (
                Some(MaxPrefixSetting {
                    limit: 5,
                    action: MaxPrefixAction::Terminate,
                }),
                0,
                6,
                false,
                0,
                "over limit terminate",
            ),
            // Over limit with Discard: ok, but no prefixes added
            (
                Some(MaxPrefixSetting {
                    limit: 5,
                    action: MaxPrefixAction::Discard,
                }),
                0,
                6,
                true,
                0,
                "over limit discard",
            ),
            // Have 4, add 2 would exceed 5: reject new, keep existing 4
            (
                Some(MaxPrefixSetting {
                    limit: 5,
                    action: MaxPrefixAction::Discard,
                }),
                4,
                2,
                true,
                4,
                "existing prefixes preserved on discard",
            ),
        ];

        for (setting, initial, new_prefixes, expected_ok, expected_rib, desc) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.config.max_prefix = setting;

            // Add initial prefixes (use different subnet to avoid overlap)
            if initial > 0 {
                let initial_nlri: Vec<_> = (0..initial)
                    .map(|i| {
                        crate::bgp::utils::IpNetwork::V4(crate::bgp::utils::Ipv4Net {
                            address: Ipv4Addr::new(192, 168, i as u8, 0),
                            prefix_length: 24,
                        })
                    })
                    .collect();
                let initial_update = UpdateMessage::new(
                    Origin::IGP,
                    vec![AsPathSegment {
                        segment_type: AsPathSegmentType::AsSequence,
                        segment_len: 1,
                        asn_list: vec![65001],
                    }],
                    Ipv4Addr::new(10, 0, 0, 1),
                    initial_nlri,
                    None,
                    None,
                    false,
                    vec![],
                );
                peer.handle_update(initial_update).unwrap();
            }

            let nlri: Vec<_> = (0..new_prefixes)
                .map(|i| {
                    crate::bgp::utils::IpNetwork::V4(crate::bgp::utils::Ipv4Net {
                        address: Ipv4Addr::new(10, 0, i as u8, 0),
                        prefix_length: 24,
                    })
                })
                .collect();

            let update = UpdateMessage::new(
                Origin::IGP,
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                Ipv4Addr::new(10, 0, 0, 1),
                nlri,
                None,
                None,
                false,
                vec![],
            );

            let result = peer.handle_update(update);
            assert_eq!(result.is_ok(), expected_ok, "{}", desc);
            assert_eq!(peer.rib_in.prefix_count(), expected_rib, "{}", desc);
        }
    }

    #[test]
    fn test_admin_shutdown_notification() {
        let notif = NotifcationMessage::new(
            BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
            Vec::new(),
        );
        let bytes = notif.to_bytes();
        assert_eq!(bytes[0], 6); // Cease error code
        assert_eq!(bytes[1], 2); // AdministrativeShutdown subcode
        assert_eq!(bytes.len(), 2); // No data
    }

    #[tokio::test]
    async fn test_check_max_prefix_limit() {
        use crate::test_helpers::{create_test_path, create_test_prefix_n};

        // (setting, rib_count, new_count, expected)
        // expected: Ok(true)=proceed, Ok(false)=discard, Err=terminate
        let cases: Vec<(Option<MaxPrefixSetting>, usize, usize, Result<bool, ()>)> = vec![
            (None, 0, 100, Ok(true)),
            (
                Some(MaxPrefixSetting {
                    limit: 10,
                    action: MaxPrefixAction::Terminate,
                }),
                0,
                5,
                Ok(true),
            ),
            (
                Some(MaxPrefixSetting {
                    limit: 10,
                    action: MaxPrefixAction::Terminate,
                }),
                0,
                10,
                Ok(true),
            ),
            (
                Some(MaxPrefixSetting {
                    limit: 10,
                    action: MaxPrefixAction::Terminate,
                }),
                0,
                11,
                Err(()),
            ),
            (
                Some(MaxPrefixSetting {
                    limit: 10,
                    action: MaxPrefixAction::Terminate,
                }),
                8,
                3,
                Err(()),
            ),
            (
                Some(MaxPrefixSetting {
                    limit: 10,
                    action: MaxPrefixAction::Discard,
                }),
                0,
                11,
                Ok(false),
            ),
            (
                Some(MaxPrefixSetting {
                    limit: 10,
                    action: MaxPrefixAction::Discard,
                }),
                8,
                3,
                Ok(false),
            ),
        ];

        for (setting, rib_count, incoming, expected) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.config.max_prefix = setting.clone();
            let test_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            for i in 0..rib_count {
                peer.rib_in
                    .add_route(create_test_prefix_n(i as u8), create_test_path(test_ip));
            }

            let result = peer.check_max_prefix_limit(incoming);
            match expected {
                Ok(b) => assert_eq!(
                    result,
                    Ok(b),
                    "setting={:?} rib={} incoming={}",
                    setting,
                    rib_count,
                    incoming
                ),
                Err(_) => assert!(
                    result.is_err(),
                    "setting={:?} rib={} incoming={}",
                    setting,
                    rib_count,
                    incoming
                ),
            }
        }
    }

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

    #[tokio::test]
    async fn test_connect_retry_timer_started_on_idle_transition() {
        let test_cases = vec![
            (FsmEvent::ManualStart, BgpState::Connect),
            (FsmEvent::AutomaticStart, BgpState::Connect),
            (FsmEvent::ManualStartPassive, BgpState::Active),
            (FsmEvent::AutomaticStartPassive, BgpState::Active),
        ];

        for (event, expected_state) in test_cases {
            let mut peer = create_test_peer_with_state(BgpState::Idle).await;
            assert!(
                peer.fsm.timers.connect_retry_started.is_none(),
                "ConnectRetryTimer should not be started initially"
            );

            peer.process_event(&event).await.unwrap();

            assert_eq!(
                peer.state(),
                expected_state,
                "State should transition to {:?}",
                expected_state
            );
            assert_eq!(
                peer.fsm.connect_retry_counter, 0,
                "ConnectRetryCounter should be set to 0 after {:?}",
                event
            );
            assert!(
                peer.fsm.timers.connect_retry_started.is_some(),
                "ConnectRetryTimer should be started after {:?}",
                event
            );
        }
    }

    #[tokio::test]
    async fn test_connect_retry_expires_in_connect_resets_everything() {
        let mut peer = create_test_peer_with_state(BgpState::Connect).await;

        // Start both timers
        peer.fsm.timers.start_connect_retry();
        peer.fsm.timers.start_delay_open_timer();

        assert!(peer.conn.is_some(), "Test peer should have connection");
        assert!(peer.fsm.timers.delay_open_timer_running());
        assert!(peer.fsm.timers.connect_retry_started.is_some());

        // Trigger ConnectRetryTimer expiry
        peer.process_event(&FsmEvent::ConnectRetryTimerExpires)
            .await
            .unwrap();

        assert!(peer.conn.is_none(), "Connection should be dropped");
        assert!(
            !peer.fsm.timers.delay_open_timer_running(),
            "DelayOpenTimer should be stopped"
        );
        assert!(
            peer.fsm.timers.connect_retry_started.is_some(),
            "ConnectRetryTimer should be restarted"
        );

        // Verify state remains Connect
        assert_eq!(peer.state(), BgpState::Connect);
    }

    #[tokio::test]
    async fn test_manual_stop_connect() {
        let mut peer = create_test_peer_with_state(BgpState::Connect).await;
        peer.fsm.connect_retry_counter = 5;
        peer.fsm.timers.start_connect_retry();

        peer.process_event(&FsmEvent::ManualStop).await.unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.manually_stopped);
        assert_eq!(peer.fsm.connect_retry_counter, 0);
        assert!(peer.fsm.timers.connect_retry_started.is_none());
        assert!(peer.conn.is_none());
    }

    #[tokio::test]
    async fn test_manual_stop_active() {
        let mut peer = create_test_peer_with_state(BgpState::Active).await;
        peer.fsm.connect_retry_counter = 3;
        peer.fsm.timers.start_connect_retry();
        peer.fsm.timers.start_delay_open_timer();

        peer.process_event(&FsmEvent::ManualStop).await.unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.manually_stopped);
        assert_eq!(peer.fsm.connect_retry_counter, 0);
        assert!(peer.fsm.timers.connect_retry_started.is_none());
        assert!(peer.fsm.timers.delay_open_timer_started.is_none());
        assert!(peer.conn.is_none());
    }

    #[tokio::test]
    async fn test_manual_stop_session_states() {
        let test_cases = vec![
            BgpState::OpenSent,
            BgpState::OpenConfirm,
            BgpState::Established,
        ];

        for state in test_cases {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();

            peer.process_event(&FsmEvent::ManualStop).await.unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.manually_stopped);
            assert!(peer.conn.is_none());
            assert!(peer.fsm.timers.hold_timer_started.is_none());
            assert!(peer.fsm.timers.keepalive_timer_started.is_none());
        }
    }

    #[tokio::test]
    async fn test_tcp_connection_fails_connect() {
        {
            // RFC 4271 8.2.2 Event 18: Without DelayOpenTimer -> Idle
            let mut peer = create_test_peer_with_state(BgpState::Connect).await;
            assert!(peer.conn.is_some());

            peer.process_event(&FsmEvent::TcpConnectionFails)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.conn.is_none());
            assert!(peer.fsm.timers.connect_retry_started.is_none());
            assert_eq!(peer.fsm.connect_retry_counter, 0);
        }

        {
            // RFC 4271 8.2.2 Event 18: With DelayOpenTimer running -> Active
            let mut peer = create_test_peer_with_state(BgpState::Connect).await;
            peer.fsm.timers.start_delay_open_timer();
            assert!(peer.conn.is_some());

            peer.process_event(&FsmEvent::TcpConnectionFails)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Active);
            assert!(peer.conn.is_none());
            assert!(!peer.fsm.timers.delay_open_timer_running());
            assert!(peer.fsm.timers.connect_retry_started.is_some());
        }
    }

    #[tokio::test]
    async fn test_open_received_in_connect_stops_timers() {
        // RFC 4271 8.2.2 Event 20: OPEN received in Connect state
        let mut peer = create_test_peer_with_state(BgpState::Connect).await;
        peer.fsm.timers.start_connect_retry();
        peer.fsm.timers.start_delay_open_timer();
        assert!(peer.fsm.timers.connect_retry_started.is_some());
        assert!(peer.fsm.timers.delay_open_timer_running());
        assert_eq!(peer.statistics.open_sent, 0);
        assert_eq!(peer.statistics.keepalive_sent, 0);

        peer.process_event(&FsmEvent::BgpOpenReceived {
            peer_asn: 65001,
            peer_hold_time: 180,
            peer_bgp_id: 0x02020202,
            local_asn: 65000,
            local_hold_time: 180,
        })
        .await
        .unwrap();

        // Verify state transition and timers stopped
        assert_eq!(peer.state(), BgpState::OpenConfirm);
        assert!(peer.fsm.timers.connect_retry_started.is_none());
        assert!(!peer.fsm.timers.delay_open_timer_running());
        // Verify OPEN and KEEPALIVE messages were sent
        assert_eq!(peer.statistics.open_sent, 1);
        assert_eq!(peer.statistics.keepalive_sent, 1);
    }

    #[tokio::test]
    async fn test_open_received_hold_time_zero() {
        // RFC 4271 8.2.2: When hold time is zero, timers should not be started
        let mut peer = create_test_peer_with_state(BgpState::Connect).await;

        peer.process_event(&FsmEvent::BgpOpenReceived {
            peer_asn: 65001,
            peer_hold_time: 0, // Peer wants no hold timer
            peer_bgp_id: 0x02020202,
            local_asn: 65000,
            local_hold_time: 180,
        })
        .await
        .unwrap();

        // Verify state transition
        assert_eq!(peer.state(), BgpState::OpenConfirm);
        // Verify hold time negotiated to zero (min of 0 and 180)
        assert_eq!(peer.fsm.timers.hold_time.as_secs(), 0);
        assert_eq!(peer.fsm.timers.keepalive_time.as_secs(), 0);
        // Verify timers are NOT started when hold_time is zero
        assert!(peer.fsm.timers.hold_timer_started.is_none());
        assert!(peer.fsm.timers.keepalive_timer_started.is_none());
        // Verify KEEPALIVE was still sent (RFC requires it)
        assert_eq!(peer.statistics.keepalive_sent, 1);
    }
}
