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
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};

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
                    if self.handle_connected_state().await {
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

    /// Passive mode: wait indefinitely for incoming connection.
    async fn handle_idle_state_passive(&mut self) -> bool {
        loop {
            match self.peer_rx.recv().await {
                Some(PeerOp::ManualStart) => {
                    debug!("ManualStart ignored for passive peer", "peer_ip" => self.addr.to_string());
                }
                Some(PeerOp::Shutdown(_)) => return true,
                Some(PeerOp::GetStatistics(response)) => {
                    let _ = response.send(self.statistics.clone());
                }
                Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                    self.accept_connection(tcp_tx, tcp_rx);
                    return false;
                }
                Some(_) => {}
                None => return true,
            }
        }
    }

    /// Active mode: wait for ManualStart or auto-reconnect timer.
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
                        self.transition(&FsmEvent::ManualStart);
                    }
                    Some(PeerOp::Shutdown(_)) => return true,
                    Some(PeerOp::GetStatistics(response)) => {
                        let _ = response.send(self.statistics.clone());
                    }
                    Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                        self.accept_connection(tcp_tx, tcp_rx);
                    }
                    Some(_) => {}
                    None => return true,
                }
            }
            _ = tokio::time::sleep(idle_hold_time), if auto_reconnect => {
                debug!("IdleHoldTimer expired, AutomaticStart", "peer_ip" => self.addr.to_string());
                self.transition(&FsmEvent::AutomaticStart);
            }
        }
        false
    }

    /// Accept an incoming TCP connection and transition FSM to OpenSent.
    fn accept_connection(&mut self, tcp_tx: OwnedWriteHalf, tcp_rx: OwnedReadHalf) {
        debug!("TcpConnectionAccepted received", "peer_ip" => self.addr.to_string());
        self.conn = Some(TcpConnection {
            tx: tcp_tx,
            rx: tcp_rx,
        });
        self.conn_type = ConnectionType::Incoming;
        self.transition(&FsmEvent::ManualStart);
        self.transition(&FsmEvent::TcpConnectionConfirmed);
    }

    /// Handle Connect state - attempt TCP connection.
    async fn handle_connect_state(&mut self) {
        let peer_addr = SocketAddr::new(self.addr, self.port);

        tokio::select! {
            result = create_and_bind_tcp_socket(self.local_addr, peer_addr) => {
                match result {
                    Ok(stream) => {
                        info!("TCP connection established", "peer_ip" => self.addr.to_string());
                        let (rx, tx) = stream.into_split();
                        self.conn = Some(TcpConnection { tx, rx });

                        // Handle DelayOpen if configured
                        if self.config.delay_open_time_secs.is_some() {
                            self.fsm.timers.start_delay_open_timer();
                        }

                        self.transition(&FsmEvent::TcpConnectionConfirmed);

                        // Send OPEN if not using DelayOpen
                        if self.config.delay_open_time_secs.is_none() {
                            if let Err(e) = self.enter_open_sent().await {
                                error!("failed to send OPEN", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                                self.disconnect();
                            }
                        }
                    }
                    Err(e) => {
                        debug!("TCP connection failed", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                        self.transition(&FsmEvent::TcpConnectionFails);
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(self.connect_retry_secs)) => {
                debug!("ConnectRetryTimer expired", "peer_ip" => self.addr.to_string());
                self.transition(&FsmEvent::ConnectRetryTimerExpires);
            }
            op = self.peer_rx.recv() => {
                if let Some(PeerOp::ManualStop) = op {
                    self.manually_stopped = true;
                    self.transition(&FsmEvent::ManualStop);
                }
            }
        }
    }

    /// Handle Active state - wait before retrying connection.
    async fn handle_active_state(&mut self) {
        let retry_time = Duration::from_secs(self.connect_retry_secs);

        tokio::select! {
            _ = tokio::time::sleep(retry_time) => {
                debug!("ConnectRetryTimer expired in Active", "peer_ip" => self.addr.to_string());
                self.transition(&FsmEvent::ConnectRetryTimerExpires);
            }
            op = self.peer_rx.recv() => {
                if let Some(PeerOp::ManualStop) = op {
                    self.manually_stopped = true;
                    self.transition(&FsmEvent::ManualStop);
                }
            }
        }
    }

    /// Handle connected states (OpenSent, OpenConfirm, Established).
    /// Returns true if shutdown requested.
    async fn handle_connected_state(&mut self) -> bool {
        let peer_ip = self.addr;

        // For incoming connections (new_connected), send OPEN if not already sent
        // But respect DelayOpen - start timer instead of sending immediately
        if self.fsm.state() == BgpState::OpenSent && self.statistics.open_sent == 0 {
            if self.config.delay_open_time_secs.is_some() {
                self.fsm.timers.start_delay_open_timer();
            } else {
                if let Err(e) = self.enter_open_sent().await {
                    error!("failed to send OPEN", "peer_ip" => peer_ip.to_string(), "error" => e.to_string());
                    self.disconnect();
                    return false;
                }
            }
        }

        // Timer interval for hold/keepalive checks
        let mut timer_interval = tokio::time::interval(Duration::from_millis(500));

        loop {
            let conn = match self.conn.as_mut() {
                Some(c) => c,
                None => {
                    // Connection lost, transition back to Idle
                    self.transition(&FsmEvent::TcpConnectionFails);
                    return false;
                }
            };

            tokio::select! {
                result = read_bgp_message(&mut conn.rx) => {
                    match result {
                        Ok(message) => {
                            if let Err(e) = self.handle_received_message(message, peer_ip).await {
                                error!("error processing message", "peer_ip" => peer_ip.to_string(), "error" => e.to_string());
                                self.disconnect();
                                return false;
                            }
                        }
                        Err(e) => {
                            error!("error reading message", "peer_ip" => peer_ip.to_string(), "error" => format!("{:?}", e));
                            if let Some(notif) = NotifcationMessage::from_parser_error(&e) {
                                let _ = self.send_notification(notif).await;
                            }
                            self.disconnect();
                            return false;
                        }
                    }
                }

                Some(msg) = self.peer_rx.recv() => {
                    match msg {
                        PeerOp::SendUpdate(update_msg) => {
                            if let Err(e) = self.send_update(update_msg).await {
                                error!("failed to send UPDATE", "peer_ip" => peer_ip.to_string(), "error" => e.to_string());
                                self.disconnect();
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
                            self.manually_stopped = true;
                            let notif = NotifcationMessage::new(
                                BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
                                Vec::new(),
                            );
                            let _ = self.send_notification(notif).await;
                            self.disconnect();
                            self.transition(&FsmEvent::ManualStop);
                            return false;
                        }
                        PeerOp::ManualStart | PeerOp::TcpConnectionAccepted { .. } => {
                            // Ignored when connected
                        }
                    }
                }

                _ = timer_interval.tick() => {
                    // DelayOpen timer check
                    if self.fsm.timers.delay_open_timer_expired() {
                        debug!("delay open timer expired", "peer_ip" => peer_ip.to_string());
                        if let Err(e) = self.handle_fsm_event(&FsmEvent::DelayOpenTimerExpires).await {
                            error!("failed to handle delay open timer", "peer_ip" => peer_ip.to_string(), "error" => e.to_string());
                            self.disconnect();
                            return false;
                        }
                    }

                    // Hold timer check
                    if self.fsm.timers.hold_timer_expired() {
                        error!("hold timer expired", "peer_ip" => peer_ip.to_string());
                        let notif = NotifcationMessage::new(BgpError::HoldTimerExpired, vec![]);
                        let _ = self.send_notification(notif).await;
                        self.fsm.handle_event(&FsmEvent::HoldTimerExpires);
                        self.disconnect();
                        return false;
                    }

                    // Keepalive timer check
                    if self.fsm.timers.keepalive_timer_expired() {
                        if let Err(e) = self.handle_fsm_event(&FsmEvent::KeepaliveTimerExpires).await {
                            error!("failed to send keepalive", "peer_ip" => peer_ip.to_string(), "error" => e.to_string());
                            self.disconnect();
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
    fn disconnect(&mut self) {
        self.conn = None;
        self.consecutive_down_count += 1;
        // Reset timers for clean reconnect
        self.fsm.timers.stop_hold_timer();
        self.fsm.timers.stop_keepalive_timer();
        self.fsm.timers.stop_delay_open_timer();
        let _ = self
            .server_tx
            .send(ServerOp::PeerDisconnected { peer_ip: self.addr });
    }

    /// Compute idle hold time with DampPeerOscillations backoff (RFC 4271 8.1.1).
    /// Returns None if automatic restart is disabled.
    fn get_idle_hold_time(&self) -> Option<Duration> {
        const MAX_IDLE_HOLD_TIME: Duration = Duration::from_secs(120);
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

    /// Handle FSM event and notify server if state changed.
    fn transition(&mut self, event: &FsmEvent) {
        let old_state = self.fsm.state();
        self.fsm.handle_event(event);
        if self.fsm.state() != old_state {
            self.notify_state_change();
        }
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

    /// Handle an FSM event and perform state transitions
    async fn handle_fsm_event(&mut self, event: &FsmEvent) -> Result<(), io::Error> {
        let old_state = self.fsm.state();
        let (new_state, fsm_error) = self.fsm.handle_event(event);

        // Handle state-specific actions based on transitions
        match (old_state, new_state, event) {
            // Entering OpenSent - send OPEN message (normal path)
            (BgpState::Connect, BgpState::OpenSent, FsmEvent::TcpConnectionConfirmed) => {
                self.enter_open_sent().await?;
            }

            // DelayOpen timer expired in Connect - send OPEN (RFC 4271 8.2.1.3)
            (BgpState::Connect, BgpState::OpenSent, FsmEvent::DelayOpenTimerExpires) => {
                self.fsm.timers.stop_delay_open_timer();
                self.enter_open_sent().await?;
            }

            // DelayOpen timer expired in OpenSent - send OPEN (incoming connection case)
            (BgpState::OpenSent, BgpState::OpenSent, FsmEvent::DelayOpenTimerExpires) => {
                self.fsm.timers.stop_delay_open_timer();
                self.enter_open_sent().await?;
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
                self.fsm.timers.stop_delay_open_timer();
                self.enter_open_sent().await?;
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
            }

            // In Established - reset hold timer on keepalive/update
            (BgpState::Established, BgpState::Established, FsmEvent::BgpKeepaliveReceived)
            | (BgpState::Established, BgpState::Established, FsmEvent::BgpUpdateReceived) => {
                self.fsm.timers.reset_hold_timer();
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

        // Notify server of state change whenever state transitions occur
        if old_state != new_state {
            let _ = self.server_tx.send(ServerOp::PeerStateChanged {
                peer_ip: self.addr,
                state: new_state,
            });
        }

        // Send NOTIFICATION and return error if FSM returned an error
        if let Some(error) = fsm_error {
            let notif = NotifcationMessage::new(error, vec![]);
            let _ = self.send_notification(notif).await;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "FSM error"));
        }

        Ok(())
    }

    /// Handle entering OpenSent state - send OPEN message
    async fn enter_open_sent(&mut self) -> Result<(), io::Error> {
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
        // Reset damping on stable connection
        self.consecutive_down_count = 0;

        // Negotiate hold time: use minimum (RFC 4271).
        let hold_time = local_hold_time.min(peer_hold_time);
        self.fsm.timers.reset_hold_timer();
        self.fsm.timers.set_negotiated_hold_time(hold_time);

        // Send KEEPALIVE
        self.send_keepalive().await?;

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
                self.handle_fsm_event(&FsmEvent::BgpOpenReceived {
                    peer_asn: open_msg.asn,
                    peer_hold_time: open_msg.hold_time,
                    peer_bgp_id: open_msg.bgp_identifier,
                    local_asn: self.fsm.local_asn(),
                    local_hold_time: self.fsm.local_hold_time(),
                })
                .await?;
            }
            BgpMessage::Update(_) => {
                self.handle_fsm_event(&FsmEvent::BgpUpdateReceived).await?;
            }
            BgpMessage::KeepAlive(_) => {
                self.handle_fsm_event(&FsmEvent::BgpKeepaliveReceived)
                    .await?;
            }
            BgpMessage::Notification(_) => {
                self.handle_fsm_event(&FsmEvent::NotificationReceived)
                    .await?;
            }
        }

        // Process UPDATE message content
        if let BgpMessage::Update(update_msg) = message {
            match self.handle_update(update_msg) {
                Ok(delta) => Ok(Some(delta)),
                Err(BgpError::Cease(CeaseSubcode::MaxPrefixesReached)) => {
                    // RFC 4271 8.1.2: check allow_automatic_stop
                    if self.config.allow_automatic_stop {
                        self.handle_fsm_event(&FsmEvent::AutomaticStop(
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
    use tokio::net::TcpListener;

    async fn create_test_peer_with_state(state: BgpState) -> Peer {
        // Create a test TCP connection
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

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
}
