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

use super::fsm::{BgpOpenParams, BgpState, FsmEvent};
use super::{Peer, PeerOp, TcpConnection};
use crate::bgp::msg::{read_bgp_message, BgpMessage};
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotifcationMessage};
use crate::server::ConnectionType;
use crate::{debug, error, info};
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// RFC 4271 8.2.2: Initial HoldTimer value when entering OpenSent state (4 minutes suggested).
const INITIAL_HOLD_TIME: Duration = Duration::from_secs(240);

impl Peer {
    /// Handle Idle state - wait for ManualStart or AutomaticStart.
    /// Returns true if shutdown requested.
    pub(super) async fn handle_idle_state(&mut self) -> bool {
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
                // RFC 4271 Event 13: IdleHoldTimer_Expires
                debug!("IdleHoldTimer expired", "peer_ip" => self.addr.to_string());
                self.try_process_event(&FsmEvent::IdleHoldTimerExpires).await;
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
                // RFC 4271 Event 13: IdleHoldTimer_Expires
                debug!("IdleHoldTimer expired", "peer_ip" => self.addr.to_string());
                self.try_process_event(&FsmEvent::IdleHoldTimerExpires).await;
            }
        }
        false
    }

    /// Handle Connect state - attempt TCP connection or wait for DelayOpen timer.
    pub(super) async fn handle_connect_state(&mut self) {
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
                result = crate::net::create_and_bind_tcp_socket(self.local_addr, peer_addr) => {
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
                        if let Err(e) = self.process_event(&FsmEvent::BgpOpenWithDelayOpenTimer(
                            BgpOpenParams {
                                peer_asn: open.asn,
                                peer_hold_time: open.hold_time,
                                local_asn: self.fsm.local_asn(),
                                local_hold_time: self.fsm.local_hold_time(),
                                peer_bgp_id: open.bgp_identifier,
                            }
                        )).await {
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
    pub(super) async fn handle_active_state(&mut self) {
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
                        if let Err(e) = self.process_event(&FsmEvent::BgpOpenWithDelayOpenTimer(
                            BgpOpenParams {
                                peer_asn: open.asn,
                                peer_hold_time: open.hold_time,
                                local_asn: self.fsm.local_asn(),
                                local_hold_time: self.fsm.local_hold_time(),
                                peer_bgp_id: open.bgp_identifier,
                            }
                        )).await {
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
    pub(super) async fn handle_open_and_established(&mut self) -> bool {
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

    /// Process FSM event, transition state, and execute associated actions.
    pub(super) async fn process_event(&mut self, event: &FsmEvent) -> Result<(), io::Error> {
        let old_state = self.fsm.state();
        let new_state = self.fsm.handle_event(event);

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

            // RFC 4271 8.2.2: Any other events (8, 10-11, 13, 19, 25-28) in Connect/Active -> Idle
            (BgpState::Connect, BgpState::Idle, FsmEvent::AutomaticStop(_))
            | (BgpState::Connect, BgpState::Idle, FsmEvent::HoldTimerExpires)
            | (BgpState::Connect, BgpState::Idle, FsmEvent::KeepaliveTimerExpires)
            | (BgpState::Connect, BgpState::Idle, FsmEvent::IdleHoldTimerExpires)
            | (BgpState::Connect, BgpState::Idle, FsmEvent::BgpOpenReceived(_))
            | (BgpState::Connect, BgpState::Idle, FsmEvent::BgpKeepaliveReceived)
            | (BgpState::Connect, BgpState::Idle, FsmEvent::BgpUpdateReceived)
            | (BgpState::Connect, BgpState::Idle, FsmEvent::BgpUpdateMsgErr(_))
            | (BgpState::Active, BgpState::Idle, FsmEvent::AutomaticStop(_))
            | (BgpState::Active, BgpState::Idle, FsmEvent::HoldTimerExpires)
            | (BgpState::Active, BgpState::Idle, FsmEvent::KeepaliveTimerExpires)
            | (BgpState::Active, BgpState::Idle, FsmEvent::IdleHoldTimerExpires)
            | (BgpState::Active, BgpState::Idle, FsmEvent::BgpOpenReceived(_))
            | (BgpState::Active, BgpState::Idle, FsmEvent::BgpKeepaliveReceived)
            | (BgpState::Active, BgpState::Idle, FsmEvent::BgpUpdateReceived)
            | (BgpState::Active, BgpState::Idle, FsmEvent::BgpUpdateMsgErr(_)) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.disconnect(true);
                self.fsm.increment_connect_retry_counter();
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

            // RFC 4271 Event 8: AutomaticStop in session states - send CEASE notification
            (BgpState::OpenSent, BgpState::Idle, FsmEvent::AutomaticStop(ref subcode))
            | (BgpState::OpenConfirm, BgpState::Idle, FsmEvent::AutomaticStop(ref subcode))
            | (BgpState::Established, BgpState::Idle, FsmEvent::AutomaticStop(ref subcode)) => {
                let notif = NotifcationMessage::new(BgpError::Cease(subcode.clone()), Vec::new());
                let _ = self.send_notification(notif).await;
                self.disconnect(true);
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();

                // Set admin state based on the cease reason
                let admin_state = match subcode {
                    CeaseSubcode::MaxPrefixesReached => {
                        crate::server::AdminState::PrefixLimitReached
                    }
                    _ => crate::server::AdminState::Down,
                };
                let _ = self.server_tx.send(crate::server::ServerOp::SetAdminState {
                    peer_ip: self.addr,
                    state: admin_state,
                });
                return Err(io::Error::new(io::ErrorKind::InvalidData, "automatic stop"));
            }

            // RFC 4271 Event 28: UpdateMsgErr in session states - send UPDATE error notification
            (BgpState::OpenSent, BgpState::Idle, FsmEvent::BgpUpdateMsgErr(ref notif))
            | (BgpState::OpenConfirm, BgpState::Idle, FsmEvent::BgpUpdateMsgErr(ref notif))
            | (BgpState::Established, BgpState::Idle, FsmEvent::BgpUpdateMsgErr(ref notif)) => {
                let _ = self.send_notification(notif.clone()).await;
                self.disconnect(true);
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "update message error",
                ));
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

            // Received OPEN while in Connect with DelayOpen - send OPEN + KEEPALIVE (RFC 4271 Event 20)
            (
                BgpState::Connect,
                BgpState::OpenConfirm,
                &FsmEvent::BgpOpenWithDelayOpenTimer(params),
            ) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.send_open().await?;
                self.enter_open_confirm(
                    params.peer_asn,
                    params.peer_hold_time,
                    params.local_asn,
                    params.local_hold_time,
                )
                .await?;
            }

            // Entering OpenConfirm from OpenSent - send KEEPALIVE
            (BgpState::OpenSent, BgpState::OpenConfirm, &FsmEvent::BgpOpenReceived(params))
            | (
                BgpState::OpenSent,
                BgpState::OpenConfirm,
                &FsmEvent::BgpOpenWithDelayOpenTimer(params),
            ) => {
                self.enter_open_confirm(
                    params.peer_asn,
                    params.peer_hold_time,
                    params.local_asn,
                    params.local_hold_time,
                )
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

            // RFC 4271 6.6: FSM Error - Event 9 in OpenConfirm
            (BgpState::OpenConfirm, BgpState::Idle, FsmEvent::ConnectRetryTimerExpires) => {
                let notif = NotifcationMessage::new(BgpError::FiniteStateMachineError, vec![]);
                let _ = self.send_notification(notif).await;
                self.disconnect(true);
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
                return Err(io::Error::new(io::ErrorKind::InvalidData, "FSM error"));
            }

            // RFC 4271 6.6: FSM Error - Event 27 in OpenConfirm
            (BgpState::OpenConfirm, BgpState::Idle, FsmEvent::BgpUpdateReceived) => {
                let notif = NotifcationMessage::new(BgpError::FiniteStateMachineError, vec![]);
                let _ = self.send_notification(notif).await;
                self.disconnect(true);
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
                return Err(io::Error::new(io::ErrorKind::InvalidData, "FSM error"));
            }

            // RFC 4271 6.6: FSM Error - Event 9 in Established
            (BgpState::Established, BgpState::Idle, FsmEvent::ConnectRetryTimerExpires) => {
                let notif = NotifcationMessage::new(BgpError::FiniteStateMachineError, vec![]);
                let _ = self.send_notification(notif).await;
                self.disconnect(true);
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
                return Err(io::Error::new(io::ErrorKind::InvalidData, "FSM error"));
            }

            // AutomaticStop: set admin state based on reason
            (_, BgpState::Idle, FsmEvent::AutomaticStop(subcode)) => {
                let admin_state = match subcode {
                    CeaseSubcode::MaxPrefixesReached => {
                        crate::server::AdminState::PrefixLimitReached
                    }
                    _ => crate::server::AdminState::Down,
                };
                let _ = self.server_tx.send(crate::server::ServerOp::SetAdminState {
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

        Ok(())
    }

    /// Process FSM event and log any errors.
    pub(super) async fn try_process_event(&mut self, event: &FsmEvent) {
        if let Err(e) = self.process_event(event).await {
            error!("failed to process event",
                "peer_ip" => self.addr.to_string(),
                "event" => format!("{:?}", event),
                "error" => e.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_notification::{MessageHeaderError, OpenMessageError, UpdateMessageError};
    use crate::config::PeerConfig;
    use crate::peer::{BgpState, Fsm};
    use crate::rib::rib_in::AdjRibIn;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

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
            fsm: Fsm::with_state(state, 65000, 180, 0x01010101, local_ip, false),
            conn: Some(TcpConnection {
                tx: tcp_tx,
                rx: tcp_rx,
            }),
            asn: Some(65001),
            rib_in: AdjRibIn::new(),
            session_type: Some(crate::peer::SessionType::Ebgp),
            statistics: crate::peer::PeerStatistics::default(),
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

        peer.process_event(&FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
            peer_asn: 65001,
            peer_hold_time: 180,
            peer_bgp_id: 0x02020202,
            local_asn: 65000,
            local_hold_time: 180,
        }))
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

        peer.process_event(&FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
            peer_asn: 65001,
            peer_hold_time: 0, // Peer wants no hold timer
            peer_bgp_id: 0x02020202,
            local_asn: 65000,
            local_hold_time: 180,
        }))
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

    #[tokio::test]
    async fn test_connect_active_other_events() {
        // RFC 4271 8.2.2: Any other events (8, 10-11, 13, 19, 25-28) in Connect/Active -> Idle with cleanup
        let events = vec![
            FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached),
            FsmEvent::HoldTimerExpires,
            FsmEvent::KeepaliveTimerExpires,
            FsmEvent::IdleHoldTimerExpires,
            FsmEvent::BgpOpenReceived(BgpOpenParams {
                peer_asn: 65001,
                peer_hold_time: 180,
                peer_bgp_id: 0x02020202,
                local_asn: 65000,
                local_hold_time: 180,
            }),
            FsmEvent::BgpKeepaliveReceived,
            FsmEvent::BgpUpdateReceived,
            FsmEvent::BgpUpdateMsgErr(NotifcationMessage::new(
                BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
                vec![],
            )),
        ];

        for state in [BgpState::Connect, BgpState::Active] {
            for event in &events {
                let mut peer = create_test_peer_with_state(state).await;
                peer.fsm.timers.start_connect_retry();
                peer.fsm.timers.start_delay_open_timer();

                peer.process_event(event).await.unwrap();

                assert_eq!(peer.state(), BgpState::Idle);
                assert!(peer.fsm.timers.connect_retry_started.is_none());
                assert!(peer.fsm.timers.delay_open_timer_started.is_none());
                assert!(peer.conn.is_none());
            }
        }
    }

    #[tokio::test]
    async fn test_update_msg_err_in_session_states() {
        // RFC 4271 Event 28: UpdateMsgErr in session states should send NOTIFICATION
        for state in [
            BgpState::OpenSent,
            BgpState::OpenConfirm,
            BgpState::Established,
        ] {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            peer.config.send_notification_without_open = true;

            let notif = NotifcationMessage::new(
                BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
                vec![],
            );

            // Process the event - should send NOTIFICATION and transition to Idle
            peer.process_event(&FsmEvent::BgpUpdateMsgErr(notif.clone()))
                .await
                .unwrap_err(); // Should return error

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.fsm.timers.hold_timer_started.is_none());
            assert!(peer.fsm.timers.keepalive_timer_started.is_none());
            assert!(peer.conn.is_none());
            // Verify notification was sent (check statistics)
            assert_eq!(peer.statistics.notification_sent, 1);
        }
    }
}
