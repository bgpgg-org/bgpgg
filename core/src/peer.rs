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
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::msg_update::UpdateMessage;
use crate::bgp::utils::IpNetwork;
use crate::fsm::{BgpEvent, BgpState, Fsm};
use crate::rib::rib_in::AdjRibIn;
use crate::rib::Path;
use crate::server::{PeerHandle, PeerMessage, ServerOp};
use crate::{debug, error, info, warn};
use std::io;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

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

pub struct Peer {
    pub addr: String,
    pub fsm: Fsm,
    pub tcp_tx: OwnedWriteHalf,
    pub asn: u16,
    pub rib_in: AdjRibIn,
    pub session_type: SessionType,
    pub statistics: PeerStatistics,
}

impl Peer {
    /// Create a new Peer with complete information
    pub fn new(addr: String, tcp_tx: OwnedWriteHalf, asn: u16, session_type: SessionType) -> Self {
        Peer {
            addr: addr.clone(),
            fsm: Fsm::new(),
            tcp_tx,
            asn,
            rib_in: AdjRibIn::new(addr),
            session_type,
            statistics: PeerStatistics::default(),
        }
    }

    /// Update session type based on peer ASN
    pub fn update_session_type(&mut self, peer_asn: u16, local_asn: u16) {
        self.session_type = if peer_asn == local_asn {
            SessionType::Ibgp
        } else {
            SessionType::Ebgp
        };
    }

    /// Get current BGP state
    pub fn state(&self) -> BgpState {
        self.fsm.state()
    }

    /// Check if peer is established
    pub fn is_established(&self) -> bool {
        self.fsm.is_established()
    }

    /// Process a BGP message and return route changes for Loc-RIB update if applicable
    /// Returns (withdrawn_prefixes, announced_routes) or None if not an UPDATE
    pub async fn process_message(
        &mut self,
        message: BgpMessage,
    ) -> Result<Option<(Vec<IpNetwork>, Vec<(IpNetwork, Path)>)>, io::Error> {
        // Track received messages
        match &message {
            BgpMessage::Open(_) => {
                self.statistics.open_received += 1;
                warn!("received duplicate OPEN, ignoring", "peer_ip" => &self.addr);
            }
            BgpMessage::Update(_) => {
                self.statistics.update_received += 1;
                info!("received UPDATE", "peer_ip" => &self.addr);
            }
            BgpMessage::KeepAlive(_) => {
                self.statistics.keepalive_received += 1;
                debug!("received KEEPALIVE", "peer_ip" => &self.addr);
            }
            BgpMessage::Notification(notif_msg) => {
                self.statistics.notification_received += 1;
                warn!("received NOTIFICATION", "peer_ip" => &self.addr, "notification" => format!("{:?}", notif_msg));
            }
        }

        // Determine FSM event and process it
        let event = match &message {
            BgpMessage::Open(_) => None,
            BgpMessage::Update(_) => Some(BgpEvent::BgpUpdateReceived),
            BgpMessage::KeepAlive(_) => Some(BgpEvent::BgpKeepaliveReceived),
            BgpMessage::Notification(_) => Some(BgpEvent::NotificationReceived),
        };

        // Process FSM event if present
        if let Some(event) = event {
            self.process_event(&event).await?;
        }

        // Process UPDATE message content
        if let BgpMessage::Update(update_msg) = message {
            Ok(Some(self.process_update(update_msg)))
        } else {
            Ok(None)
        }
    }

    /// Process a BGP event and handle state transitions
    pub async fn process_event(&mut self, event: &BgpEvent) -> Result<(), io::Error> {
        let old_state = self.fsm.state();
        let new_state = self.fsm.process_event(event);

        // Handle state-specific actions based on transitions
        match (old_state, new_state, event) {
            // Entering OpenSent - send OPEN message
            (
                BgpState::Connect,
                BgpState::OpenSent,
                BgpEvent::TcpConnectionConfirmed {
                    local_asn,
                    hold_time,
                    bgp_id,
                },
            ) => {
                let open_msg = OpenMessage::new(*local_asn, *hold_time, *bgp_id);
                self.tcp_tx.write_all(&open_msg.serialize()).await?;
                self.statistics.open_sent += 1;
                info!("sent OPEN message", "peer_ip" => &self.addr);
            }

            // Entering OpenConfirm - send KEEPALIVE
            (
                BgpState::OpenSent,
                BgpState::OpenConfirm,
                BgpEvent::BgpOpenReceived {
                    peer_asn: _,
                    peer_hold_time,
                },
            ) => {
                self.fsm.timers.reset_hold_timer();
                self.fsm.timers.set_negotiated_hold_time(*peer_hold_time);
                let keepalive_msg = KeepAliveMessage {};
                self.tcp_tx.write_all(&keepalive_msg.serialize()).await?;
                self.statistics.keepalive_sent += 1;
                debug!("sent KEEPALIVE message", "peer_ip" => &self.addr);
                self.fsm.timers.start_keepalive_timer();
            }

            // In OpenConfirm or Established - handle keepalive timer expiry
            (_, BgpState::OpenConfirm, BgpEvent::KeepaliveTimerExpires)
            | (_, BgpState::Established, BgpEvent::KeepaliveTimerExpires) => {
                let keepalive_msg = KeepAliveMessage {};
                self.tcp_tx.write_all(&keepalive_msg.serialize()).await?;
                self.statistics.keepalive_sent += 1;
                debug!("sent KEEPALIVE message", "peer_ip" => &self.addr);
                self.fsm.timers.start_keepalive_timer();
            }

            // Received keepalive in OpenConfirm - entering Established
            (BgpState::OpenConfirm, BgpState::Established, BgpEvent::BgpKeepaliveReceived) => {
                self.fsm.timers.reset_hold_timer();
            }

            // In Established - reset hold timer on keepalive/update
            (BgpState::Established, BgpState::Established, BgpEvent::BgpKeepaliveReceived)
            | (BgpState::Established, BgpState::Established, BgpEvent::BgpUpdateReceived) => {
                self.fsm.timers.reset_hold_timer();
            }

            _ => {}
        }

        Ok(())
    }

    /// Process a BGP UPDATE message
    /// Returns (withdrawn_prefixes, announced_routes) - only what changed in THIS update
    pub fn process_update(
        &mut self,
        update_msg: UpdateMessage,
    ) -> (Vec<IpNetwork>, Vec<(IpNetwork, Path)>) {
        let mut withdrawn = Vec::new();
        let mut announced = Vec::new();

        // Process withdrawn routes
        for prefix in update_msg.withdrawn_routes() {
            info!("withdrawing route", "prefix" => format!("{:?}", prefix), "peer_ip" => &self.addr);
            self.rib_in.remove_route(*prefix);
            withdrawn.push(*prefix);
        }

        // Extract path attributes for announced routes
        let origin = update_msg.get_origin();
        let as_path = update_msg.get_as_path();
        let next_hop = update_msg.get_next_hop();

        // Only process announcements if we have required attributes
        if let (Some(origin), Some(as_path), Some(next_hop)) = (origin, as_path, next_hop) {
            // Process announced routes (NLRI)
            for prefix in update_msg.nlri_list() {
                let source = match self.session_type {
                    SessionType::Ebgp => crate::rib::RouteSource::Ebgp(self.addr.clone()),
                    SessionType::Ibgp => crate::rib::RouteSource::Ibgp(self.addr.clone()),
                };
                let path = Path {
                    origin,
                    as_path: as_path.clone(),
                    next_hop,
                    source,
                    local_pref: None,
                    med: None,
                };
                info!("adding route to Adj-RIB-In", "prefix" => format!("{:?}", prefix), "peer_ip" => &self.addr);
                self.rib_in.add_route(*prefix, path.clone());
                announced.push((*prefix, path));
            }
        } else if !update_msg.nlri_list().is_empty() {
            warn!("UPDATE has NLRI but missing required attributes, skipping announcements", "peer_ip" => &self.addr);
        }

        // Return only what changed in this UPDATE
        (withdrawn, announced)
    }

    /// Send UPDATE message and reset keepalive timer (RFC 4271 requirement)
    pub async fn send_update(&mut self, update_msg: UpdateMessage) -> Result<(), io::Error> {
        self.tcp_tx.write_all(&update_msg.serialize()).await?;
        self.statistics.update_sent += 1;
        // RFC 4271: "Each time the local system sends a KEEPALIVE or UPDATE message,
        // it restarts its KeepaliveTimer"
        self.fsm.timers.reset_keepalive_timer();
        Ok(())
    }

    /// Set negotiated hold time from received OPEN message
    pub fn set_negotiated_hold_time(&mut self, hold_time: u16) {
        self.fsm.timers.set_negotiated_hold_time(hold_time);
        info!("negotiated hold time", "peer_ip" => &self.addr, "hold_time_seconds" => hold_time);
    }

    /// Main peer task - handles the full lifecycle of a BGP peer connection
    pub async fn run(
        peer_ip: String,
        mut reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
        local_asn: u16,
        hold_time: u16,
        local_bgp_id: u32,
        server_op_tx: mpsc::UnboundedSender<ServerOp>,
    ) {
        debug!("handling peer", "peer_ip" => &peer_ip);

        // Create a placeholder Peer to send OPEN immediately (we don't know peer_asn yet)
        let mut peer = Peer::new(peer_ip.clone(), writer, 0, SessionType::Ebgp);

        // Send OPEN via FSM to avoid deadlock
        if let Err(e) = peer.process_event(&BgpEvent::ManualStart).await {
            error!("failed to start FSM", "peer_ip" => &peer_ip, "error" => e.to_string());
            return;
        }

        if let Err(e) = peer
            .process_event(&BgpEvent::TcpConnectionConfirmed {
                local_asn,
                hold_time,
                bgp_id: local_bgp_id,
            })
            .await
        {
            error!("failed to send OPEN", "peer_ip" => &peer_ip, "error" => e.to_string());
            return;
        }

        // Wait for peer's OPEN message
        let (peer_asn, peer_hold_time) = loop {
            let result = read_bgp_message(&mut reader).await;

            match result {
                Ok(message) => match message {
                    BgpMessage::Open(open_msg) => {
                        info!("received OPEN from peer", "peer_ip" => &peer_ip, "asn" => open_msg.asn, "hold_time" => open_msg.hold_time, "bgp_identifier" => open_msg.bgp_identifier);
                        break (open_msg.asn, open_msg.hold_time);
                    }
                    _ => {
                        error!("expected OPEN as first message", "peer_ip" => &peer_ip);
                        return;
                    }
                },
                Err(e) => {
                    error!("error reading first message from peer", "peer_ip" => &peer_ip, "error" => format!("{:?}", e));
                    return;
                }
            }
        };

        // Negotiate hold time: use minimum of our hold time and peer's hold time (RFC 4271)
        let negotiated_hold_time = hold_time.min(peer_hold_time);

        // Determine session type
        let session_type = if peer_asn == local_asn {
            SessionType::Ibgp
        } else {
            SessionType::Ebgp
        };

        // Update peer with correct ASN and session type
        peer.asn = peer_asn;
        peer.session_type = session_type;

        // Track that we received OPEN (it was received before peer was fully created)
        peer.statistics.open_received += 1;

        // Process receiving peer's OPEN (sends KEEPALIVE)
        if let Err(e) = peer
            .process_event(&BgpEvent::BgpOpenReceived {
                peer_asn,
                peer_hold_time: negotiated_hold_time,
            })
            .await
        {
            error!("failed to complete connection", "peer_ip" => &peer_ip, "error" => e.to_string());
            return;
        }

        // Create channel for receiving messages from the server (route updates to send)
        let (message_tx, mut message_rx) = mpsc::unbounded_channel();

        // Track whether we've registered with the server yet
        let mut peer_registered = false;

        // Create keepalive interval timer (RFC 4271)
        let mut keepalive_interval = if negotiated_hold_time > 0 {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // Skip first immediate tick
            Some(interval)
        } else {
            None
        };

        // RFC 4271: Hold timer - track last KEEPALIVE or UPDATE received
        let hold_timeout = tokio::time::Duration::from_secs(negotiated_hold_time as u64);
        let mut last_keepalive_or_update = tokio::time::Instant::now();

        // Check hold timer every 500ms
        let mut hold_check_interval =
            tokio::time::interval(tokio::time::Duration::from_millis(500));
        hold_check_interval.tick().await; // Skip first immediate tick

        // Main event loop for this peer
        loop {
            tokio::select! {
                // Read messages from peer
                result = read_bgp_message(&mut reader) => {
                    match result {
                        Ok(message) => {
                            // RFC 4271: Only restart hold timer on KEEPALIVE or UPDATE
                            let is_keepalive_or_update = matches!(&message, BgpMessage::KeepAlive(_) | BgpMessage::Update(_));
                            let is_notification = matches!(&message, BgpMessage::Notification(_));

                            // Process message with peer
                            let delta = match peer.process_message(message).await {
                                Ok(delta) => delta,
                                Err(e) => {
                                    error!("failed to process message", "peer_ip" => &peer_ip, "error" => e.to_string());
                                    None
                                }
                            };

                            // RFC 4271: Restart hold timer on KEEPALIVE or UPDATE
                            if is_keepalive_or_update {
                                last_keepalive_or_update = tokio::time::Instant::now();
                            }

                            // Register with server once we reach Established state
                            if !peer_registered && peer.state() == BgpState::Established {
                                let handle = PeerHandle {
                                    addr: peer_ip.clone(),
                                    asn: peer_asn,
                                    state: BgpState::Established,
                                    statistics: peer.statistics.clone(),
                                    message_tx: message_tx.clone(),
                                };

                                if let Err(e) = server_op_tx.send(ServerOp::PeerEstablished {
                                    peer_ip: peer_ip.clone(),
                                    asn: peer_asn,
                                    handle,
                                }) {
                                    error!("failed to register peer with server", "peer_ip" => &peer_ip, "error" => e.to_string());
                                    break;
                                }
                                peer_registered = true;
                            }

                            // Send RIB update to server if we have route changes
                            if let Some((withdrawn, announced)) = delta {
                                if let Err(e) = server_op_tx.send(ServerOp::PeerUpdate {
                                    peer_ip: peer_ip.clone(),
                                    withdrawn,
                                    announced,
                                }) {
                                    error!("failed to send RIB update to server", "peer_ip" => &peer_ip, "error" => e.to_string());
                                    break;
                                }
                            }

                            // If notification received, break the loop
                            if is_notification {
                                break;
                            }
                        }
                        Err(e) => {
                            error!("error reading message from peer", "peer_ip" => &peer_ip, "error" => format!("{:?}", e));
                            break;
                        }
                    }
                }

                // Receive messages from server (route updates to send to peer)
                Some(msg) = message_rx.recv() => {
                    match msg {
                        PeerMessage::SendUpdate(update_msg) => {
                            if let Err(e) = peer.send_update(update_msg).await {
                                error!("failed to send UPDATE to peer", "peer_ip" => &peer_ip, "error" => e.to_string());
                                break;
                            }
                        }
                    }
                }

                // RFC 4271: Check if hold timer expired (no KEEPALIVE/UPDATE received)
                _ = hold_check_interval.tick() => {
                    if last_keepalive_or_update.elapsed() > hold_timeout {
                        error!("hold timer expired (no KEEPALIVE or UPDATE received)", "peer_ip" => &peer_ip);
                        break;
                    }
                }

                // Periodic KEEPALIVE check
                _ = async {
                    match &mut keepalive_interval {
                        Some(interval) => interval.tick().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if peer.fsm.timers.keepalive_timer_expired() {
                        if let Err(e) = peer.process_event(&BgpEvent::KeepaliveTimerExpires).await {
                            error!("failed to send keepalive", "peer_ip" => &peer_ip, "error" => e.to_string());
                            break;
                        }
                    }
                }
            }
        }

        // Notify server that peer disconnected
        let _ = server_op_tx.send(ServerOp::PeerDisconnected {
            peer_ip: peer_ip.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn create_test_peer_with_state(state: BgpState) -> Peer {
        // Create a test TCP connection
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (_, tcp_tx) = client.into_split();

        let mut peer = Peer::new(addr.ip().to_string(), tcp_tx, 65001, SessionType::Ebgp);
        peer.fsm = Fsm::with_state(state);
        peer
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
    async fn test_is_established() {
        let peer = create_test_peer_with_state(BgpState::Idle).await;
        assert!(!peer.is_established());

        let peer = create_test_peer_with_state(BgpState::Connect).await;
        assert!(!peer.is_established());

        let peer = create_test_peer_with_state(BgpState::OpenSent).await;
        assert!(!peer.is_established());

        let peer = create_test_peer_with_state(BgpState::Established).await;
        assert!(peer.is_established());
    }
}
