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
use crate::fsm::{BgpState, Fsm, FsmEvent};
use crate::rib::rib_in::AdjRibIn;
use crate::rib::{Path, RouteSource};
use crate::server::ServerOp;
use crate::{debug, error, info, warn};
use std::io;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};

// Operations that can be sent to a peer task
pub enum PeerOp {
    SendUpdate(UpdateMessage),
    GetStatistics(oneshot::Sender<PeerStatistics>),
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

pub struct Peer {
    pub addr: String,
    pub fsm: Fsm,
    pub asn: u16,
    pub rib_in: AdjRibIn,
    pub session_type: SessionType,
    pub statistics: PeerStatistics,
    pub tcp_tx: OwnedWriteHalf,
    tcp_rx: OwnedReadHalf,
    peer_rx: mpsc::UnboundedReceiver<PeerOp>,
    server_tx: mpsc::UnboundedSender<ServerOp>,
}

impl Peer {
    /// Create a new Peer with complete information and complete handshake
    /// Returns (Peer, sender) where sender is used to send operations to this peer
    /// The Peer is returned in OpenConfirm state, ready to run
    pub async fn new(
        addr: String,
        asn: u16,
        session_type: SessionType,
        tcp_tx: OwnedWriteHalf,
        tcp_rx: OwnedReadHalf,
        server_tx: mpsc::UnboundedSender<ServerOp>,
        peer_hold_time: u16,
        local_hold_time: u16,
    ) -> Result<(Self, mpsc::UnboundedSender<PeerOp>), io::Error> {
        let (peer_tx, peer_rx) = mpsc::unbounded_channel();

        let mut peer = Peer {
            addr: addr.clone(),
            fsm: Fsm::with_state(BgpState::OpenSent),
            tcp_tx,
            tcp_rx,
            asn,
            rib_in: AdjRibIn::new(addr),
            session_type,
            statistics: PeerStatistics::default(),
            peer_rx,
            server_tx,
        };

        // Track that we sent and received OPEN (these happened in perform_handshake)
        peer.statistics.open_sent += 1;
        peer.statistics.open_received += 1;

        // Process receiving peer's OPEN (sends KEEPALIVE and transitions to OpenConfirm)
        // This performs hold time negotiation and sets up FSM timers
        peer.handle_fsm_event(&FsmEvent::BgpOpenReceived {
            peer_asn: asn,
            peer_hold_time,
            local_hold_time,
        })
        .await?;

        Ok((peer, peer_tx))
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
    async fn handle_message(
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
            BgpMessage::Update(_) => Some(FsmEvent::BgpUpdateReceived),
            BgpMessage::KeepAlive(_) => Some(FsmEvent::BgpKeepaliveReceived),
            BgpMessage::Notification(_) => Some(FsmEvent::NotificationReceived),
        };

        // Process FSM event if present
        if let Some(event) = event {
            self.handle_fsm_event(&event).await?;
        }

        // Process UPDATE message content
        if let BgpMessage::Update(update_msg) = message {
            Ok(Some(self.handle_update(update_msg)))
        } else {
            Ok(None)
        }
    }

    /// Handle an FSM event and perform state transitions
    pub async fn handle_fsm_event(&mut self, event: &FsmEvent) -> Result<(), io::Error> {
        let old_state = self.fsm.state();
        let new_state = self.fsm.handle_event(event);

        // Handle state-specific actions based on transitions
        match (old_state, new_state, event) {
            // Entering OpenSent - send OPEN message
            (
                BgpState::Connect,
                BgpState::OpenSent,
                FsmEvent::TcpConnectionConfirmed {
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
                FsmEvent::BgpOpenReceived {
                    peer_asn: _,
                    peer_hold_time,
                    local_hold_time,
                },
            ) => {
                // Negotiate hold time: RFC 4271 says use minimum
                let hold_time = (*local_hold_time).min(*peer_hold_time);

                self.fsm.timers.reset_hold_timer();
                self.fsm.timers.set_negotiated_hold_time(hold_time);
                let keepalive_msg = KeepAliveMessage {};
                self.tcp_tx.write_all(&keepalive_msg.serialize()).await?;
                self.statistics.keepalive_sent += 1;
                debug!("sent KEEPALIVE message", "peer_ip" => &self.addr);
                self.fsm.timers.start_keepalive_timer();
            }

            // In OpenConfirm or Established - handle keepalive timer expiry
            (_, BgpState::OpenConfirm, FsmEvent::KeepaliveTimerExpires)
            | (_, BgpState::Established, FsmEvent::KeepaliveTimerExpires) => {
                let keepalive_msg = KeepAliveMessage {};
                self.tcp_tx.write_all(&keepalive_msg.serialize()).await?;
                self.statistics.keepalive_sent += 1;
                debug!("sent KEEPALIVE message", "peer_ip" => &self.addr);
                self.fsm.timers.start_keepalive_timer();
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

            _ => {}
        }

        Ok(())
    }

    /// Handle a BGP UPDATE message
    /// Returns (withdrawn_prefixes, announced_routes) - only what changed in THIS update
    pub fn handle_update(
        &mut self,
        update_msg: UpdateMessage,
    ) -> (Vec<IpNetwork>, Vec<(IpNetwork, Path)>) {
        let withdrawn = self.process_withdrawals(&update_msg);
        let announced = self.process_announcements(&update_msg);
        (withdrawn, announced)
    }

    /// Process withdrawn routes from an UPDATE message
    fn process_withdrawals(&mut self, update_msg: &UpdateMessage) -> Vec<IpNetwork> {
        let mut withdrawn = Vec::new();
        for prefix in update_msg.withdrawn_routes() {
            info!("withdrawing route", "prefix" => format!("{:?}", prefix), "peer_ip" => &self.addr);
            self.rib_in.remove_route(*prefix);
            withdrawn.push(*prefix);
        }
        withdrawn
    }

    /// Process announced routes (NLRI) from an UPDATE message
    fn process_announcements(&mut self, update_msg: &UpdateMessage) -> Vec<(IpNetwork, Path)> {
        let mut announced = Vec::new();

        // Extract path attributes for announced routes
        let origin = update_msg.get_origin();
        let as_path = update_msg.get_as_path();
        let next_hop = update_msg.get_next_hop();

        // Only process announcements if we have required attributes
        if let (Some(origin), Some(as_path), Some(next_hop)) = (origin, as_path, next_hop) {
            let source = RouteSource::from_session(self.session_type, self.addr.clone());

            // Process announced routes (NLRI)
            for prefix in update_msg.nlri_list() {
                let path = Path::from_attributes(origin, as_path.clone(), next_hop, source.clone());
                info!("adding route to Adj-RIB-In", "prefix" => format!("{:?}", prefix), "peer_ip" => &self.addr);
                self.rib_in.add_route(*prefix, path.clone());
                announced.push((*prefix, path));
            }
        } else if !update_msg.nlri_list().is_empty() {
            warn!("UPDATE has NLRI but missing required attributes, skipping announcements", "peer_ip" => &self.addr);
        }

        announced
    }

    /// Send UPDATE message and reset keepalive timer (RFC 4271 requirement)
    async fn send_update(&mut self, update_msg: UpdateMessage) -> Result<(), io::Error> {
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

    /// Main peer task - handles the full lifecycle of a BGP peer connection after handshake
    pub async fn run(mut self) {
        let peer_ip = self.addr.clone();

        debug!("starting peer event loop", "peer_ip" => &peer_ip);

        // Extract the negotiated hold time from FSM timers (already set during Peer::new)
        let hold_time = self.fsm.timers.hold_time.as_secs() as u16;

        // Create keepalive interval timer (RFC 4271)
        let mut keepalive_interval = if hold_time > 0 {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // Skip first immediate tick
            Some(interval)
        } else {
            None
        };

        // RFC 4271: Hold timer - track last KEEPALIVE or UPDATE received
        let hold_timeout = tokio::time::Duration::from_secs(hold_time as u64);
        let mut last_keepalive_or_update = tokio::time::Instant::now();

        // Check hold timer every 500ms
        let mut hold_check_interval =
            tokio::time::interval(tokio::time::Duration::from_millis(500));
        hold_check_interval.tick().await; // Skip first immediate tick

        // Main event loop for this peer
        loop {
            tokio::select! {
                // Read messages from peer
                result = read_bgp_message(&mut self.tcp_rx) => {
                    match result {
                        Ok(message) => {
                            // RFC 4271: Only restart hold timer on KEEPALIVE or UPDATE
                            let is_keepalive_or_update = matches!(&message, BgpMessage::KeepAlive(_) | BgpMessage::Update(_));
                            let is_notification = matches!(&message, BgpMessage::Notification(_));

                            // Process message with peer
                            let delta = match self.handle_message(message).await {
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

                            // Notify server of state change if we reached Established
                            if self.state() == BgpState::Established {
                                if let Err(e) = self.server_tx.send(ServerOp::PeerStateChanged {
                                    peer_ip: peer_ip.clone(),
                                    state: BgpState::Established,
                                }) {
                                    error!("failed to notify server of state change", "peer_ip" => &peer_ip, "error" => e.to_string());
                                    break;
                                }
                            }

                            // Send RIB update to server if we have route changes
                            if let Some((withdrawn, announced)) = delta {
                                if let Err(e) = self.server_tx.send(ServerOp::PeerUpdate {
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
                Some(msg) = self.peer_rx.recv() => {
                    match msg {
                        PeerOp::SendUpdate(update_msg) => {
                            if let Err(e) = self.send_update(update_msg).await {
                                error!("failed to send UPDATE to peer", "peer_ip" => &peer_ip, "error" => e.to_string());
                                break;
                            }
                        }
                        PeerOp::GetStatistics(response) => {
                            let _ = response.send(self.statistics.clone());
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
                    if self.fsm.timers.keepalive_timer_expired() {
                        if let Err(e) = self.handle_fsm_event(&FsmEvent::KeepaliveTimerExpires).await {
                            error!("failed to send keepalive", "peer_ip" => &peer_ip, "error" => e.to_string());
                            break;
                        }
                    }
                }
            }
        }

        // Notify server that peer disconnected
        let _ = self.server_tx.send(ServerOp::PeerDisconnected {
            peer_ip: peer_ip.clone(),
        });
    }
}

/// Perform BGP OPEN handshake and return peer information
/// Returns (peer_asn, peer_hold_time, session_type)
pub async fn perform_handshake(
    peer_ip: &str,
    tcp_rx: &mut OwnedReadHalf,
    tcp_tx: &mut OwnedWriteHalf,
    local_asn: u16,
    local_hold_time: u16,
    local_bgp_id: u32,
) -> Result<(u16, u16, SessionType), io::Error> {
    debug!("starting BGP handshake", "peer_ip" => peer_ip);

    // Send OPEN message to peer
    let open_msg = OpenMessage::new(local_asn, local_hold_time, local_bgp_id);
    tcp_tx.write_all(&open_msg.serialize()).await?;
    info!("sent OPEN message", "peer_ip" => peer_ip);

    // Wait for peer's OPEN message
    let (peer_asn, peer_hold_time) = loop {
        let result = read_bgp_message(tcp_rx).await;

        match result {
            Ok(message) => match message {
                BgpMessage::Open(open_msg) => {
                    info!("received OPEN from peer", "peer_ip" => peer_ip, "asn" => open_msg.asn, "hold_time" => open_msg.hold_time, "bgp_identifier" => open_msg.bgp_identifier);
                    break (open_msg.asn, open_msg.hold_time);
                }
                _ => {
                    error!("expected OPEN as first message", "peer_ip" => peer_ip);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "expected OPEN message",
                    ));
                }
            },
            Err(e) => {
                error!("error reading first message from peer", "peer_ip" => peer_ip, "error" => format!("{:?}", e));
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to read BGP message: {:?}", e),
                ));
            }
        }
    };

    // Determine session type
    let session_type = if peer_asn == local_asn {
        SessionType::Ibgp
    } else {
        SessionType::Ebgp
    };

    info!("BGP handshake complete", "peer_ip" => peer_ip, "peer_asn" => peer_asn, "session_type" => format!("{:?}", session_type), "peer_hold_time" => peer_hold_time);

    Ok((peer_asn, peer_hold_time, session_type))
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
        let (tcp_rx, tcp_tx) = client.into_split();

        // Create dummy channels for testing
        let (server_tx, _server_rx) = mpsc::unbounded_channel();
        let (_peer_tx, peer_rx) = mpsc::unbounded_channel();

        // Create peer directly for testing (bypass Peer::new which does handshake)
        Peer {
            addr: addr.ip().to_string(),
            fsm: Fsm::with_state(state),
            tcp_tx,
            tcp_rx,
            asn: 65001,
            rib_in: AdjRibIn::new(addr.ip().to_string()),
            session_type: SessionType::Ebgp,
            statistics: PeerStatistics::default(),
            peer_rx,
            server_tx,
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
