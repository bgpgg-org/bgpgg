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
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotifcationMessage, UpdateMessageError};
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::msg_update::UpdateMessage;
use crate::bgp::utils::IpNetwork;
use crate::fsm::{BgpState, Fsm, FsmEvent};
use crate::rib::rib_in::AdjRibIn;
use crate::rib::{Path, RouteSource};
use crate::server::ServerOp;
use crate::{debug, error, info, warn};
use std::io;
use std::net::Ipv4Addr;
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

/// Action to take when max prefix limit is reached
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxPrefixAction {
    /// Send CEASE notification and close the session
    Terminate,
    /// Discard new prefixes but keep the session
    Discard,
}

/// Max prefix limit configuration
#[derive(Debug, Clone, Copy)]
pub struct MaxPrefixSetting {
    pub limit: u32,
    pub action: MaxPrefixAction,
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
    pub asn: Option<u16>,
    pub rib_in: AdjRibIn,
    pub session_type: Option<SessionType>,
    pub statistics: PeerStatistics,
    pub max_prefix_setting: Option<MaxPrefixSetting>,
    pub tcp_tx: OwnedWriteHalf,
    tcp_rx: OwnedReadHalf,
    peer_rx: mpsc::UnboundedReceiver<PeerOp>,
    server_tx: mpsc::UnboundedSender<ServerOp>,
}

impl Peer {
    /// Create a new Peer in Connect state
    /// Returns (Peer, sender) where sender is used to send operations to this peer
    pub fn new(
        addr: String,
        tcp_tx: OwnedWriteHalf,
        tcp_rx: OwnedReadHalf,
        server_tx: mpsc::UnboundedSender<ServerOp>,
        local_asn: u16,
        local_hold_time: u16,
        local_bgp_id: u32,
        local_addr: Ipv4Addr,
        max_prefix_setting: Option<MaxPrefixSetting>,
    ) -> (Self, mpsc::UnboundedSender<PeerOp>) {
        let (peer_tx, peer_rx) = mpsc::unbounded_channel();

        let peer = Peer {
            addr: addr.clone(),
            fsm: Fsm::new(local_asn, local_hold_time, local_bgp_id, local_addr),
            tcp_tx,
            tcp_rx,
            asn: None,
            rib_in: AdjRibIn::new(addr),
            session_type: None,
            statistics: PeerStatistics::default(),
            max_prefix_setting,
            peer_rx,
            server_tx,
        };

        (peer, peer_tx)
    }

    /// Main peer task - handles the full lifecycle of a BGP peer connection after handshake
    pub async fn run(mut self) {
        let peer_ip = self.addr.clone();

        debug!("starting peer event loop", "peer_ip" => &peer_ip);

        // Fire TcpConnectionConfirmed to start handshake (Connect → OpenSent, sends OPEN)
        if let Err(e) = self
            .handle_fsm_event(&FsmEvent::TcpConnectionConfirmed)
            .await
        {
            error!("failed to start handshake", "peer_ip" => &peer_ip, "error" => e.to_string());
            let _ = self.server_tx.send(ServerOp::PeerDisconnected {
                peer_ip: peer_ip.clone(),
            });
            return;
        }

        // Interval for periodic timer checks (hold timer and keepalive timer)
        // Initialized lazily when hold_timeout is set (i.e., when entering OpenConfirm)
        let mut keepalive_check_interval: Option<tokio::time::Interval> = None;

        // Main event loop for this peer
        loop {
            tokio::select! {
                // Read messages from peer
                result = read_bgp_message(&mut self.tcp_rx) => {
                    match result {
                        Ok(message) => {
                            if let Err(e) = self.handle_received_message(message, &peer_ip).await {
                                error!("error processing message", "peer_ip" => &peer_ip, "error" => e.to_string());
                                break;
                            }

                            // Initialize interval when entering OpenConfirm (handshake complete)
                            if keepalive_check_interval.is_none() && self.state() == BgpState::OpenConfirm {
                                keepalive_check_interval = Some(tokio::time::interval(std::time::Duration::from_millis(500)));
                            }
                        }
                        Err(e) => {
                            error!("error reading message from peer", "peer_ip" => &peer_ip, "error" => format!("{:?}", e));

                            if let Some(notif) = NotifcationMessage::from_parser_error(&e) {
                                let _ = self.send_notification(notif).await;
                            }

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

                // Periodic timer checks (both hold timer and keepalive timer)
                _ = async {
                    match &mut keepalive_check_interval {
                        Some(interval) => interval.tick().await,
                        None => std::future::pending().await,
                    }
                } => {
                    // RFC 4271: Check if hold timer expired (no KEEPALIVE/UPDATE received)
                    if self.fsm.timers.hold_timer_expired() {
                        error!("hold timer expired (no KEEPALIVE or UPDATE received)", "peer_ip" => &peer_ip);
                        let notif = NotifcationMessage::new(BgpError::HoldTimerExpired, vec![]);
                        let _ = self.send_notification(notif).await;
                        break;
                    }

                    // Check if keepalive timer expired and needs to send KEEPALIVE
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

    /// Get current BGP state
    pub fn state(&self) -> BgpState {
        self.fsm.state()
    }

    /// Handle an FSM event and perform state transitions
    async fn handle_fsm_event(&mut self, event: &FsmEvent) -> Result<(), io::Error> {
        let old_state = self.fsm.state();
        let (new_state, fsm_error) = self.fsm.handle_event(event);

        // RFC 4271 6.6: Send NOTIFICATION for FSM errors
        if let Some(error) = fsm_error {
            let notif = NotifcationMessage::new(error, vec![]);
            let _ = self.send_notification(notif).await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FSM error: unexpected event",
            ));
        }

        // Handle state-specific actions based on transitions
        match (old_state, new_state, event) {
            // Entering OpenSent - send OPEN message
            (BgpState::Connect, BgpState::OpenSent, FsmEvent::TcpConnectionConfirmed) => {
                self.enter_open_sent().await?;
            }

            // Entering OpenConfirm - send KEEPALIVE
            (
                BgpState::OpenSent,
                BgpState::OpenConfirm,
                &FsmEvent::BgpOpenReceived {
                    peer_asn,
                    peer_hold_time,
                    local_asn,
                    local_hold_time,
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

            _ => {}
        }

        // Notify server of state change whenever state transitions occur
        if old_state != new_state {
            let _ = self.server_tx.send(ServerOp::PeerStateChanged {
                peer_ip: self.addr.clone(),
                state: new_state,
            });
        }

        Ok(())
    }

    /// Handle entering OpenSent state - send OPEN message
    async fn enter_open_sent(&mut self) -> Result<(), io::Error> {
        let open_msg = OpenMessage::new(
            self.fsm.local_asn(),
            self.fsm.local_hold_time(),
            self.fsm.local_bgp_id(),
        );
        self.tcp_tx.write_all(&open_msg.serialize()).await?;
        self.statistics.open_sent += 1;
        info!("sent OPEN message", "peer_ip" => &self.addr);
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
        self.fsm.timers.reset_hold_timer();
        self.fsm.timers.set_negotiated_hold_time(hold_time);

        // Send KEEPALIVE
        self.send_keepalive().await?;

        info!("timers initialized", "peer_ip" => &self.addr, "hold_time" => hold_time);

        // Notify server that handshake is complete
        let _ = self.server_tx.send(ServerOp::PeerHandshakeComplete {
            peer_ip: self.addr.clone(),
            asn: peer_asn,
        });

        Ok(())
    }

    /// Send KEEPALIVE message and restart keepalive timer
    async fn send_keepalive(&mut self) -> Result<(), io::Error> {
        let keepalive_msg = KeepAliveMessage {};
        self.tcp_tx.write_all(&keepalive_msg.serialize()).await?;
        self.statistics.keepalive_sent += 1;
        debug!("sent KEEPALIVE message", "peer_ip" => &self.addr);
        self.fsm.timers.start_keepalive_timer();
        Ok(())
    }

    /// Send NOTIFICATION message (RFC 4271 Section 6.1)
    async fn send_notification(&mut self, notif_msg: NotifcationMessage) -> Result<(), io::Error> {
        self.tcp_tx.write_all(&notif_msg.serialize()).await?;
        self.statistics.notification_sent += 1;
        warn!("sent NOTIFICATION", "peer_ip" => &self.addr, "error" => format!("{:?}", notif_msg.error()));
        Ok(())
    }

    /// Process a received BGP message from the TCP stream
    /// Returns Err if should disconnect (notification or processing error)
    async fn handle_received_message(
        &mut self,
        message: BgpMessage,
        peer_ip: &str,
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
                        peer_ip: peer_ip.to_string(),
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
        // Track received messages
        match &message {
            BgpMessage::Open(open_msg) => {
                self.statistics.open_received += 1;
                info!("received OPEN from peer", "peer_ip" => &self.addr, "asn" => open_msg.asn, "hold_time" => open_msg.hold_time);
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

        // Determine FSM event and process it - FSM will ignore if state doesn't match
        let event = match &message {
            BgpMessage::Open(open_msg) => Some(FsmEvent::BgpOpenReceived {
                peer_asn: open_msg.asn,
                peer_hold_time: open_msg.hold_time,
                local_asn: self.fsm.local_asn(),
                local_hold_time: self.fsm.local_hold_time(),
            }),
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
            match self.handle_update(update_msg) {
                Ok(delta) => Ok(Some(delta)),
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
                              "peer_ip" => &self.addr, "leftmost_as" => leftmost_as, "peer_asn" => peer_asn);
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
            info!("withdrawing route", "prefix" => format!("{:?}", prefix), "peer_ip" => &self.addr);
            self.rib_in.remove_route(*prefix);
            withdrawn.push(*prefix);
        }
        withdrawn
    }

    /// Process announced routes (NLRI) from an UPDATE message
    fn process_announcements(
        &mut self,
        update_msg: &UpdateMessage,
    ) -> Result<Vec<(IpNetwork, Path)>, BgpError> {
        let mut announced = Vec::new();

        // Check max prefix limit
        if let Some(setting) = self.max_prefix_setting {
            let current_count = self.rib_in.prefix_count();
            let new_prefixes = update_msg.nlri_list().len();

            if current_count + new_prefixes > setting.limit as usize {
                match setting.action {
                    MaxPrefixAction::Terminate => {
                        warn!("max prefix limit exceeded, terminating session",
                              "peer_ip" => &self.addr, "limit" => setting.limit, "current" => current_count);
                        return Err(BgpError::Cease(CeaseSubcode::MaxPrefixesReached));
                    }
                    MaxPrefixAction::Discard => {
                        warn!("max prefix limit reached, discarding new prefixes",
                              "peer_ip" => &self.addr, "limit" => setting.limit, "current" => current_count);
                        return Ok(announced);
                    }
                }
            }
        }

        // Extract path attributes for announced routes
        let origin = update_msg.get_origin();
        let as_path = update_msg.get_as_path();
        let next_hop = update_msg.get_next_hop();
        let local_pref = update_msg.get_local_pref();
        let med = update_msg.get_med();
        let atomic_aggregate = update_msg.get_atomic_aggregate();
        let unknown_attrs = update_msg.get_unknown_attrs();

        // Only process announcements if we have required attributes
        if let (Some(origin), Some(as_path), Some(next_hop)) = (origin, as_path, next_hop) {
            // RFC 4271 5.1.3(a): NEXT_HOP must not be receiving speaker's IP
            if next_hop == self.fsm.local_addr() {
                warn!("rejecting UPDATE: NEXT_HOP is local address",
                      "next_hop" => next_hop.to_string(), "peer" => &self.addr);
                return Ok(announced);
            }

            let source = RouteSource::from_session(
                self.session_type
                    .expect("session_type must be set in Established state"),
                self.addr.clone(),
            );

            // Process announced routes (NLRI)
            for prefix in update_msg.nlri_list() {
                let path = Path::from_attributes(
                    origin,
                    as_path.clone(),
                    next_hop,
                    source.clone(),
                    local_pref,
                    med,
                    atomic_aggregate,
                    unknown_attrs.clone(),
                );
                info!("adding route to Adj-RIB-In", "prefix" => format!("{:?}", prefix), "peer_ip" => &self.addr, "med" => format!("{:?}", med));
                self.rib_in.add_route(*prefix, path.clone());
                announced.push((*prefix, path));
            }
        } else if !update_msg.nlri_list().is_empty() {
            warn!("UPDATE has NLRI but missing required attributes, skipping announcements", "peer_ip" => &self.addr);
        }

        Ok(announced)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin, UpdateMessage};
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
        let local_addr = Ipv4Addr::new(127, 0, 0, 1);
        Peer {
            addr: addr.ip().to_string(),
            fsm: Fsm::with_state(state, 65000, 180, 0x01010101, local_addr),
            tcp_tx,
            tcp_rx,
            asn: Some(65001),
            rib_in: AdjRibIn::new(addr.ip().to_string()),
            session_type: Some(SessionType::Ebgp),
            statistics: PeerStatistics::default(),
            max_prefix_setting: None,
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
        let cases = vec![
            // (max_prefix_setting, num_prefixes, expected_ok, description)
            (None, 10, true, "no limit set"),
            (Some(MaxPrefixSetting { limit: 5, action: MaxPrefixAction::Terminate }), 3, true, "under limit"),
            (Some(MaxPrefixSetting { limit: 5, action: MaxPrefixAction::Terminate }), 5, true, "at limit"),
            (Some(MaxPrefixSetting { limit: 5, action: MaxPrefixAction::Terminate }), 6, false, "over limit terminate"),
            (Some(MaxPrefixSetting { limit: 5, action: MaxPrefixAction::Discard }), 6, true, "over limit discard"),
        ];

        for (setting, num_prefixes, expected_ok, desc) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.max_prefix_setting = setting;

            let nlri: Vec<_> = (0..num_prefixes)
                .map(|i| crate::bgp::utils::IpNetwork::V4(crate::bgp::utils::Ipv4Net {
                    address: Ipv4Addr::new(10, 0, i as u8, 0),
                    prefix_length: 24,
                }))
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
            assert_eq!(result.is_ok(), expected_ok, "case: {}", desc);

            if let Some(s) = setting {
                if s.action == MaxPrefixAction::Discard && num_prefixes > s.limit as usize {
                    assert_eq!(peer.rib_in.prefix_count(), 0, "discard should not add prefixes");
                }
            }
        }
    }
}
