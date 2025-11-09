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

use crate::bgp::msg::{BgpMessage, Message};
use crate::bgp::msg_keepalive::KeepAliveMessage;
use crate::bgp::msg_update::UpdateMessage;
use crate::bgp::utils::IpNetwork;
use crate::fsm::{BgpEvent, BgpState, Fsm};
use crate::rib::rib_in::AdjRibIn;
use crate::rib::Path;
use crate::{debug, info, warn};
use std::io;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;

/// Type of BGP session based on AS relationship
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    /// External BGP session (different AS)
    Ebgp,
    /// Internal BGP session (same AS)
    Ibgp,
}

pub struct Peer {
    pub addr: String,
    pub fsm: Fsm,
    pub tcp_tx: OwnedWriteHalf,
    pub asn: u16,
    pub rib_in: AdjRibIn,
    pub session_type: SessionType,
}

impl Peer {
    pub fn new(
        addr: String,
        tcp_tx: OwnedWriteHalf,
        asn: u16,
        session_type: SessionType,
    ) -> Self {
        Peer {
            addr: addr.clone(),
            fsm: Fsm::new(),
            tcp_tx,
            asn,
            rib_in: AdjRibIn::new(addr),
            session_type,
        }
    }

    /// Get current BGP state
    pub fn state(&self) -> BgpState {
        self.fsm.state()
    }

    /// Check if peer is established
    pub fn is_established(&self) -> bool {
        self.fsm.is_established()
    }

    /// Initialize the BGP connection after receiving OPEN
    pub async fn initialize_connection(&mut self) -> Result<(), io::Error> {
        // Process FSM events for connection establishment
        for event in &[
            BgpEvent::ManualStart,
            BgpEvent::TcpConnectionConfirmed,
            BgpEvent::BgpOpenReceived,
        ] {
            self.process_event(*event).await?;
        }
        Ok(())
    }

    /// Process a BGP message and return route changes for Loc-RIB update if applicable
    /// Returns (withdrawn_prefixes, announced_routes) or None if not an UPDATE
    pub async fn process_message(
        &mut self,
        message: BgpMessage,
    ) -> Result<Option<(Vec<IpNetwork>, Vec<(IpNetwork, Path)>)>, io::Error> {
        // Determine FSM event and process it
        let event = match &message {
            BgpMessage::Open(_) => {
                warn!("received duplicate OPEN, ignoring", "peer_ip" => &self.addr);
                None
            }
            BgpMessage::Update(_) => {
                info!("received UPDATE", "peer_ip" => &self.addr);
                Some(BgpEvent::BgpUpdateReceived)
            }
            BgpMessage::KeepAlive(_) => {
                debug!("received KEEPALIVE", "peer_ip" => &self.addr);
                Some(BgpEvent::BgpKeepaliveReceived)
            }
            BgpMessage::Notification(notif_msg) => {
                warn!("received NOTIFICATION", "peer_ip" => &self.addr, "notification" => format!("{:?}", notif_msg));
                Some(BgpEvent::NotificationReceived)
            }
        };

        // Process FSM event if present
        if let Some(event) = event {
            self.process_event(event).await?;
        }

        // Process UPDATE message content
        if let BgpMessage::Update(update_msg) = message {
            Ok(Some(self.process_update(update_msg)))
        } else {
            Ok(None)
        }
    }

    /// Process a BGP event and handle state transitions
    pub async fn process_event(&mut self, event: BgpEvent) -> Result<(), io::Error> {
        let old_state = self.fsm.state();
        let new_state = self.fsm.process_event(event);

        // Handle state-specific actions based on transitions
        match (old_state, new_state, event) {
            // Note: OPEN message is sent by the server before Peer is created,
            // so we don't send it here during FSM state transitions

            // Entering OpenConfirm - send KEEPALIVE
            (BgpState::OpenSent, BgpState::OpenConfirm, BgpEvent::BgpOpenReceived) => {
                self.fsm.timers.reset_hold_timer();
                let keepalive_msg = KeepAliveMessage {};
                self.tcp_tx.write_all(&keepalive_msg.serialize()).await?;
                debug!("sent KEEPALIVE message", "peer_ip" => &self.addr);
                self.fsm.timers.start_keepalive_timer();
            }

            // In OpenConfirm or Established - handle keepalive timer expiry
            (_, BgpState::OpenConfirm, BgpEvent::KeepaliveTimerExpires)
            | (_, BgpState::Established, BgpEvent::KeepaliveTimerExpires) => {
                let keepalive_msg = KeepAliveMessage {};
                self.tcp_tx.write_all(&keepalive_msg.serialize()).await?;
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
