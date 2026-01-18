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

use super::fsm::{BgpOpenParams, FsmEvent};
use crate::bgp::msg::{BgpMessage, Message};
use crate::bgp::msg_keepalive::KeepaliveMessage;
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::msg_open_types::{
    BgpCapabiltyCode, Capability, OptionalParam, OptionalParamTypes, ParamVal,
};
use crate::bgp::msg_update::UpdateMessage;
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::net::IpNetwork;
use crate::rib::Path;
use crate::server::ServerOp;
use crate::{debug, info, warn};
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use super::{Peer, SessionType};

/// Default local capabilities to advertise
fn default_local_capabilities() -> Vec<AfiSafi> {
    vec![
        AfiSafi::new(Afi::Ipv4, Safi::Unicast),
        AfiSafi::new(Afi::Ipv6, Safi::Unicast),
    ]
}

/// Convert AfiSafi to capability bytes
/// Format: [AFI_HIGH, AFI_LOW, RESERVED, SAFI]
fn afi_safi_to_capability_bytes(afi_safi: &AfiSafi) -> Vec<u8> {
    let afi_bytes = (afi_safi.afi as u16).to_be_bytes();
    vec![afi_bytes[0], afi_bytes[1], 0x00, afi_safi.safi as u8]
}

/// Extract multiprotocol capabilities from OPEN message
fn extract_capabilities(open_msg: &OpenMessage) -> Vec<AfiSafi> {
    let mut capabilities = Vec::new();

    for param in &open_msg.optional_params {
        if let ParamVal::Capability(cap) = &param.param_value {
            if cap.code == BgpCapabiltyCode::Multiprotocol {
                if let Ok(afi_safi) = AfiSafi::from_capability_bytes(&cap.val) {
                    capabilities.push(afi_safi);
                }
            }
        }
    }

    capabilities
}

/// Create an OPEN message with multiprotocol capabilities
fn create_open_message(asn: u16, hold_time: u16, router_id: Ipv4Addr) -> OpenMessage {
    // Create multiprotocol capabilities
    let local_capabilities = default_local_capabilities();
    let mut optional_params = Vec::new();

    for afi_safi in local_capabilities {
        let cap_bytes = afi_safi_to_capability_bytes(&afi_safi);
        let capability = Capability {
            code: BgpCapabiltyCode::Multiprotocol,
            len: cap_bytes.len() as u8,
            val: cap_bytes,
        };
        optional_params.push(OptionalParam {
            param_type: OptionalParamTypes::Capabilities,
            param_len: 2 + capability.len, // code(1) + len(1) + val
            param_value: ParamVal::Capability(capability),
        });
    }

    // Calculate total optional params length
    let optional_params_len = optional_params
        .iter()
        .map(|p| 2 + p.param_len as usize) // type(1) + len(1) + value
        .sum::<usize>() as u8;

    OpenMessage {
        version: 4,
        asn,
        hold_time,
        bgp_identifier: u32::from(router_id),
        optional_params_len,
        optional_params,
    }
}

impl Peer {
    /// Send OPEN message to peer.
    pub(super) async fn send_open(&mut self) -> Result<(), io::Error> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no TCP connection"))?;
        let open_msg = create_open_message(
            self.fsm.local_asn(),
            self.fsm.local_hold_time(),
            Ipv4Addr::from(self.fsm.local_bgp_id()),
        );
        self.sent_open = Some(open_msg.clone());
        conn.tx.write_all(&open_msg.serialize()).await?;
        self.statistics.open_sent += 1;
        info!(&self.logger, "sent OPEN message", "peer_ip" => self.addr.to_string());
        Ok(())
    }

    /// Handle entering OpenConfirm state - negotiate timers, send KEEPALIVE, notify server
    pub(super) async fn enter_open_confirm(
        &mut self,
        peer_asn: u16,
        peer_hold_time: u16,
        local_asn: u16,
        local_hold_time: u16,
        peer_capabilities: Vec<AfiSafi>,
    ) -> Result<(), io::Error> {
        // Set peer ASN and determine session type
        self.asn = Some(peer_asn);
        self.session_type = Some(if peer_asn == local_asn {
            SessionType::Ibgp
        } else {
            SessionType::Ebgp
        });

        // Negotiate multiprotocol capabilities (intersection of local and peer)
        let local_capabilities = default_local_capabilities();
        let local_set: HashSet<_> = local_capabilities.into_iter().collect();
        let peer_set: HashSet<_> = peer_capabilities.into_iter().collect();
        self.negotiated_capabilities = local_set.intersection(&peer_set).copied().collect();

        info!(&self.logger, "negotiated capabilities",
              "capabilities" => format!("{:?}", self.negotiated_capabilities),
              "peer_ip" => self.addr.to_string());

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

        info!(&self.logger, "timers initialized", "peer_ip" => self.addr.to_string(), "hold_time" => hold_time);

        // Notify server that handshake is complete
        let _ = self.server_tx.send(ServerOp::PeerHandshakeComplete {
            peer_ip: self.addr,
            asn: peer_asn,
        });

        Ok(())
    }

    /// Send KEEPALIVE message and restart keepalive timer
    pub(super) async fn send_keepalive(&mut self) -> Result<(), io::Error> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no TCP connection"))?;
        let keepalive_msg = KeepaliveMessage {};
        conn.tx.write_all(&keepalive_msg.serialize()).await?;
        self.statistics.keepalive_sent += 1;
        debug!(&self.logger, "sent KEEPALIVE message", "peer_ip" => self.addr.to_string());
        // RFC 4271: Restart KeepaliveTimer unless negotiated HoldTime is zero
        if self.fsm.timers.hold_time.as_secs() > 0 {
            self.fsm.timers.start_keepalive_timer();
        }
        Ok(())
    }

    /// Send NOTIFICATION message (RFC 4271 Section 6.1)
    ///
    /// RFC 4271 8.2.1.5: SendNOTIFICATIONwithoutOPEN controls whether NOTIFICATION
    /// can be sent before OPEN. If disabled (default), NOTIFICATION is only sent
    /// after OPEN has been sent.
    pub(super) async fn send_notification(
        &mut self,
        notif_msg: NotificationMessage,
    ) -> Result<(), io::Error> {
        if !self.can_send_notification() {
            warn!(&self.logger, "skipping NOTIFICATION", "peer_ip" => self.addr.to_string(), "error" => format!("{:?}", notif_msg.error()));
            return Ok(());
        }
        // Safe: can_send_notification checks conn.is_some()
        let conn = self.conn.as_mut().unwrap();
        conn.tx.write_all(&notif_msg.serialize()).await?;
        self.statistics.notification_sent += 1;
        warn!(&self.logger, "sent NOTIFICATION", "peer_ip" => self.addr.to_string(), "error" => format!("{:?}", notif_msg.error()));
        Ok(())
    }

    /// Process a received BGP message from the TCP stream
    /// Returns Err if should disconnect (notification or processing error)
    pub(super) async fn handle_received_message(
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
                // RFC 4271: Reset HoldTimer if negotiated HoldTime is non-zero
                if self.fsm.timers.hold_time.as_secs() > 0 {
                    self.fsm.timers.reset_hold_timer();
                }

                if let Some((withdrawn, announced)) = delta {
                    let _ = self.server_tx.send(ServerOp::PeerUpdate {
                        peer_ip,
                        withdrawn,
                        announced,
                    });
                }
                Ok(())
            }
            BgpMessage::Keepalive(_) => {
                let _ = self.handle_message(message).await;
                // RFC 4271: Reset HoldTimer if negotiated HoldTime is non-zero
                if self.fsm.timers.hold_time.as_secs() > 0 {
                    self.fsm.timers.reset_hold_timer();
                }
                Ok(())
            }
            BgpMessage::Open(_) => {
                let _ = self.handle_message(message).await;
                Ok(())
            }
            BgpMessage::RouteRefresh(_) => {
                let _ = self.handle_message(message).await;
                Ok(())
            }
        }
    }

    /// Track statistics for received BGP messages
    fn track_received_message(&mut self, message: &BgpMessage) {
        match message {
            BgpMessage::Open(open_msg) => {
                self.statistics.open_received += 1;
                info!(&self.logger, "received OPEN from peer", "peer_ip" => self.addr.to_string(), "asn" => open_msg.asn, "hold_time" => open_msg.hold_time);
            }
            BgpMessage::Update(_) => {
                self.statistics.update_received += 1;
                info!(&self.logger, "received UPDATE", "peer_ip" => self.addr.to_string());
            }
            BgpMessage::Keepalive(_) => {
                self.statistics.keepalive_received += 1;
                debug!(&self.logger, "received KEEPALIVE", "peer_ip" => self.addr.to_string());
            }
            BgpMessage::Notification(notif_msg) => {
                self.statistics.notification_received += 1;
                warn!(&self.logger, "received NOTIFICATION", "peer_ip" => self.addr.to_string(), "notification" => format!("{:?}", notif_msg));
            }
            BgpMessage::RouteRefresh(msg) => {
                self.statistics.route_refresh_received += 1;
                info!(&self.logger, "received ROUTE_REFRESH", "peer_ip" => self.addr.to_string(), "afi" => format!("{:?}", msg.afi), "safi" => format!("{:?}", msg.safi));
            }
        }
    }

    /// Process a BGP message and return route changes for Loc-RIB update if applicable
    /// Returns (withdrawn_prefixes, announced_routes) or None if not an UPDATE
    pub(super) async fn handle_message(
        &mut self,
        message: BgpMessage,
    ) -> Result<Option<(Vec<IpNetwork>, Vec<(IpNetwork, Arc<Path>)>)>, io::Error> {
        self.track_received_message(&message);

        // Process FSM event
        match &message {
            BgpMessage::Open(open_msg) => {
                // Store received OPEN for BMP PeerUp
                self.received_open = Some(open_msg.clone());

                // RFC 4271 6.8: Notify server for collision detection
                let _ = self.server_tx.send(ServerOp::OpenReceived {
                    peer_ip: self.addr,
                    bgp_id: open_msg.bgp_identifier,
                    conn_type: self.conn_type,
                });

                // Extract multiprotocol capabilities from OPEN message
                let peer_capabilities = extract_capabilities(open_msg);

                self.process_event(&FsmEvent::BgpOpenReceived(BgpOpenParams {
                    peer_asn: open_msg.asn,
                    peer_hold_time: open_msg.hold_time,
                    peer_bgp_id: open_msg.bgp_identifier,
                    local_asn: self.fsm.local_asn(),
                    local_hold_time: self.fsm.local_hold_time(),
                    peer_capabilities,
                }))
                .await?;
            }
            BgpMessage::Update(_) => {
                self.process_event(&FsmEvent::BgpUpdateReceived).await?;
            }
            BgpMessage::Keepalive(_) => {
                self.process_event(&FsmEvent::BgpKeepaliveReceived).await?;
            }
            BgpMessage::Notification(notif) => {
                self.handle_notification_received(notif).await;
                return Ok(None);
            }
            BgpMessage::RouteRefresh(msg) => {
                self.handle_route_refresh(msg.afi, msg.safi).await;
                return Ok(None);
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
                        .await?;
                        Ok(None)
                    } else {
                        warn!(&self.logger, "max prefix exceeded but allow_automatic_stop=false, continuing",
                              "peer_ip" => self.addr.to_string());
                        Ok(None)
                    }
                }
                Err(bgp_error) => {
                    // RFC 4271 Event 28: UpdateMsgErr
                    let notif = NotificationMessage::new(bgp_error, vec![]);
                    self.process_event(&FsmEvent::BgpUpdateMsgErr(notif))
                        .await?;
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Handle received ROUTE_REFRESH message
    async fn handle_route_refresh(&mut self, afi: Afi, safi: Safi) {
        // Validate against negotiated capabilities
        let requested = AfiSafi::new(afi, safi);
        if !self.negotiated_capabilities.contains(&requested) {
            warn!(&self.logger, "ROUTE_REFRESH for non-negotiated AFI/SAFI",
                  "peer_ip" => self.addr.to_string(),
                  "afi" => format!("{:?}", afi),
                  "safi" => format!("{:?}", safi));
            return;
        }

        // Send to server to trigger route re-advertisement
        let _ = self.server_tx.send(ServerOp::RouteRefresh {
            peer_ip: self.addr,
            afi,
            safi,
        });
    }

    /// Send UPDATE message and reset keepalive timer (RFC 4271 requirement)
    pub(super) async fn send_update(&mut self, update_msg: UpdateMessage) -> Result<(), io::Error> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no TCP connection"))?;
        conn.tx.write_all(&update_msg.serialize()).await?;
        self.statistics.update_sent += 1;
        // RFC 4271: "Each time the local system sends a KEEPALIVE or UPDATE message,
        // it restarts its KeepaliveTimer, unless the negotiated HoldTime value is zero"
        if self.fsm.timers.hold_time.as_secs() > 0 {
            self.fsm.timers.reset_keepalive_timer();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg::Message;
    use crate::bgp::msg_update::{
        AsPathSegment, AsPathSegmentType, NextHopAddr, Origin, UpdateMessage,
    };
    use crate::peer::fsm::BgpState;
    use std::net::Ipv4Addr;

    #[test]
    fn test_afi_safi_to_capability_bytes() {
        let cases = vec![
            (
                AfiSafi::new(Afi::Ipv4, Safi::Unicast),
                vec![0x00, 0x01, 0x00, 0x01],
            ),
            (
                AfiSafi::new(Afi::Ipv6, Safi::Unicast),
                vec![0x00, 0x02, 0x00, 0x01],
            ),
            (
                AfiSafi::new(Afi::Ipv4, Safi::Multicast),
                vec![0x00, 0x01, 0x00, 0x02],
            ),
        ];

        for (afi_safi, expected_bytes) in cases {
            let bytes = afi_safi_to_capability_bytes(&afi_safi);
            assert_eq!(bytes, expected_bytes, "{:?}", afi_safi);
        }
    }

    #[test]
    fn test_extract_capabilities() {
        let open_msg = create_open_message(65001, 180, Ipv4Addr::new(1, 1, 1, 1));
        let capabilities = extract_capabilities(&open_msg);

        assert_eq!(capabilities.len(), 2);
        assert!(capabilities.contains(&AfiSafi::new(Afi::Ipv4, Safi::Unicast)));
        assert!(capabilities.contains(&AfiSafi::new(Afi::Ipv6, Safi::Unicast)));
    }

    #[tokio::test]
    async fn test_capability_negotiation_intersection() {
        use std::collections::HashSet;

        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        let ipv4_multicast = AfiSafi::new(Afi::Ipv4, Safi::Multicast);
        let ipv6_unicast = AfiSafi::new(Afi::Ipv6, Safi::Unicast);

        // (local_caps, peer_caps, expected_negotiated)
        let cases = vec![
            (vec![ipv4_unicast], vec![ipv4_unicast], vec![ipv4_unicast]),
            (
                vec![ipv4_unicast],
                vec![ipv4_unicast, ipv4_multicast],
                vec![ipv4_unicast],
            ),
            (vec![ipv4_unicast], vec![ipv6_unicast], vec![]),
            (
                vec![ipv4_unicast, ipv6_unicast],
                vec![ipv4_unicast, ipv6_unicast],
                vec![ipv4_unicast, ipv6_unicast],
            ),
            (
                vec![ipv4_unicast, ipv6_unicast],
                vec![ipv4_unicast],
                vec![ipv4_unicast],
            ),
        ];

        for (local_caps, peer_caps, expected) in cases {
            let local_set: HashSet<_> = local_caps.iter().copied().collect();
            let peer_set: HashSet<_> = peer_caps.iter().copied().collect();
            let negotiated: HashSet<_> = local_set.intersection(&peer_set).copied().collect();
            let expected_set: HashSet<_> = expected.iter().copied().collect();

            assert_eq!(
                negotiated, expected_set,
                "local={:?} peer={:?}",
                local_caps, peer_caps
            );
        }
    }

    #[test]
    fn test_admin_shutdown_notification() {
        let notif = NotificationMessage::new(
            BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
            Vec::new(),
        );
        let bytes = notif.to_bytes();
        assert_eq!(bytes[0], 6); // Cease error code
        assert_eq!(bytes[1], 2); // AdministrativeShutdown subcode
        assert_eq!(bytes.len(), 2); // No data
    }

    #[tokio::test]
    async fn test_update_rejected_in_non_established_states() {
        // RFC 4271 Section 9: "An UPDATE message may be received only in the Established state.
        // Receiving an UPDATE message in any other state is an error."
        use crate::peer::states::tests::create_test_peer_with_state;

        let non_established_states = vec![
            BgpState::Connect,
            BgpState::Active,
            BgpState::OpenSent,
            BgpState::OpenConfirm,
        ];

        for state in non_established_states {
            let mut peer = create_test_peer_with_state(state).await;
            peer.config.send_notification_without_open = true;

            let update = UpdateMessage::new(
                Origin::IGP,
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                vec![],
                None,
                None,
                false,
                vec![],
                vec![],
                vec![],
            );

            let result = peer.handle_message(BgpMessage::Update(update)).await;

            assert!(
                result.is_err(),
                "UPDATE should cause error in {:?} state",
                state
            );
            assert_eq!(
                peer.state(),
                BgpState::Idle,
                "Peer should transition to Idle after UPDATE in {:?}",
                state
            );
            assert_eq!(
                peer.statistics.notification_sent, 1,
                "FSM error NOTIFICATION should be sent in {:?}",
                state
            );
        }
    }

    #[tokio::test]
    async fn test_update_accepted_in_established() {
        // RFC 4271 Section 9: UPDATE is processed normally in Established state
        use crate::peer::states::tests::create_test_peer_with_state;

        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.timers.start_hold_timer();

        let update = UpdateMessage::new(
            Origin::IGP,
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65001],
            }],
            NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            vec![],
            None,
            None,
            false,
            vec![],
            vec![],
            vec![],
        );

        let result = peer.handle_message(BgpMessage::Update(update)).await;

        assert!(
            result.is_ok(),
            "UPDATE should be accepted in Established state"
        );
        assert_eq!(
            peer.state(),
            BgpState::Established,
            "Peer should remain in Established state"
        );
        assert_eq!(
            peer.statistics.notification_sent, 0,
            "No NOTIFICATION should be sent for valid UPDATE"
        );
    }
}
