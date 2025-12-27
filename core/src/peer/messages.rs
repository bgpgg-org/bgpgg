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
use crate::bgp::msg_keepalive::KeepAliveMessage;
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotifcationMessage};
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::msg_update::UpdateMessage;
use crate::bgp::utils::IpNetwork;
use crate::rib::Path;
use crate::server::ServerOp;
use crate::{debug, info, warn};
use std::io;
use std::net::IpAddr;
use tokio::io::AsyncWriteExt;

use super::{Peer, SessionType};

impl Peer {
    /// Send OPEN message to peer.
    pub(super) async fn send_open(&mut self) -> Result<(), io::Error> {
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
    pub(super) async fn enter_open_confirm(
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
    pub(super) async fn send_keepalive(&mut self) -> Result<(), io::Error> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no TCP connection"))?;
        let keepalive_msg = KeepAliveMessage {};
        conn.tx.write_all(&keepalive_msg.serialize()).await?;
        self.statistics.keepalive_sent += 1;
        debug!("sent KEEPALIVE message", "peer_ip" => self.addr.to_string());
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
        notif_msg: NotifcationMessage,
    ) -> Result<(), io::Error> {
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

    /// Track statistics for received BGP messages
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

    /// Process a BGP message and return route changes for Loc-RIB update if applicable
    /// Returns (withdrawn_prefixes, announced_routes) or None if not an UPDATE
    pub(super) async fn handle_message(
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
                self.process_event(&FsmEvent::BgpOpenReceived(BgpOpenParams {
                    peer_asn: open_msg.asn,
                    peer_hold_time: open_msg.hold_time,
                    peer_bgp_id: open_msg.bgp_identifier,
                    local_asn: self.fsm.local_asn(),
                    local_hold_time: self.fsm.local_hold_time(),
                }))
                .await?;
            }
            BgpMessage::Update(_) => {
                self.process_event(&FsmEvent::BgpUpdateReceived).await?;
            }
            BgpMessage::KeepAlive(_) => {
                self.process_event(&FsmEvent::BgpKeepaliveReceived).await?;
            }
            BgpMessage::Notification(notif) => {
                self.handle_notification_received(notif).await;
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
                        warn!("max prefix exceeded but allow_automatic_stop=false, continuing",
                              "peer_ip" => self.addr.to_string());
                        Ok(None)
                    }
                }
                Err(bgp_error) => {
                    // RFC 4271 Event 28: UpdateMsgErr
                    let notif = NotifcationMessage::new(bgp_error, vec![]);
                    self.process_event(&FsmEvent::BgpUpdateMsgErr(notif))
                        .await?;
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
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
}
