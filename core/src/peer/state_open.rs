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

use super::fsm::{BgpState, FsmEvent};
use super::{Peer, PeerOp};
use crate::bgp::msg::read_bgp_message;
use crate::bgp::msg_notification::{BgpError, NotifcationMessage};
use crate::{error, info};
use std::time::Duration;

impl Peer {
    /// Handle OpenSent and OpenConfirm states
    /// Returns true if shutdown requested.
    pub(super) async fn handle_open_states(&mut self) -> bool {
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
                        PeerOp::SendUpdate(_) => {
                            // RFC violation: UPDATEs not allowed in OpenSent/OpenConfirm
                            // Drop silently
                        }
                        PeerOp::GetStatistics(response) => {
                            let _ = response.send(self.statistics.clone());
                        }
                        PeerOp::Shutdown(subcode) => {
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
                        self.try_process_event(&FsmEvent::HoldTimerExpires).await;
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

            // Check if we transitioned out of OpenSent/OpenConfirm
            match self.fsm.state() {
                BgpState::OpenSent | BgpState::OpenConfirm => {}
                _ => return false,
            }
        }
    }
}
