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
use super::{Peer, PeerError};
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotifcationMessage};
use std::time::Instant;

impl Peer {
    /// Handle OpenConfirm state transitions.
    pub(super) async fn handle_openconfirm_transitions(
        &mut self,
        new_state: BgpState,
        event: &FsmEvent,
    ) -> Result<(), PeerError> {
        match (new_state, event) {
            // RFC 4271 8.2.2: ManualStop in session states
            (BgpState::Idle, FsmEvent::ManualStop) => {
                self.manually_stopped = true;
                let notif = NotifcationMessage::new(
                    BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
                    Vec::new(),
                );
                let _ = self.send_notification(notif).await;
                self.disconnect(true);
                self.fsm.timers.stop_connect_retry();
                self.fsm.reset_connect_retry_counter();
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
            }

            // RFC 4271 Event 8: AutomaticStop in session states
            (BgpState::Idle, FsmEvent::AutomaticStop(ref subcode)) => {
                let notif = NotifcationMessage::new(BgpError::Cease(subcode.clone()), Vec::new());
                let _ = self.send_notification(notif).await;
                self.disconnect(true);
                self.fsm.timers.stop_connect_retry();
                self.fsm.increment_connect_retry_counter();
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();

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
                return Err(PeerError::AutomaticStop(subcode.clone()));
            }

            // RFC 4271 Event 10: HoldTimer_Expires in session states
            (BgpState::Idle, FsmEvent::HoldTimerExpires) => {
                let notif = NotifcationMessage::new(BgpError::HoldTimerExpired, vec![]);
                let _ = self.send_notification(notif).await;
                self.disconnect(true);
                self.fsm.timers.stop_connect_retry();
                self.fsm.increment_connect_retry_counter();
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
            }

            (BgpState::Idle, FsmEvent::BgpUpdateMsgErr(ref notif)) => {
                let _ = self.send_notification(notif.clone()).await;
                self.disconnect(true);
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
                return Err(PeerError::UpdateError);
            }

            (BgpState::OpenConfirm, FsmEvent::KeepaliveTimerExpires) => {
                self.send_keepalive().await?;
            }

            (BgpState::Established, FsmEvent::BgpKeepaliveReceived) => {
                self.fsm.timers.reset_hold_timer();
                self.established_at = Some(Instant::now());
            }

            (BgpState::Idle, FsmEvent::ConnectRetryTimerExpires) => {
                let notif = NotifcationMessage::new(BgpError::FiniteStateMachineError, vec![]);
                let _ = self.send_notification(notif).await;
                self.disconnect(true);
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
                return Err(PeerError::FsmError);
            }

            (BgpState::Idle, FsmEvent::BgpUpdateReceived) => {
                let notif = NotifcationMessage::new(BgpError::FiniteStateMachineError, vec![]);
                let _ = self.send_notification(notif).await;
                self.disconnect(true);
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
                return Err(PeerError::FsmError);
            }

            _ => {}
        }
        Ok(())
    }
}
