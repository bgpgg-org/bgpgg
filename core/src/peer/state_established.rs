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
use crate::debug;

impl Peer {
    /// Handle Established state transitions.
    pub(super) async fn handle_established_transitions(
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

            // RFC 4271 8.2.2: TcpConnectionFails in Established -> Idle
            (BgpState::Idle, FsmEvent::TcpConnectionFails) => {
                self.disconnect(true);
                self.fsm.timers.stop_connect_retry();
                self.fsm.increment_connect_retry_counter();
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
            }

            // RFC 4271 8.2.2: NotifMsg in Established -> Idle
            (BgpState::Idle, FsmEvent::NotifMsg) | (BgpState::Idle, FsmEvent::NotifMsgVerErr) => {
                self.disconnect(true);
                self.fsm.timers.stop_connect_retry();
                self.fsm.increment_connect_retry_counter();
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
            }

            (BgpState::Established, FsmEvent::KeepaliveTimerExpires) => {
                self.send_keepalive().await?;
            }

            (BgpState::Established, FsmEvent::BgpKeepaliveReceived)
            | (BgpState::Established, FsmEvent::BgpUpdateReceived) => {
                // RFC 4271: Reset HoldTimer if negotiated HoldTime is non-zero
                if self.fsm.timers.hold_time.as_secs() > 0 {
                    self.fsm.timers.reset_hold_timer();
                }
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

            (BgpState::Idle, FsmEvent::ConnectRetryTimerExpires) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_notification::{CeaseSubcode, UpdateMessageError};
    use crate::peer::states::tests::create_test_peer_with_state;

    #[tokio::test]
    async fn test_established_ignores_start_events() {
        // RFC 4271 8.2.2: Events 1, 3-7 (Start events) are ignored in Established state
        let start_events = vec![
            FsmEvent::ManualStart,
            FsmEvent::AutomaticStart,
            FsmEvent::ManualStartPassive,
            FsmEvent::AutomaticStartPassive,
        ];

        for event in start_events {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            let initial_counter = peer.fsm.connect_retry_counter;

            peer.process_event(&event).await.unwrap();

            assert_eq!(
                peer.state(),
                BgpState::Established,
                "Start event {:?} should be ignored in Established state",
                event
            );
            assert!(peer.conn.is_some(), "TCP connection should remain");
            assert_eq!(peer.fsm.connect_retry_counter, initial_counter);
            assert!(peer.fsm.timers.hold_timer_started.is_some());
            assert!(peer.fsm.timers.keepalive_timer_started.is_some());
        }
    }

    #[tokio::test]
    async fn test_established_manual_stop() {
        // RFC 4271 8.2.2: ManualStop -> send NOTIFICATION with Cease, -> Idle
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.connect_retry_counter = 5;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        peer.process_event(&FsmEvent::ManualStop).await.unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert_eq!(
            peer.fsm.connect_retry_counter, 0,
            "ConnectRetryCounter should be set to zero"
        );
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
        assert_eq!(
            peer.statistics.notification_sent, 1,
            "NOTIFICATION with Cease should be sent"
        );
        assert!(peer.manually_stopped, "manually_stopped flag should be set");
    }

    #[tokio::test]
    async fn test_established_automatic_stop() {
        // RFC 4271 8.2.2: AutomaticStop -> send NOTIFICATION, -> Idle
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.connect_retry_counter = 2;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        let result = peer
            .process_event(&FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached))
            .await;

        assert!(result.is_err(), "AutomaticStop should return error");
        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 3,
            "ConnectRetryCounter should be incremented"
        );
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
        assert_eq!(
            peer.statistics.notification_sent, 1,
            "NOTIFICATION with Cease should be sent"
        );
    }

    #[tokio::test]
    async fn test_established_hold_timer_expires() {
        // RFC 4271 8.2.2: HoldTimer_Expires -> send NOTIFICATION, -> Idle
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.connect_retry_counter = 1;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        peer.process_event(&FsmEvent::HoldTimerExpires)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert_eq!(
            peer.statistics.notification_sent, 1,
            "NOTIFICATION with HoldTimerExpired should be sent"
        );
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 2,
            "ConnectRetryCounter should be incremented"
        );
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
    }

    #[tokio::test]
    async fn test_established_keepalive_timer_expires() {
        // RFC 4271 8.2.2: KeepaliveTimer_Expires -> send KEEPALIVE, stay Established
        let test_cases = vec![
            (180, true),  // (hold_time, should_restart_timer)
            (0, false),   // hold_time=0 should not restart timer
        ];

        for (hold_time, should_restart) in test_cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.fsm.timers.set_negotiated_hold_time(hold_time);
            if hold_time > 0 {
                peer.fsm.timers.start_hold_timer();
                peer.fsm.timers.start_keepalive_timer();
            }
            let initial_keepalive_sent = peer.statistics.keepalive_sent;

            peer.process_event(&FsmEvent::KeepaliveTimerExpires)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Established);
            assert_eq!(
                peer.statistics.keepalive_sent,
                initial_keepalive_sent + 1,
                "KEEPALIVE message should be sent (hold_time={})",
                hold_time
            );
            assert!(peer.conn.is_some(), "TCP connection should remain");

            if should_restart {
                assert!(
                    peer.fsm.timers.keepalive_timer_started.is_some(),
                    "KeepaliveTimer should be restarted when hold_time > 0"
                );
            } else {
                assert!(
                    peer.fsm.timers.keepalive_timer_started.is_none(),
                    "KeepaliveTimer should NOT be restarted when hold_time is zero"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_established_keepalive_received() {
        // RFC 4271 8.2.2: KeepAliveMsg -> reset HoldTimer if non-zero, stay Established
        let test_cases = vec![
            (180, true),  // (hold_time, should_reset_hold_timer)
            (0, false),   // hold_time=0 should not reset hold timer
        ];

        for (hold_time, should_reset) in test_cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.fsm.timers.set_negotiated_hold_time(hold_time);
            if hold_time > 0 {
                peer.fsm.timers.start_hold_timer();
                peer.fsm.timers.start_keepalive_timer();
            }
            peer.consecutive_down_count = 3;
            peer.config.damp_peer_oscillations = true;

            // Set established_at to simulate stable connection
            peer.established_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(200));

            peer.process_event(&FsmEvent::BgpKeepaliveReceived)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Established);
            assert!(peer.conn.is_some(), "TCP connection should remain");

            if should_reset {
                assert!(
                    peer.fsm.timers.hold_timer_started.is_some(),
                    "Hold timer should be reset when hold_time > 0"
                );
            } else {
                assert!(
                    peer.fsm.timers.hold_timer_started.is_none(),
                    "Hold timer should NOT be reset when hold_time is zero"
                );
            }

            if hold_time > 0 {
                assert_eq!(
                    peer.consecutive_down_count, 0,
                    "Damping counter should be reset after stable connection"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_established_update_received() {
        // RFC 4271 8.2.2: UpdateMsg -> reset HoldTimer if non-zero, stay Established
        let test_cases = vec![
            (180, true),  // (hold_time, should_reset_hold_timer)
            (0, false),   // hold_time=0 should not reset hold timer
        ];

        for (hold_time, should_reset) in test_cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.fsm.timers.set_negotiated_hold_time(hold_time);
            if hold_time > 0 {
                peer.fsm.timers.start_hold_timer();
                peer.fsm.timers.start_keepalive_timer();
            }

            peer.process_event(&FsmEvent::BgpUpdateReceived)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Established);
            assert!(peer.conn.is_some(), "TCP connection should remain");

            if should_reset {
                assert!(
                    peer.fsm.timers.hold_timer_started.is_some(),
                    "Hold timer should be reset when hold_time > 0"
                );
            } else {
                assert!(
                    peer.fsm.timers.hold_timer_started.is_none(),
                    "Hold timer should NOT be reset when hold_time is zero"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_established_update_msg_error() {
        // RFC 4271 8.2.2: UpdateMsgErr -> send NOTIFICATION, -> Idle
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        let notif = NotifcationMessage::new(
            BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
            vec![],
        );

        let result = peer.process_event(&FsmEvent::BgpUpdateMsgErr(notif)).await;

        assert!(result.is_err(), "UpdateMsgErr should return error");
        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
        assert_eq!(
            peer.statistics.notification_sent, 1,
            "NOTIFICATION should be sent"
        );
    }

    #[tokio::test]
    async fn test_established_tcp_connection_fails() {
        // RFC 4271 8.2.2: TcpConnectionFails -> Idle (no NOTIFICATION)
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.connect_retry_counter = 2;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();

        // Simulate TCP connection failure by dropping the connection
        peer.conn = None;

        peer.process_event(&FsmEvent::TcpConnectionFails)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 3,
            "ConnectRetryCounter should be incremented"
        );
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
        assert_eq!(
            peer.statistics.notification_sent, 0,
            "No NOTIFICATION should be sent on TCP failure"
        );
    }

    #[tokio::test]
    async fn test_established_notification_received() {
        // RFC 4271 8.2.2: NotifMsg -> Idle
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.connect_retry_counter = 1;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();

        peer.process_event(&FsmEvent::NotifMsg).await.unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 2,
            "ConnectRetryCounter should be incremented"
        );
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
    }

    #[tokio::test]
    async fn test_established_fsm_error_connect_retry_timer() {
        // RFC 4271 6.6: Event 9 (ConnectRetryTimerExpires) in Established -> FSM Error
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        let result = peer
            .process_event(&FsmEvent::ConnectRetryTimerExpires)
            .await;

        assert!(result.is_err(), "FSM error should return error");
        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
        assert_eq!(
            peer.statistics.notification_sent, 1,
            "NOTIFICATION should be sent"
        );
    }

    #[tokio::test]
    async fn test_established_damping_reset_after_stability() {
        // Test that consecutive_down_count is reset after stable connection
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.consecutive_down_count = 5;
        peer.config.damp_peer_oscillations = true;

        // Set established_at to simulate stable connection (longer than hold_time)
        let hold_time = peer.fsm.timers.hold_time;
        peer.established_at = Some(std::time::Instant::now() - hold_time - std::time::Duration::from_secs(1));

        peer.process_event(&FsmEvent::BgpKeepaliveReceived)
            .await
            .unwrap();

        assert_eq!(
            peer.consecutive_down_count, 0,
            "Damping counter should be reset after stable connection"
        );
    }

    #[tokio::test]
    async fn test_established_damping_not_reset_before_stability() {
        // Test that consecutive_down_count is NOT reset before stability threshold
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.consecutive_down_count = 3;
        peer.config.damp_peer_oscillations = true;

        // Set established_at to simulate recent connection (less than hold_time)
        peer.established_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(10));

        peer.process_event(&FsmEvent::BgpKeepaliveReceived)
            .await
            .unwrap();

        assert_eq!(
            peer.consecutive_down_count, 3,
            "Damping counter should NOT be reset before stability threshold"
        );
    }
}
