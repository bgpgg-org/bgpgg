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
    /// Handle OpenConfirm state transitions (RFC 4271 Section 8.2.2).
    pub(super) async fn handle_openconfirm_transitions(
        &mut self,
        new_state: BgpState,
        event: &FsmEvent,
    ) -> Result<(), PeerError> {
        match (new_state, event) {
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

            (BgpState::Idle, FsmEvent::HoldTimerExpires) => {
                let notif = NotifcationMessage::new(BgpError::HoldTimerExpired, vec![]);
                let _ = self.send_notification(notif).await;
                self.disconnect(true);
                self.fsm.timers.stop_connect_retry();
                self.fsm.increment_connect_retry_counter();
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
            }

            (BgpState::Idle, FsmEvent::TcpConnectionFails) => {
                self.disconnect(true);
                self.fsm.timers.stop_connect_retry();
                self.fsm.increment_connect_retry_counter();
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
            }

            (BgpState::Idle, FsmEvent::NotifMsgVerErr) => {
                self.disconnect(false);
                self.fsm.timers.stop_connect_retry();
            }

            (BgpState::Idle, FsmEvent::NotifMsg) => {
                self.disconnect(true);
                self.fsm.timers.stop_connect_retry();
                self.fsm.increment_connect_retry_counter();
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
            }

            (BgpState::Idle, FsmEvent::BgpHeaderErr(ref notif))
            | (BgpState::Idle, FsmEvent::BgpOpenMsgErr(ref notif)) => {
                let _ = self.send_notification(notif.clone()).await;
                self.disconnect(true);
                self.fsm.timers.stop_connect_retry();
                self.fsm.increment_connect_retry_counter();
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
            }

            (BgpState::OpenConfirm, FsmEvent::KeepaliveTimerExpires) => {
                self.send_keepalive().await?;
            }

            (BgpState::Established, FsmEvent::BgpKeepaliveReceived) => {
                self.fsm.timers.reset_hold_timer();
                self.established_at = Some(Instant::now());
            }

            (BgpState::Idle, FsmEvent::ConnectRetryTimerExpires)
            | (BgpState::Idle, FsmEvent::DelayOpenTimerExpires)
            | (BgpState::Idle, FsmEvent::IdleHoldTimerExpires)
            | (BgpState::Idle, FsmEvent::BgpOpenWithDelayOpenTimer(_))
            | (BgpState::Idle, FsmEvent::BgpUpdateReceived)
            | (BgpState::Idle, FsmEvent::BgpUpdateMsgErr(_)) => {
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
    use crate::bgp::msg_notification::CeaseSubcode;
    use crate::peer::fsm::BgpOpenParams;
    use crate::peer::states::tests::create_test_peer_with_state;

    #[tokio::test]
    async fn test_openconfirm_ignores_start_events() {
        let start_events = vec![
            FsmEvent::ManualStart,
            FsmEvent::AutomaticStart,
            FsmEvent::ManualStartPassive,
            FsmEvent::AutomaticStartPassive,
        ];

        for event in start_events {
            let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            let initial_counter = peer.fsm.connect_retry_counter;

            peer.process_event(&event).await.unwrap();

            assert_eq!(peer.state(), BgpState::OpenConfirm);
            assert!(peer.conn.is_some());
            assert_eq!(peer.fsm.connect_retry_counter, initial_counter);
            assert!(peer.fsm.timers.hold_timer_started.is_some());
            assert!(peer.fsm.timers.keepalive_timer_started.is_some());
        }
    }

    #[tokio::test]
    async fn test_openconfirm_manual_stop() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 5;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        peer.process_event(&FsmEvent::ManualStop).await.unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert_eq!(
            peer.fsm.connect_retry_counter, 0,
            "ConnectRetryCounter should be zero"
        );
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be zero"
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
    async fn test_openconfirm_automatic_stop() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
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
            "ConnectRetryTimer should be zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 3,
            "ConnectRetryCounter should be incremented by 1"
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
    async fn test_openconfirm_automatic_stop_with_damping() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 1;
        peer.config.damp_peer_oscillations = true;
        peer.consecutive_down_count = 0;
        peer.config.send_notification_without_open = true;

        let result = peer
            .process_event(&FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached))
            .await;

        assert!(result.is_err());
        assert_eq!(peer.state(), BgpState::Idle);
        assert_eq!(
            peer.fsm.connect_retry_counter, 2,
            "ConnectRetryCounter should be incremented"
        );
        assert_eq!(
            peer.consecutive_down_count, 1,
            "Peer oscillation damping should increment consecutive_down_count"
        );
    }

    #[tokio::test]
    async fn test_openconfirm_keepalive_timer_expires() {
        let test_cases = vec![
            (180, true), // (hold_time, should_restart_timer)
            (0, false),  // hold_time=0 should not restart timer
        ];

        for (hold_time, should_restart) in test_cases {
            let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
            peer.fsm.timers.set_negotiated_hold_time(hold_time);
            if hold_time > 0 {
                peer.fsm.timers.start_hold_timer();
                peer.fsm.timers.start_keepalive_timer();
            }
            let initial_keepalive_sent = peer.statistics.keepalive_sent;

            peer.process_event(&FsmEvent::KeepaliveTimerExpires)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::OpenConfirm);
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
    async fn test_openconfirm_hold_timer_expires() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 3;
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
            peer.fsm.connect_retry_counter, 4,
            "ConnectRetryCounter should be incremented by 1"
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
    async fn test_openconfirm_tcp_connection_fails() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 2;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();

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
            "ConnectRetryCounter should be incremented by 1"
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
    async fn test_openconfirm_notification_received() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
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
            "ConnectRetryCounter should be incremented by 1"
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
    async fn test_openconfirm_notification_version_error() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 5;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();

        peer.process_event(&FsmEvent::NotifMsgVerErr).await.unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 5,
            "ConnectRetryCounter should NOT be incremented for version error"
        );
    }

    #[tokio::test]
    async fn test_openconfirm_bgp_header_error() {
        use crate::bgp::msg_notification::MessageHeaderError;

        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 1;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        let notif = NotifcationMessage::new(
            BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            vec![],
        );

        peer.process_event(&FsmEvent::BgpHeaderErr(notif))
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 2,
            "ConnectRetryCounter should be incremented by 1"
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
            "NOTIFICATION should be sent"
        );
    }

    #[tokio::test]
    async fn test_openconfirm_bgp_open_msg_error() {
        use crate::bgp::msg_notification::OpenMessageError;

        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 3;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        let notif = NotifcationMessage::new(
            BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber),
            vec![],
        );

        peer.process_event(&FsmEvent::BgpOpenMsgErr(notif))
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 4,
            "ConnectRetryCounter should be incremented by 1"
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
            "NOTIFICATION should be sent"
        );
    }

    #[tokio::test]
    async fn test_openconfirm_fsm_errors() {
        let events = vec![
            FsmEvent::ConnectRetryTimerExpires,
            FsmEvent::DelayOpenTimerExpires,
            FsmEvent::IdleHoldTimerExpires,
            FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
                peer_asn: 65001,
                peer_hold_time: 180,
                peer_bgp_id: 0x02020202,
                local_asn: 65000,
                local_hold_time: 180,
            }),
            FsmEvent::BgpUpdateReceived,
            FsmEvent::BgpUpdateMsgErr(NotifcationMessage::new(
                BgpError::UpdateMessageError(
                    crate::bgp::msg_notification::UpdateMessageError::MalformedAttributeList,
                ),
                vec![],
            )),
        ];

        for event in events {
            let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
            peer.fsm.connect_retry_counter = 2;
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            peer.config.damp_peer_oscillations = true;
            peer.config.send_notification_without_open = true;

            let result = peer.process_event(&event).await;

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
    }

    #[tokio::test]
    async fn test_openconfirm_transition_to_established() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();

        peer.process_event(&FsmEvent::BgpKeepaliveReceived)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Established);
        assert!(peer.established_at.is_some());
    }

    #[tokio::test]
    async fn test_openconfirm_keepalive_received() {
        use std::time::Duration;

        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.timers.start_hold_timer();
        let hold_start = peer.fsm.timers.hold_timer_started;

        tokio::time::sleep(Duration::from_millis(10)).await;

        peer.process_event(&FsmEvent::BgpKeepaliveReceived)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Established);
        assert!(peer.fsm.timers.hold_timer_started > hold_start);
    }
}
