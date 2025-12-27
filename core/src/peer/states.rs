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
use super::{Peer, PeerError, TcpConnection};
use crate::bgp::msg_notification::NotifcationMessage;
use crate::server::ConnectionType;
use crate::{debug, error};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

impl Peer {
    /// Handle received NOTIFICATION and generate appropriate event (Event 24 or 25).
    pub(super) async fn handle_notification_received(&mut self, notif: &NotifcationMessage) {
        let event = if notif.is_version_error() {
            debug!("NOTIFICATION with version error received", "peer_ip" => self.addr.to_string());
            FsmEvent::NotifMsgVerErr
        } else {
            debug!("NOTIFICATION received", "peer_ip" => self.addr.to_string());
            FsmEvent::NotifMsg
        };
        self.try_process_event(&event).await;
    }

    /// Accept an incoming TCP connection in Connect or Active state.
    pub(super) async fn accept_connection(
        &mut self,
        tcp_tx: OwnedWriteHalf,
        tcp_rx: OwnedReadHalf,
    ) {
        debug!("TcpConnectionAccepted", "peer_ip" => self.addr.to_string());
        self.conn = Some(TcpConnection {
            tx: tcp_tx,
            rx: tcp_rx,
        });
        self.conn_type = ConnectionType::Incoming;
        self.fsm.timers.stop_connect_retry();
        if self.config.delay_open_time_secs.is_some() {
            self.fsm.timers.start_delay_open_timer();
        } else if let Err(e) = self.process_event(&FsmEvent::TcpConnectionConfirmed).await {
            error!("failed to send OPEN", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
            self.disconnect(true);
        }
    }

    /// Process FSM event, transition state, and execute associated actions.
    pub(super) async fn process_event(&mut self, event: &FsmEvent) -> Result<(), PeerError> {
        let old_state = self.fsm.state();
        let new_state = self.fsm.handle_event(event);

        // Dispatch to state-specific transition handlers
        match old_state {
            BgpState::Idle => self.handle_idle_transitions(new_state, event).await?,
            BgpState::Connect => self.handle_connect_transitions(new_state, event).await?,
            BgpState::Active => self.handle_active_transitions(new_state, event).await?,
            BgpState::OpenSent => self.handle_opensent_transitions(new_state, event).await?,
            BgpState::OpenConfirm => {
                self.handle_openconfirm_transitions(new_state, event)
                    .await?
            }
            BgpState::Established => {
                self.handle_established_transitions(new_state, event)
                    .await?
            }
        }

        // Notify server of state change after all actions complete
        if old_state != new_state {
            self.notify_state_change();
        }

        Ok(())
    }

    /// Process FSM event and log any errors.
    pub(super) async fn try_process_event(&mut self, event: &FsmEvent) {
        if let Err(e) = self.process_event(event).await {
            error!("failed to process event",
                "peer_ip" => self.addr.to_string(),
                "event" => format!("{:?}", event),
                "error" => e.to_string());
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::bgp::msg_notification::{BgpError, CeaseSubcode, UpdateMessageError};
    use crate::config::PeerConfig;
    use crate::peer::fsm::BgpOpenParams;
    use crate::peer::{BgpState, Fsm};
    use crate::rib::rib_in::AdjRibIn;
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    pub(crate) async fn create_test_peer_with_state(state: BgpState) -> Peer {
        // Create a test TCP connection
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn task to accept connection and drain data
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (mut rx, _tx) = stream.into_split();
                let mut buf = vec![0u8; 4096];
                while rx.read(&mut buf).await.is_ok() {}
            }
        });

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (tcp_rx, tcp_tx) = client.into_split();

        // Create dummy channels for testing
        let (server_tx, _server_rx) = mpsc::unbounded_channel();
        let (_peer_tx, peer_rx) = mpsc::unbounded_channel();

        // Create peer directly for testing
        let local_ip = Ipv4Addr::new(127, 0, 0, 1);
        Peer {
            addr: addr.ip(),
            port: addr.port(),
            fsm: Fsm::with_state(state, 65000, 180, 0x01010101, local_ip, false),
            conn: Some(TcpConnection {
                tx: tcp_tx,
                rx: tcp_rx,
            }),
            asn: Some(65001),
            rib_in: AdjRibIn::new(),
            session_type: Some(crate::peer::SessionType::Ebgp),
            statistics: crate::peer::PeerStatistics::default(),
            config: PeerConfig::default(),
            peer_rx,
            server_tx,
            local_addr: SocketAddr::new(local_ip.into(), 0),
            connect_retry_secs: 120,
            consecutive_down_count: 0,
            conn_type: ConnectionType::Outgoing,
            manually_stopped: false,
            established_at: None,
            mrai_interval: Duration::from_secs(0),
            last_update_sent: None,
            pending_updates: VecDeque::new(),
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
    async fn test_manual_stop_session_states() {
        let test_cases = vec![
            BgpState::OpenSent,
            BgpState::OpenConfirm,
            BgpState::Established,
        ];

        for state in test_cases {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.connect_retry_counter = 5;
            peer.fsm.timers.start_connect_retry();
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();

            peer.process_event(&FsmEvent::ManualStop).await.unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.manually_stopped);
            assert!(peer.conn.is_none());
            assert_eq!(
                peer.fsm.connect_retry_counter, 0,
                "ConnectRetryCounter should be reset to 0"
            );
            assert!(
                peer.fsm.timers.connect_retry_started.is_none(),
                "ConnectRetryTimer should be stopped"
            );
            assert!(peer.fsm.timers.hold_timer_started.is_none());
            assert!(peer.fsm.timers.keepalive_timer_started.is_none());
        }
    }

    #[tokio::test]
    async fn test_update_msg_err_in_session_states() {
        // RFC 4271 Event 28: UpdateMsgErr in session states should send NOTIFICATION
        for state in [
            BgpState::OpenSent,
            BgpState::OpenConfirm,
            BgpState::Established,
        ] {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            peer.config.send_notification_without_open = true;

            let notif = NotifcationMessage::new(
                BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
                vec![],
            );

            // Process the event - should send NOTIFICATION and transition to Idle
            peer.process_event(&FsmEvent::BgpUpdateMsgErr(notif.clone()))
                .await
                .unwrap_err(); // Should return error

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.fsm.timers.hold_timer_started.is_none());
            assert!(peer.fsm.timers.keepalive_timer_started.is_none());
            assert!(peer.conn.is_none());
            // Verify notification was sent (check statistics)
            assert_eq!(peer.statistics.notification_sent, 1);
        }
    }

    #[tokio::test]
    async fn test_automatic_stop_in_session_states() {
        for state in [
            BgpState::OpenSent,
            BgpState::OpenConfirm,
            BgpState::Established,
        ] {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.connect_retry_counter = 2;
            peer.fsm.timers.start_connect_retry();
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            peer.statistics.open_sent = 1;

            let result = peer
                .process_event(&FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached))
                .await;
            assert!(result.is_err(), "AutomaticStop should return error");

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(
                peer.fsm.timers.connect_retry_started.is_none(),
                "ConnectRetryTimer should be set to zero"
            );
            assert_eq!(
                peer.fsm.connect_retry_counter, 3,
                "ConnectRetryCounter should be incremented"
            );
            assert!(peer.conn.is_none(), "TCP connection should be dropped");
            assert!(peer.fsm.timers.hold_timer_started.is_none());
            assert!(peer.fsm.timers.keepalive_timer_started.is_none());
            assert_eq!(
                peer.statistics.notification_sent, 1,
                "NOTIFICATION with Cease should be sent"
            );
        }
    }

    #[tokio::test]
    async fn test_hold_timer_expires_in_session_states() {
        for state in [
            BgpState::OpenSent,
            BgpState::OpenConfirm,
            BgpState::Established,
        ] {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.connect_retry_counter = 1;
            peer.fsm.timers.start_connect_retry();
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            peer.statistics.open_sent = 1;

            peer.process_event(&FsmEvent::HoldTimerExpires)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(
                peer.fsm.timers.connect_retry_started.is_none(),
                "ConnectRetryTimer should be set to zero"
            );
            assert_eq!(
                peer.fsm.connect_retry_counter, 2,
                "ConnectRetryCounter should be incremented"
            );
            assert!(peer.conn.is_none(), "TCP connection should be dropped");
            assert!(peer.fsm.timers.hold_timer_started.is_none());
            assert!(peer.fsm.timers.keepalive_timer_started.is_none());
            assert_eq!(
                peer.statistics.notification_sent, 1,
                "NOTIFICATION with HoldTimerExpired should be sent"
            );
        }
    }

    #[tokio::test]
    async fn test_open_received_hold_time_zero() {
        // RFC 4271 8.2.2: When hold time is zero, timers should not be started
        let mut peer = create_test_peer_with_state(BgpState::Connect).await;

        peer.process_event(&FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
            peer_asn: 65001,
            peer_hold_time: 0, // Peer wants no hold timer
            peer_bgp_id: 0x02020202,
            local_asn: 65000,
            local_hold_time: 180,
        }))
        .await
        .unwrap();

        // Verify state transition
        assert_eq!(peer.state(), BgpState::OpenConfirm);
        // Verify hold time negotiated to zero (min of 0 and 180)
        assert_eq!(peer.fsm.timers.hold_time.as_secs(), 0);
        assert_eq!(peer.fsm.timers.keepalive_time.as_secs(), 0);
        // Verify timers are NOT started when hold_time is zero
        assert!(peer.fsm.timers.hold_timer_started.is_none());
        assert!(peer.fsm.timers.keepalive_timer_started.is_none());
        // Verify KEEPALIVE was still sent (RFC requires it)
        assert_eq!(peer.statistics.keepalive_sent, 1);
    }
}
