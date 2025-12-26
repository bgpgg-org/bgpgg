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

use super::fsm::{BgpOpenParams, BgpState, FsmEvent};
use super::{Peer, PeerError, PeerOp};
use crate::bgp::msg::{read_bgp_message, BgpMessage};
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotifcationMessage};
use crate::{debug, error};
use std::time::Duration;

const INITIAL_HOLD_TIME: Duration = Duration::from_secs(240);

impl Peer {
    /// Handle Active state - listen for incoming connections.
    pub(super) async fn handle_active_state(&mut self) {
        if self.fsm.timers.delay_open_timer_running() {
            self.handle_active_delay_open_wait().await;
        } else {
            let retry_time = Duration::from_secs(self.connect_retry_secs);

            tokio::select! {
                _ = tokio::time::sleep(retry_time) => {
                    debug!("ConnectRetryTimer expired in Active", "peer_ip" => self.addr.to_string());
                    self.try_process_event(&FsmEvent::ConnectRetryTimerExpires).await;
                }
                op = self.peer_rx.recv() => {
                    match op {
                        Some(PeerOp::ManualStop) => {
                            self.try_process_event(&FsmEvent::ManualStop).await;
                        }
                        Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                            self.accept_connection(tcp_tx, tcp_rx).await;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Wait for DelayOpen timer in Active state (RFC 4271 8.2.2).
    /// Does not monitor ConnectRetryTimer.
    async fn handle_active_delay_open_wait(&mut self) {
        let conn = self.conn.as_mut().expect("connection should exist");
        let mut timer_interval = tokio::time::interval(Duration::from_millis(100));

        tokio::select! {
            result = read_bgp_message(&mut conn.rx) => {
                match result {
                    Ok(BgpMessage::Open(open)) => {
                        debug!("OPEN received while DelayOpen running", "peer_ip" => self.addr.to_string());
                        self.fsm.timers.stop_delay_open_timer();
                        if let Err(e) = self.process_event(&FsmEvent::BgpOpenWithDelayOpenTimer(
                            BgpOpenParams {
                                peer_asn: open.asn,
                                peer_hold_time: open.hold_time,
                                local_asn: self.fsm.local_asn(),
                                local_hold_time: self.fsm.local_hold_time(),
                                peer_bgp_id: open.bgp_identifier,
                            }
                        )).await {
                            error!("failed to send response to OPEN", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                            self.disconnect(true);
                        }
                    }
                    Ok(BgpMessage::Notification(notif)) => {
                        self.handle_notification_received(&notif).await;
                    }
                    Ok(_) => {
                        error!("unexpected message while waiting for DelayOpen", "peer_ip" => self.addr.to_string());
                        self.disconnect(true);
                    }
                    Err(e) => {
                        debug!("connection error while waiting for DelayOpen", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                        let event = if let Some(notif) = NotifcationMessage::from_parser_error(&e) {
                            match notif.error() {
                                BgpError::MessageHeaderError(_) => FsmEvent::BgpHeaderErr(notif),
                                BgpError::OpenMessageError(_) => FsmEvent::BgpOpenMsgErr(notif),
                                _ => FsmEvent::TcpConnectionFails,
                            }
                        } else {
                            FsmEvent::TcpConnectionFails
                        };
                        self.try_process_event(&event).await;
                    }
                }
            }
            _ = timer_interval.tick() => {
                if self.fsm.timers.delay_open_timer_expired() {
                    debug!("DelayOpen timer expired", "peer_ip" => self.addr.to_string());
                    if let Err(e) = self.process_event(&FsmEvent::DelayOpenTimerExpires).await {
                        error!("failed to send OPEN", "peer_ip" => self.addr.to_string(), "error" => e.to_string());
                        self.disconnect(true);
                    }
                }
            }
            op = self.peer_rx.recv() => {
                match op {
                    Some(PeerOp::ManualStop) => {
                        self.try_process_event(&FsmEvent::ManualStop).await;
                    }
                    Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                        debug!("closing duplicate incoming connection", "peer_ip" => self.addr.to_string());
                        drop(tcp_tx);
                        drop(tcp_rx);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Handle Active state transitions.
    pub(super) async fn handle_active_transitions(
        &mut self,
        new_state: BgpState,
        event: &FsmEvent,
    ) -> Result<(), PeerError> {
        match (new_state, event) {
            // RFC 4271 8.2.2: ConnectRetryTimer expires in Active state
            (BgpState::Connect, FsmEvent::ConnectRetryTimerExpires) => {
                self.fsm.timers.start_connect_retry();
            }

            // RFC 4271 8.2.2 Event 18: TcpConnectionFails in Active -> Idle
            (BgpState::Idle, FsmEvent::TcpConnectionFails) => {
                self.disconnect(true);
                self.fsm.timers.stop_delay_open_timer();
                self.fsm.timers.start_connect_retry();
                self.fsm.increment_connect_retry_counter();
            }

            // RFC 4271 Events 21, 22: BGP header/OPEN message errors -> Idle (shared with Connect)
            (BgpState::Idle, FsmEvent::BgpHeaderErr(ref notif))
            | (BgpState::Idle, FsmEvent::BgpOpenMsgErr(ref notif)) => {
                let _ = self.send_notification(notif.clone()).await;
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.disconnect(true);
                self.fsm.increment_connect_retry_counter();
            }

            // RFC 4271 Event 24: NOTIFICATION with version error -> Idle (shared with Connect)
            (BgpState::Idle, FsmEvent::NotifMsgVerErr) => {
                self.fsm.timers.stop_connect_retry();
                let delay_open_was_running = self.fsm.timers.delay_open_timer_running();
                self.fsm.timers.stop_delay_open_timer();
                self.disconnect(!delay_open_was_running);
                if !delay_open_was_running {
                    self.fsm.increment_connect_retry_counter();
                }
            }

            // RFC 4271 Event 25: NOTIFICATION without version error -> Idle (shared with Connect)
            (BgpState::Idle, FsmEvent::NotifMsg) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.disconnect(true);
                self.fsm.increment_connect_retry_counter();
            }

            // RFC 4271 8.2.2: Any other events (8, 10-11, 13, 19, 25-28) in Active -> Idle
            (BgpState::Idle, FsmEvent::AutomaticStop(_))
            | (BgpState::Idle, FsmEvent::HoldTimerExpires)
            | (BgpState::Idle, FsmEvent::KeepaliveTimerExpires)
            | (BgpState::Idle, FsmEvent::IdleHoldTimerExpires)
            | (BgpState::Idle, FsmEvent::BgpOpenReceived(_))
            | (BgpState::Idle, FsmEvent::BgpKeepaliveReceived)
            | (BgpState::Idle, FsmEvent::BgpUpdateReceived)
            | (BgpState::Idle, FsmEvent::BgpUpdateMsgErr(_)) => {
                self.fsm.timers.stop_connect_retry();
                self.disconnect(true);
                self.fsm.increment_connect_retry_counter();
            }

            // RFC 4271 8.2.2: ManualStop in Active state
            (BgpState::Idle, FsmEvent::ManualStop) => {
                if self.fsm.timers.delay_open_timer_running()
                    && self.config.send_notification_without_open
                {
                    let notif = NotifcationMessage::new(
                        BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
                        Vec::new(),
                    );
                    let _ = self.send_notification(notif).await;
                }
                self.disconnect(true);
                self.manually_stopped = true;
                self.fsm.reset_connect_retry_counter();
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
            }

            (BgpState::OpenSent, FsmEvent::DelayOpenTimerExpires) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.fsm.timers.set_initial_hold_time(INITIAL_HOLD_TIME);
                self.fsm.timers.start_hold_timer();
                self.send_open().await?;
            }

            // Entering OpenSent - send OPEN message (shared with Connect)
            (BgpState::OpenSent, FsmEvent::TcpConnectionConfirmed) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.set_initial_hold_time(INITIAL_HOLD_TIME);
                self.fsm.timers.start_hold_timer();
                self.send_open().await?;
            }

            // Received OPEN while in Active with DelayOpen - send OPEN + KEEPALIVE (RFC 4271 Event 20)
            (BgpState::OpenConfirm, &FsmEvent::BgpOpenWithDelayOpenTimer(params)) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.send_open().await?;
                self.enter_open_confirm(
                    params.peer_asn,
                    params.peer_hold_time,
                    params.local_asn,
                    params.local_hold_time,
                )
                .await?;
            }

            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use crate::peer::{BgpState, Fsm};
    use crate::rib::rib_in::AdjRibIn;
    use crate::server::ConnectionType;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    async fn create_test_peer(state: BgpState) -> Peer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (mut rx, _tx) = stream.into_split();
                let mut buf = vec![0u8; 4096];
                while rx.read(&mut buf).await.is_ok() {}
            }
        });

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (tcp_rx, tcp_tx) = client.into_split();

        let (server_tx, _server_rx) = mpsc::unbounded_channel();
        let (_peer_tx, peer_rx) = mpsc::unbounded_channel();

        let local_ip = Ipv4Addr::new(127, 0, 0, 1);
        Peer {
            addr: addr.ip(),
            port: addr.port(),
            fsm: Fsm::with_state(state, 65000, 180, 0x01010101, local_ip, false),
            conn: Some(super::super::TcpConnection {
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
        }
    }

    #[tokio::test]
    async fn test_manual_stop_active() {
        let cases = vec![
            (true, true, 1),
            (true, false, 0),
            (false, true, 0),
            (false, false, 0),
        ];

        for (delay_open_running, send_notif_config, expected_notif) in cases {
            let mut peer = create_test_peer(BgpState::Active).await;
            peer.fsm.connect_retry_counter = 3;
            peer.fsm.timers.start_connect_retry();
            peer.config.send_notification_without_open = send_notif_config;

            if delay_open_running {
                peer.fsm.timers.start_delay_open_timer();
            }

            peer.process_event(&FsmEvent::ManualStop).await.unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.manually_stopped);
            assert_eq!(peer.fsm.connect_retry_counter, 0);
            assert!(peer.fsm.timers.connect_retry_started.is_none());
            assert!(peer.fsm.timers.delay_open_timer_started.is_none());
            assert!(peer.conn.is_none());
            assert_eq!(peer.statistics.notification_sent, expected_notif);
        }
    }

    #[tokio::test]
    async fn test_connect_retry_timer_expires_active() {
        let mut peer = create_test_peer(BgpState::Active).await;
        peer.fsm.timers.start_connect_retry();
        let timer_before = peer.fsm.timers.connect_retry_started;

        peer.process_event(&FsmEvent::ConnectRetryTimerExpires)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Connect);
        let timer_after = peer.fsm.timers.connect_retry_started;
        assert!(timer_after.is_some(), "ConnectRetryTimer should be running");
        assert_ne!(timer_before, timer_after);
    }

    #[tokio::test]
    async fn test_delay_open_timer_expires_active() {
        let mut peer = create_test_peer(BgpState::Active).await;
        peer.fsm.timers.start_connect_retry();
        peer.fsm.timers.start_delay_open_timer();
        assert_eq!(peer.statistics.open_sent, 0);

        peer.process_event(&FsmEvent::DelayOpenTimerExpires)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::OpenSent);
        assert!(!peer.fsm.timers.delay_open_timer_running());
        assert!(peer.fsm.timers.connect_retry_started.is_none());
        assert!(peer.fsm.timers.hold_timer_started.is_some());
        assert_eq!(peer.statistics.open_sent, 1);
    }

    #[tokio::test]
    async fn test_tcp_connection_fails_active() {
        let mut peer = create_test_peer(BgpState::Active).await;
        peer.fsm.timers.start_delay_open_timer();
        peer.config.damp_peer_oscillations = true;
        assert!(peer.conn.is_some());

        peer.process_event(&FsmEvent::TcpConnectionFails)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none());
        assert!(!peer.fsm.timers.delay_open_timer_running());
        assert!(peer.fsm.timers.connect_retry_started.is_some());
        assert_eq!(peer.fsm.connect_retry_counter, 1);
        assert_eq!(peer.consecutive_down_count, 1);
    }

    #[tokio::test]
    async fn test_open_received_in_active_stops_timers() {
        let mut peer = create_test_peer(BgpState::Active).await;
        peer.fsm.timers.start_connect_retry();
        peer.fsm.timers.start_delay_open_timer();
        assert!(peer.fsm.timers.connect_retry_started.is_some());
        assert!(peer.fsm.timers.delay_open_timer_running());
        assert_eq!(peer.statistics.open_sent, 0);
        assert_eq!(peer.statistics.keepalive_sent, 0);

        peer.process_event(&FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
            peer_asn: 65001,
            peer_hold_time: 180,
            peer_bgp_id: 0x02020202,
            local_asn: 65000,
            local_hold_time: 180,
        }))
        .await
        .unwrap();

        assert_eq!(peer.state(), BgpState::OpenConfirm);
        assert!(peer.fsm.timers.connect_retry_started.is_none());
        assert!(!peer.fsm.timers.delay_open_timer_running());
        assert_eq!(peer.statistics.open_sent, 1);
        assert_eq!(peer.statistics.keepalive_sent, 1);
        assert!(peer.fsm.timers.hold_timer_started.is_some());
        assert!(peer.fsm.timers.keepalive_timer_started.is_some());
        assert_eq!(peer.fsm.timers.hold_time.as_secs(), 180);
        assert_eq!(peer.fsm.timers.keepalive_time.as_secs(), 60);
    }

    #[tokio::test]
    async fn test_open_received_in_active_hold_time_zero() {
        let mut peer = create_test_peer(BgpState::Active).await;
        peer.fsm.timers.start_connect_retry();
        peer.fsm.timers.start_delay_open_timer();

        peer.process_event(&FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
            peer_asn: 65001,
            peer_hold_time: 0,
            peer_bgp_id: 0x02020202,
            local_asn: 65000,
            local_hold_time: 180,
        }))
        .await
        .unwrap();

        assert_eq!(peer.state(), BgpState::OpenConfirm);
        assert!(peer.fsm.timers.connect_retry_started.is_none());
        assert!(!peer.fsm.timers.delay_open_timer_running());
        assert_eq!(peer.fsm.timers.hold_time.as_secs(), 0);
        assert_eq!(peer.fsm.timers.keepalive_time.as_secs(), 0);
        assert!(peer.fsm.timers.hold_timer_started.is_none());
        assert!(peer.fsm.timers.keepalive_timer_started.is_none());
        assert_eq!(peer.statistics.keepalive_sent, 1);
    }

    #[tokio::test]
    async fn test_tcp_connection_success_active() {
        let cases = vec![(None, BgpState::OpenSent), (Some(5), BgpState::Active)];

        for (delay_open, expected_state) in cases {
            let mut peer = create_test_peer(BgpState::Active).await;
            peer.fsm.timers.start_connect_retry();
            peer.config.delay_open_time_secs = delay_open;

            if delay_open.is_none() {
                peer.process_event(&FsmEvent::TcpConnectionConfirmed)
                    .await
                    .unwrap();

                assert_eq!(peer.state(), expected_state);
                assert!(peer.fsm.timers.connect_retry_started.is_none());
                assert!(peer.fsm.timers.hold_timer_started.is_some());
                assert_eq!(peer.statistics.open_sent, 1);
            } else {
                peer.fsm.timers.stop_connect_retry();
                peer.fsm.timers.start_delay_open_timer();

                assert_eq!(peer.state(), expected_state);
                assert!(peer.fsm.timers.connect_retry_started.is_none());
                assert!(peer.fsm.timers.delay_open_timer_running());
                assert_eq!(peer.statistics.open_sent, 0);
            }
        }
    }
}
