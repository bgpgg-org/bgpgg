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
use super::{Peer, PeerError, PeerOp};
use crate::debug;
use std::time::Duration;

impl Peer {
    /// Handle Idle state - wait for ManualStart or AutomaticStart.
    /// Returns true if shutdown requested.
    pub(super) async fn handle_idle_state(&mut self) -> bool {
        if self.config.passive_mode {
            self.handle_idle_state_passive().await
        } else {
            self.handle_idle_state_active().await
        }
    }

    /// Passive mode: wait for start event or IdleHoldTimer to transition to Active.
    /// RFC 4271 8.1.2: Event 7 (AutomaticStart_with_DampPeerOscillations_and_PassiveTcpEstablishment)
    /// and Event 13 (IdleHoldTimer_Expires) apply to passive peers.
    async fn handle_idle_state_passive(&mut self) -> bool {
        let idle_hold_time = self.get_idle_hold_time();
        let auto_reconnect = idle_hold_time.is_some() && !self.manually_stopped;
        let idle_hold_time = idle_hold_time.unwrap_or(Duration::ZERO);

        tokio::select! {
            op = self.peer_rx.recv() => {
                match op {
                    Some(PeerOp::ManualStartPassive) => {
                        debug!("ManualStartPassive received", "peer_ip" => self.addr.to_string());
                        self.manually_stopped = false;
                        self.try_process_event(&FsmEvent::ManualStartPassive).await;
                    }
                    Some(PeerOp::AutomaticStartPassive) => {
                        debug!("AutomaticStartPassive received", "peer_ip" => self.addr.to_string());
                        self.try_process_event(&FsmEvent::AutomaticStartPassive).await;
                    }
                    Some(PeerOp::Shutdown(_)) => return true,
                    Some(PeerOp::GetStatistics(response)) => {
                        let _ = response.send(self.statistics.clone());
                    }
                    Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                        // RFC 4271 8.2.2: In Idle state, refuse incoming connections
                        debug!("connection refused in Idle state", "peer_ip" => self.addr.to_string());
                        drop(tcp_tx);
                        drop(tcp_rx);
                    }
                    Some(_) => {}
                    None => return true,
                }
            }
            _ = tokio::time::sleep(idle_hold_time), if auto_reconnect => {
                // RFC 4271 Event 13: IdleHoldTimer_Expires
                debug!("IdleHoldTimer expired", "peer_ip" => self.addr.to_string());
                self.try_process_event(&FsmEvent::IdleHoldTimerExpires).await;
            }
        }
        false
    }

    /// Non-passive mode: wait for ManualStart, AutomaticStart, or auto-reconnect timer.
    async fn handle_idle_state_active(&mut self) -> bool {
        let idle_hold_time = self.get_idle_hold_time();
        let auto_reconnect = idle_hold_time.is_some() && !self.manually_stopped;
        let idle_hold_time = idle_hold_time.unwrap_or(Duration::ZERO);

        tokio::select! {
            op = self.peer_rx.recv() => {
                match op {
                    Some(PeerOp::ManualStart) => {
                        debug!("ManualStart received", "peer_ip" => self.addr.to_string());
                        self.manually_stopped = false;
                        self.try_process_event(&FsmEvent::ManualStart).await;
                    }
                    Some(PeerOp::AutomaticStart) => {
                        debug!("AutomaticStart received", "peer_ip" => self.addr.to_string());
                        self.try_process_event(&FsmEvent::AutomaticStart).await;
                    }
                    Some(PeerOp::Shutdown(_)) => return true,
                    Some(PeerOp::GetStatistics(response)) => {
                        let _ = response.send(self.statistics.clone());
                    }
                    Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                        // RFC 4271 8.2.2: In Idle state, refuse incoming connections
                        debug!("connection refused in Idle state", "peer_ip" => self.addr.to_string());
                        drop(tcp_tx);
                        drop(tcp_rx);
                    }
                    Some(_) => {}
                    None => return true,
                }
            }
            _ = tokio::time::sleep(idle_hold_time), if auto_reconnect => {
                // RFC 4271 Event 13: IdleHoldTimer_Expires
                debug!("IdleHoldTimer expired", "peer_ip" => self.addr.to_string());
                self.try_process_event(&FsmEvent::IdleHoldTimerExpires).await;
            }
        }
        false
    }

    /// Handle Idle state transitions.
    pub(super) async fn handle_idle_transitions(
        &mut self,
        new_state: BgpState,
        _event: &FsmEvent,
    ) -> Result<(), PeerError> {
        match new_state {
            // RFC 4271 8.2.2: Initialize resources and start ConnectRetryTimer when leaving Idle
            BgpState::Connect | BgpState::Active => {
                self.fsm.reset_connect_retry_counter();
                self.fsm.timers.start_connect_retry();
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
    async fn test_connect_retry_timer_started_on_idle_transition() {
        let test_cases = vec![
            (FsmEvent::ManualStart, BgpState::Connect),
            (FsmEvent::AutomaticStart, BgpState::Connect),
            (FsmEvent::ManualStartPassive, BgpState::Active),
            (FsmEvent::AutomaticStartPassive, BgpState::Active),
        ];

        for (event, expected_state) in test_cases {
            let mut peer = create_test_peer(BgpState::Idle).await;
            assert!(
                peer.fsm.timers.connect_retry_started.is_none(),
                "ConnectRetryTimer should not be started initially"
            );

            peer.process_event(&event).await.unwrap();

            assert_eq!(
                peer.state(),
                expected_state,
                "State should transition to {:?}",
                expected_state
            );
            assert_eq!(
                peer.fsm.connect_retry_counter, 0,
                "ConnectRetryCounter should be set to 0 after {:?}",
                event
            );
            assert!(
                peer.fsm.timers.connect_retry_started.is_some(),
                "ConnectRetryTimer should be started after {:?}",
                event
            );
        }
    }
}
