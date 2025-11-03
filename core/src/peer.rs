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

use crate::bgp::msg::Message;
use crate::bgp::msg_keepalive::KeepAliveMessage;
use crate::bgp::msg_open::OpenMessage;
use crate::fsm::{BgpEvent, BgpState, Fsm, FsmAction};
use crate::{debug, info, warn};
use std::io;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;

pub struct Peer {
    pub addr: SocketAddr,
    pub fsm: Fsm,
    pub writer: OwnedWriteHalf,
    pub asn: u16,
    local_asn: u16,
    local_bgp_id: u32,
}

impl Peer {
    pub fn new(
        addr: SocketAddr,
        writer: OwnedWriteHalf,
        asn: u16,
        local_asn: u16,
        local_bgp_id: u32,
    ) -> Self {
        Peer {
            addr,
            fsm: Fsm::new(),
            writer,
            asn,
            local_asn,
            local_bgp_id,
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

    /// Process an FSM event and execute the resulting actions
    pub async fn process_event(&mut self, event: BgpEvent) -> Result<(), io::Error> {
        let transition = self.fsm.process_event(event);

        debug!("FSM transition", "peer_addr" => self.addr.to_string(), "new_state" => format!("{:?}", transition.new_state), "event" => format!("{:?}", event));

        // Execute actions
        for action in transition.actions {
            self.execute_action(action).await?;
        }

        Ok(())
    }

    /// Process multiple FSM events in sequence
    pub async fn process_events(&mut self, events: &[BgpEvent]) -> Result<(), io::Error> {
        for &event in events {
            self.process_event(event).await?;
        }
        Ok(())
    }

    /// Execute an FSM action
    async fn execute_action(&mut self, action: FsmAction) -> Result<(), io::Error> {
        match action {
            FsmAction::InitializeResources => {
                debug!("initializing resources", "peer_addr" => self.addr.to_string());
            }

            FsmAction::ReleaseResources => {
                debug!("releasing resources", "peer_addr" => self.addr.to_string());
            }

            FsmAction::StartConnectRetryTimer => {
                self.fsm.timers.start_connect_retry();
                debug!("started ConnectRetry timer", "peer_addr" => self.addr.to_string());
            }

            FsmAction::StopConnectRetryTimer => {
                self.fsm.timers.stop_connect_retry();
                debug!("stopped ConnectRetry timer", "peer_addr" => self.addr.to_string());
            }

            FsmAction::InitiateTcpConnection => {
                debug!("initiate TCP connection (handled externally)", "peer_addr" => self.addr.to_string());
            }

            FsmAction::CloseTcpConnection => {
                debug!("close TCP connection (handled externally)", "peer_addr" => self.addr.to_string());
            }

            FsmAction::SendOpen => {
                let open_msg = OpenMessage::new(self.local_asn, 180, self.local_bgp_id);
                self.writer.write_all(&open_msg.serialize()).await?;
                info!("sent OPEN message", "peer_addr" => self.addr.to_string());
            }

            FsmAction::SendKeepalive => {
                let keepalive_msg = KeepAliveMessage {};
                self.writer.write_all(&keepalive_msg.serialize()).await?;
                debug!("sent KEEPALIVE message", "peer_addr" => self.addr.to_string());
            }

            FsmAction::SendNotification => {
                warn!("send NOTIFICATION not yet implemented", "peer_addr" => self.addr.to_string());
                // TODO: Implement notification sending with proper error codes
            }

            FsmAction::StartHoldTimer => {
                self.fsm.timers.start_hold_timer();
                debug!("started Hold timer", "peer_addr" => self.addr.to_string());
            }

            FsmAction::ResetHoldTimer => {
                self.fsm.timers.reset_hold_timer();
                debug!("reset Hold timer", "peer_addr" => self.addr.to_string());
            }

            FsmAction::StartKeepaliveTimer => {
                self.fsm.timers.start_keepalive_timer();
                debug!("started Keepalive timer", "peer_addr" => self.addr.to_string());
            }

            FsmAction::ProcessUpdate => {
                debug!("process UPDATE (handled by RIB)", "peer_addr" => self.addr.to_string());
            }
        }

        Ok(())
    }

    /// Set negotiated hold time from received OPEN message
    pub fn set_negotiated_hold_time(&mut self, hold_time: u16) {
        self.fsm.timers.set_negotiated_hold_time(hold_time);
        info!("negotiated hold time", "peer_addr" => self.addr.to_string(), "hold_time_seconds" => hold_time);
    }
}
