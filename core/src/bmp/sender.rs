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

use crate::bmp::destination::BmpDestination;
use crate::bmp::msg::BmpMessage;
use crate::bmp::msg_initiation::InitiationMessage;
use crate::bmp::msg_peer_down::PeerDownMessage;
use crate::bmp::msg_peer_up::PeerUpMessage;
use crate::bmp::utils::PeerDistinguisher;
use crate::info;
use crate::server::BmpOp;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::time::Instant;

// Batching constants
const MAX_BATCH_SIZE: usize = 100;
const MAX_BATCH_TIME: Duration = Duration::from_millis(100);

pub struct BmpSender {
    receiver: mpsc::UnboundedReceiver<BmpOp>,
    destinations: Vec<BmpDestination>,

    // Batching state
    batch: Vec<BmpMessage>,
    last_flush: Instant,
}

impl BmpSender {
    pub fn new(receiver: mpsc::UnboundedReceiver<BmpOp>) -> Self {
        Self {
            receiver,
            destinations: Vec::new(),
            batch: Vec::new(),
            last_flush: Instant::now(),
        }
    }

    pub fn add_destination(&mut self, dest: BmpDestination) {
        self.destinations.push(dest);
    }

    pub async fn run(mut self) {
        info!("BMP sender task starting");

        // Send Initiation message on startup
        let initiation = BmpMessage::Initiation(InitiationMessage::new(
            "bgpgg",
            "bgpgg BGP implementation",
            &[],
        ));
        self.batch.push(initiation);
        self.flush().await;

        loop {
            tokio::select! {
                // Receive BmpOp from server
                Some(op) = self.receiver.recv() => {
                    if let Some(msg) = self.convert_to_bmp(op) {
                        self.batch.push(msg);

                        // Flush if batch full
                        if self.batch.len() >= MAX_BATCH_SIZE {
                            self.flush().await;
                        }
                    }
                }

                // Periodic flush on timeout
                _ = tokio::time::sleep_until(self.last_flush + MAX_BATCH_TIME) => {
                    if !self.batch.is_empty() {
                        self.flush().await;
                    }
                }
            }
        }
    }

    fn convert_to_bmp(&self, op: BmpOp) -> Option<BmpMessage> {
        match op {
            BmpOp::PeerUp {
                peer_ip,
                peer_as,
                peer_bgp_id,
                local_address,
                local_port,
                remote_port,
                sent_open,
                received_open,
            } => {
                info!("BMP: Peer Up", "peer_ip" => &peer_ip);
                Some(BmpMessage::PeerUp(PeerUpMessage::new(
                    PeerDistinguisher::Global,
                    peer_ip,
                    peer_as,
                    peer_bgp_id,
                    false, // post_policy
                    Some(SystemTime::now()),
                    local_address,
                    local_port,
                    remote_port,
                    sent_open,
                    received_open,
                    &[], // No Information strings for now
                )))
            }
            BmpOp::PeerDown { peer_ip, reason } => {
                info!("BMP: Peer Down", "peer_ip" => &peer_ip);
                // We need peer AS and BGP ID, but we don't have them in PeerDown event
                // For now, use placeholder values - we'll improve this later
                // TODO: Store peer info in BmpSender or pass more info in PeerDown
                Some(BmpMessage::PeerDown(PeerDownMessage::new(
                    PeerDistinguisher::Global,
                    peer_ip,
                    0,     // peer_as - TODO: get from state
                    0,     // peer_bgp_id - TODO: get from state
                    false, // post_policy
                    Some(SystemTime::now()),
                    reason,
                )))
            }
        }
    }

    async fn flush(&mut self) {
        if self.batch.is_empty() {
            return;
        }

        info!("BMP: Flushing batch", "count" => self.batch.len());

        // Send batch to all destinations
        for dest in &mut self.destinations {
            dest.send_batch(&self.batch).await;
        }

        self.batch.clear();
        self.last_flush = Instant::now();
    }
}
