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

use crate::bmp::destination::{BmpDestination, BmpTcpClient};
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

        loop {
            tokio::select! {
                // Receive BmpOp from server
                Some(op) = self.receiver.recv() => {
                    match op {
                        BmpOp::AddDestination { addr, sys_name, sys_descr, response } => {
                            info!("BMP: Adding destination", "addr" => &addr.to_string());
                            let mut dest = BmpDestination::TcpClient(BmpTcpClient::new(addr));

                            // Send Initiation message to new destination immediately
                            let initiation = BmpMessage::Initiation(InitiationMessage::new(
                                &sys_name,
                                &sys_descr,
                                &[],
                            ));
                            dest.send(&initiation).await;

                            self.destinations.push(dest);
                            let _ = response.send(Ok(()));
                        }
                        BmpOp::RemoveDestination { addr, response } => {
                            info!("BMP: Removing destination", "addr" => &addr.to_string());
                            self.destinations.retain(|d| match d {
                                BmpDestination::TcpClient(client) => client.addr() != addr,
                            });
                            let _ = response.send(Ok(()));
                        }
                        BmpOp::GetDestinations { response } => {
                            let addrs: Vec<String> = self.destinations.iter().map(|d| match d {
                                BmpDestination::TcpClient(client) => client.addr().to_string(),
                            }).collect();
                            let _ = response.send(addrs);
                        }
                        _ => {
                            if let Some(msg) = self.convert_to_bmp(op) {
                                self.batch.push(msg);

                                // Flush if batch full
                                if self.batch.len() >= MAX_BATCH_SIZE {
                                    self.flush().await;
                                }
                            }
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
            BmpOp::PeerDown {
                peer_ip,
                peer_as,
                peer_bgp_id,
                reason,
            } => {
                info!("BMP: Peer Down", "peer_ip" => &peer_ip);
                Some(BmpMessage::PeerDown(PeerDownMessage::new(
                    PeerDistinguisher::Global,
                    peer_ip,
                    peer_as,
                    peer_bgp_id,
                    false, // post_policy
                    Some(SystemTime::now()),
                    reason,
                )))
            }
            BmpOp::AddDestination { .. }
            | BmpOp::RemoveDestination { .. }
            | BmpOp::GetDestinations { .. } => {
                // Management ops handled in main loop, not converted to BMP messages
                None
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
