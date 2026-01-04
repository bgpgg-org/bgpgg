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

use super::destination::BmpDestination;
use super::msg::BmpMessage;
use super::msg_initiation::InitiationMessage;
use super::msg_peer_down::PeerDownMessage;
use super::msg_peer_up::PeerUpMessage;
use super::msg_route_monitoring::RouteMonitoringMessage;
use super::msg_statistics::{StatType, StatisticsReportMessage, StatisticsTlv};
use super::msg_termination::{TerminationMessage, TerminationReason};
use super::utils::PeerDistinguisher;
use crate::server::{BmpOp, MgmtOp};
use crate::info;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

// Batching constants
const MAX_BATCH_SIZE: usize = 100;
const MAX_BATCH_TIME: Duration = Duration::from_millis(100);

pub struct BmpClient {
    addr: SocketAddr,
    destination: BmpDestination,
    rx: mpsc::UnboundedReceiver<BmpOp>,
    mgmt_tx: mpsc::Sender<MgmtOp>,
    statistics_timeout: Option<u64>,

    // Batching state
    batch: Vec<BmpMessage>,
    last_flush: Instant,
}

impl BmpClient {
    pub fn new(
        addr: SocketAddr,
        destination: BmpDestination,
        rx: mpsc::UnboundedReceiver<BmpOp>,
        mgmt_tx: mpsc::Sender<MgmtOp>,
        statistics_timeout: Option<u64>,
    ) -> Self {
        Self {
            addr,
            destination,
            rx,
            mgmt_tx,
            statistics_timeout,
            batch: Vec::new(),
            last_flush: Instant::now(),
        }
    }

    pub async fn run(mut self, sys_name: String, sys_descr: String) {
        info!("BMP client starting", "addr" => &self.addr.to_string());

        // Send Initiation message
        let initiation = BmpMessage::Initiation(InitiationMessage::new(
            &sys_name,
            &sys_descr,
            &[],
        ));
        self.destination.send(&initiation).await;

        // Spawn statistics timer if configured
        let stats_rx = if let Some(timeout_secs) = self.statistics_timeout {
            if timeout_secs > 0 {
                let (tx, rx) = mpsc::unbounded_channel();
                self.spawn_statistics_timer(timeout_secs, tx);
                Some(rx)
            } else {
                None
            }
        } else {
            None
        };

        // Main event loop
        self.event_loop(stats_rx).await;

        // Flush any pending batched messages before sending Termination
        if !self.batch.is_empty() {
            self.flush().await;
        }

        // Send Termination message before exiting
        let termination = BmpMessage::Termination(TerminationMessage::new(
            TerminationReason::PermanentlyAdminClose,
            &[],
        ));
        self.destination.send(&termination).await;

        info!("BMP client exiting", "addr" => &self.addr.to_string());
    }

    async fn event_loop(&mut self, mut stats_rx: Option<mpsc::UnboundedReceiver<()>>) {
        loop {
            tokio::select! {
                op = self.rx.recv() => {
                    match op {
                        Some(op) => {
                            if let Some(msg) = self.convert_to_bmp(op) {
                                self.batch.push(msg);

                                // Flush if batch full
                                if self.batch.len() >= MAX_BATCH_SIZE {
                                    self.flush().await;
                                }
                            }
                        }
                        None => break, // Channel closed, exit
                    }
                }
                Some(_) = async {
                    match &mut stats_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.send_statistics().await;
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

    async fn flush(&mut self) {
        if self.batch.is_empty() {
            return;
        }

        info!("BMP: Flushing batch", "addr" => &self.addr.to_string(), "count" => self.batch.len());
        self.destination.send_batch(&self.batch).await;
        self.batch.clear();
        self.last_flush = Instant::now();
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
                    &[],
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
            BmpOp::RouteMonitoring {
                peer_ip,
                peer_as,
                peer_bgp_id,
                update,
            } => Some(BmpMessage::RouteMonitoring(RouteMonitoringMessage::new(
                PeerDistinguisher::Global,
                peer_ip,
                peer_as,
                peer_bgp_id,
                false, // post_policy
                false, // legacy_as_path
                Some(SystemTime::now()),
                update,
            ))),
            BmpOp::Statistics { .. } => None, // Ignore broadcast stats
            BmpOp::AddDestination { .. }
            | BmpOp::RemoveDestination { .. }
            | BmpOp::GetDestinations { .. } => None,
        }
    }

    fn spawn_statistics_timer(&self, timeout_secs: u64, tx: mpsc::UnboundedSender<()>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(timeout_secs));
            interval.tick().await; // Skip first immediate tick

            loop {
                interval.tick().await;
                if tx.send(()).is_err() {
                    break; // Client task died
                }
            }
        });
    }

    async fn send_statistics(&mut self) {
        let (tx, rx) = oneshot::channel();
        if self
            .mgmt_tx
            .send(MgmtOp::GetBmpStatistics { response: tx })
            .await
            .is_err()
        {
            return;
        }

        let Ok(stats) = rx.await else { return };

        for peer_stat in stats {
            let tlvs = vec![StatisticsTlv::new_counter64(
                StatType::RoutesInAdjRibIn,
                peer_stat.adj_rib_in_count,
            )];

            let msg = BmpMessage::StatisticsReport(StatisticsReportMessage::new(
                PeerDistinguisher::Global,
                peer_stat.peer_ip,
                peer_stat.peer_as,
                peer_stat.peer_bgp_id,
                Some(SystemTime::now()),
                tlvs,
            ));

            self.destination.send(&msg).await;
        }
    }
}
