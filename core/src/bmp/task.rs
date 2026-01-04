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

use super::destination::{BmpDestination, BmpTcpClient};
use super::msg::BmpMessage;
use super::msg_initiation::InitiationMessage;
use super::msg_peer_down::PeerDownMessage;
use super::msg_peer_up::PeerUpMessage;
use super::msg_route_monitoring::RouteMonitoringMessage;
use super::msg_statistics::{StatType, StatisticsReportMessage, StatisticsTlv};
use super::msg_termination::{TerminationMessage, TerminationReason};
use super::utils::PeerDistinguisher;
use crate::info;
use crate::server::{BmpOp, ServerOp};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

// Batching constants
const MAX_BATCH_SIZE: usize = 100;
const MAX_BATCH_TIME: Duration = Duration::from_millis(100);

/// Manages all BMP tasks (one per destination)
pub struct BmpTaskManager {
    rx: mpsc::UnboundedReceiver<Arc<BmpOp>>,
    tasks: HashMap<SocketAddr, mpsc::UnboundedSender<Arc<BmpOp>>>,
    server_tx: mpsc::UnboundedSender<ServerOp>,
}

impl BmpTaskManager {
    pub fn new(
        rx: mpsc::UnboundedReceiver<Arc<BmpOp>>,
        server_tx: mpsc::UnboundedSender<ServerOp>,
    ) -> Self {
        Self {
            rx,
            tasks: HashMap::new(),
            server_tx,
        }
    }

    pub async fn run(mut self) {
        info!("BMP task manager starting");

        while let Some(op) = self.rx.recv().await {
            // Inspect variant type
            match op.as_ref() {
                BmpOp::AddDestination { .. }
                | BmpOp::RemoveDestination { .. }
                | BmpOp::GetDestinations { .. } => {
                    // Management ops: unwrap Arc (should always succeed - only one reference)
                    let op = match Arc::try_unwrap(op) {
                        Ok(op) => op,
                        Err(_) => panic!("management op should have single reference"),
                    };
                    match op {
                        BmpOp::AddDestination {
                            addr,
                            sys_name,
                            sys_descr,
                            statistics_timeout,
                            response,
                        } => {
                            self.add_task(addr, sys_name, sys_descr, statistics_timeout)
                                .await;
                            let _ = response.send(Ok(()));
                        }
                        BmpOp::RemoveDestination { addr, response } => {
                            self.remove_task(addr);
                            let _ = response.send(Ok(()));
                        }
                        BmpOp::GetDestinations { response } => {
                            let addrs: Vec<String> =
                                self.tasks.keys().map(|a| a.to_string()).collect();
                            let _ = response.send(addrs);
                        }
                        _ => unreachable!(),
                    }
                }
                _ => {
                    // Broadcast operations
                    self.broadcast(op).await;
                }
            }
        }
    }

    async fn add_task(
        &mut self,
        addr: SocketAddr,
        sys_name: String,
        sys_descr: String,
        statistics_timeout: Option<u64>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();

        let destination = BmpDestination::TcpClient(BmpTcpClient::new(addr));
        let task = BmpTask::new(
            addr,
            destination,
            rx,
            self.server_tx.clone(),
            statistics_timeout,
        );

        tokio::spawn(async move {
            task.run(sys_name, sys_descr).await;
        });

        self.tasks.insert(addr, tx);
        info!("BMP task added", "addr" => &addr.to_string());
    }

    fn remove_task(&mut self, addr: SocketAddr) {
        if let Some(tx) = self.tasks.remove(&addr) {
            drop(tx); // Drop channel, task will exit
            info!("BMP task removed", "addr" => &addr.to_string());
        }
    }

    async fn broadcast(&self, op: Arc<BmpOp>) {
        for tx in self.tasks.values() {
            let _ = tx.send(Arc::clone(&op));
        }
    }
}

/// Individual BMP task handling one destination
pub struct BmpTask {
    addr: SocketAddr,
    destination: BmpDestination,
    rx: mpsc::UnboundedReceiver<Arc<BmpOp>>,
    server_tx: mpsc::UnboundedSender<ServerOp>,
    statistics_timeout: Option<u64>,

    // Batching state
    batch: Vec<BmpMessage>,
    last_flush: Instant,
}

impl BmpTask {
    pub fn new(
        addr: SocketAddr,
        destination: BmpDestination,
        rx: mpsc::UnboundedReceiver<Arc<BmpOp>>,
        server_tx: mpsc::UnboundedSender<ServerOp>,
        statistics_timeout: Option<u64>,
    ) -> Self {
        Self {
            addr,
            destination,
            rx,
            server_tx,
            statistics_timeout,
            batch: Vec::new(),
            last_flush: Instant::now(),
        }
    }

    pub async fn run(mut self, sys_name: String, sys_descr: String) {
        info!("BMP task starting", "addr" => &self.addr.to_string());

        // Send Initiation message
        let initiation = BmpMessage::Initiation(InitiationMessage::new(&sys_name, &sys_descr, &[]));
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

        info!("BMP task exiting", "addr" => &self.addr.to_string());
    }

    async fn event_loop(&mut self, mut stats_rx: Option<mpsc::UnboundedReceiver<()>>) {
        loop {
            tokio::select! {
                op = self.rx.recv() => {
                    match op {
                        Some(op) => {
                            if let Some(msg) = self.convert_to_bmp(&op) {
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

    fn convert_to_bmp(&self, op: &BmpOp) -> Option<BmpMessage> {
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
                info!("BMP: Peer Up", "peer_ip" => peer_ip);
                Some(BmpMessage::PeerUp(PeerUpMessage::new(
                    PeerDistinguisher::Global,
                    *peer_ip,
                    *peer_as,
                    *peer_bgp_id,
                    false, // post_policy
                    Some(SystemTime::now()),
                    *local_address,
                    *local_port,
                    *remote_port,
                    sent_open.clone(),
                    received_open.clone(),
                    &[],
                )))
            }
            BmpOp::PeerDown {
                peer_ip,
                peer_as,
                peer_bgp_id,
                reason,
            } => {
                info!("BMP: Peer Down", "peer_ip" => peer_ip);
                Some(BmpMessage::PeerDown(PeerDownMessage::new(
                    PeerDistinguisher::Global,
                    *peer_ip,
                    *peer_as,
                    *peer_bgp_id,
                    false, // post_policy
                    Some(SystemTime::now()),
                    reason.clone(),
                )))
            }
            BmpOp::RouteMonitoring {
                peer_ip,
                peer_as,
                peer_bgp_id,
                update,
            } => Some(BmpMessage::RouteMonitoring(RouteMonitoringMessage::new(
                PeerDistinguisher::Global,
                *peer_ip,
                *peer_as,
                *peer_bgp_id,
                false, // post_policy
                false, // legacy_as_path
                Some(SystemTime::now()),
                update.clone(),
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
                    break; // Task died
                }
            }
        });
    }

    async fn send_statistics(&mut self) {
        let (tx, rx) = oneshot::channel();
        if self
            .server_tx
            .send(ServerOp::GetBmpStatistics { response: tx })
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
