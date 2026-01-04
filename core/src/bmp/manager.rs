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

use super::client::BmpClient;
use super::destination::{BmpDestination, BmpTcpClient};
use crate::server::{BmpOp, MgmtOp};
use crate::info;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc;

pub struct BmpClientManager {
    rx: mpsc::UnboundedReceiver<BmpOp>,
    clients: HashMap<SocketAddr, mpsc::UnboundedSender<BmpOp>>,
    mgmt_tx: mpsc::Sender<MgmtOp>,
}

impl BmpClientManager {
    pub fn new(rx: mpsc::UnboundedReceiver<BmpOp>, mgmt_tx: mpsc::Sender<MgmtOp>) -> Self {
        Self {
            rx,
            clients: HashMap::new(),
            mgmt_tx,
        }
    }

    pub async fn run(mut self) {
        info!("BMP client manager starting");

        while let Some(op) = self.rx.recv().await {
            match op {
                BmpOp::AddDestination {
                    addr,
                    sys_name,
                    sys_descr,
                    statistics_timeout,
                    response,
                } => {
                    self.add_client(addr, sys_name, sys_descr, statistics_timeout)
                        .await;
                    let _ = response.send(Ok(()));
                }
                BmpOp::RemoveDestination { addr, response } => {
                    self.remove_client(addr);
                    let _ = response.send(Ok(()));
                }
                BmpOp::GetDestinations { response } => {
                    let addrs: Vec<String> =
                        self.clients.keys().map(|a| a.to_string()).collect();
                    let _ = response.send(addrs);
                }
                _ => {
                    // Broadcast to all clients
                    self.broadcast(op).await;
                }
            }
        }
    }

    async fn add_client(
        &mut self,
        addr: SocketAddr,
        sys_name: String,
        sys_descr: String,
        statistics_timeout: Option<u64>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();

        let destination = BmpDestination::TcpClient(BmpTcpClient::new(addr));
        let client = BmpClient::new(addr, destination, rx, self.mgmt_tx.clone(), statistics_timeout);

        tokio::spawn(async move {
            client.run(sys_name, sys_descr).await;
        });

        self.clients.insert(addr, tx);
        info!("BMP client added", "addr" => &addr.to_string());
    }

    fn remove_client(&mut self, addr: SocketAddr) {
        if let Some(tx) = self.clients.remove(&addr) {
            drop(tx); // Drop channel, client task will exit
            info!("BMP client removed", "addr" => &addr.to_string());
        }
    }

    async fn broadcast(&self, op: BmpOp) {
        for tx in self.clients.values() {
            let _ = tx.send(op.clone());
        }
    }
}
