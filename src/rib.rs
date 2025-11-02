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

use crate::bgp::msg::BgpMessage;
use std::net::SocketAddr;
use tokio::sync::mpsc;

pub enum RibMessage {
    PeerConnected(SocketAddr),
    PeerDisconnected(SocketAddr),
    BgpMessage { from: SocketAddr, message: BgpMessage },
}

pub struct Rib {
    // For now, just a placeholder
    // Later: add actual routing tables, prefixes, paths, etc.
}

impl Rib {
    pub fn new() -> Self {
        Rib {}
    }

    pub async fn run(mut self, mut rx: mpsc::Receiver<RibMessage>) {
        println!("RIB manager started");

        while let Some(msg) = rx.recv().await {
            match msg {
                RibMessage::PeerConnected(addr) => {
                    println!("RIB: Peer {} connected", addr);
                }
                RibMessage::PeerDisconnected(addr) => {
                    println!("RIB: Peer {} disconnected", addr);
                }
                RibMessage::BgpMessage { from, message } => {
                    self.process_bgp_message(from, message);
                }
            }
        }

        println!("RIB manager stopped");
    }

    fn process_bgp_message(&mut self, from: SocketAddr, message: BgpMessage) {
        match message {
            BgpMessage::Open(open_msg) => {
                println!(
                    "RIB: Processing OPEN from {}: ASN={}, Hold Time={}, BGP ID={}",
                    from, open_msg.asn, open_msg.hold_time, open_msg.bgp_identifier
                );
            }
            BgpMessage::Update(update_msg) => {
                println!("RIB: Processing UPDATE from {}: {:?}", from, update_msg);
                // TODO: Update routing table
            }
            BgpMessage::KeepAlive(_) => {
                println!("RIB: Processing KEEPALIVE from {}", from);
            }
            BgpMessage::Notification(notif_msg) => {
                println!("RIB: Processing NOTIFICATION from {}: {:?}", from, notif_msg);
            }
        }
    }
}
