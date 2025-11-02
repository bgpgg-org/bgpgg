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
use crate::bgp::msg_update::Origin;
use crate::bgp::utils::IpNetwork;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::sync::mpsc;

pub enum RibMessage {
    PeerConnected(SocketAddr),
    PeerDisconnected(SocketAddr),
    BgpMessage { from: SocketAddr, message: BgpMessage },
    QueryRoutes {
        response_tx: tokio::sync::oneshot::Sender<Vec<Route>>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Path {
    pub origin: Origin,
    pub as_path: Vec<u16>,
    pub next_hop: Ipv4Addr,
    pub from_peer: SocketAddr,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub prefix: IpNetwork,
    pub paths: Vec<Path>,
}

pub struct Rib {
    // Map from prefix to Route (which contains multiple paths)
    routes: HashMap<IpNetwork, Route>,
}

impl Rib {
    pub fn new() -> Self {
        Rib {
            routes: HashMap::new(),
        }
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
                    self.remove_routes_from_peer(addr);
                }
                RibMessage::BgpMessage { from, message } => {
                    self.process_bgp_message(from, message);
                }
                RibMessage::QueryRoutes { response_tx } => {
                    let routes = self.get_all_routes();
                    let _ = response_tx.send(routes);
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
                self.process_update(from, update_msg);
            }
            BgpMessage::KeepAlive(_) => {
                println!("RIB: Processing KEEPALIVE from {}", from);
            }
            BgpMessage::Notification(notif_msg) => {
                println!("RIB: Processing NOTIFICATION from {}: {:?}", from, notif_msg);
            }
        }
    }

    fn process_update(&mut self, from: SocketAddr, update_msg: crate::bgp::msg_update::UpdateMessage) {
        // Extract path attributes
        let origin = match update_msg.get_origin() {
            Some(o) => o,
            None => {
                println!("RIB: UPDATE from {} missing Origin attribute, skipping", from);
                return;
            }
        };

        let as_path = match update_msg.get_as_path() {
            Some(p) => p,
            None => {
                println!("RIB: UPDATE from {} missing AS Path attribute, skipping", from);
                return;
            }
        };

        let next_hop = match update_msg.get_next_hop() {
            Some(nh) => nh,
            None => {
                println!("RIB: UPDATE from {} missing Next Hop attribute, skipping", from);
                return;
            }
        };

        // Process NLRI (announced routes)
        for prefix in update_msg.nlri_list() {
            let path = Path {
                origin,
                as_path: as_path.clone(),
                next_hop,
                from_peer: from,
            };

            self.add_route(*prefix, path);
        }

        // Process withdrawn routes
        for prefix in update_msg.withdrawn_routes() {
            self.remove_route(*prefix, from);
        }

        println!("RIB: Total routes in RIB: {}", self.routes.len());
    }

    fn add_route(&mut self, prefix: IpNetwork, path: Path) {
        println!("RIB: Adding route for prefix {:?} from peer {}", prefix, path.from_peer);

        self.routes
            .entry(prefix)
            .and_modify(|route| {
                // Check if we already have a path from this peer, if so replace it
                if let Some(existing_path) = route.paths.iter_mut().find(|p| p.from_peer == path.from_peer) {
                    *existing_path = path.clone();
                    println!("RIB: Updated existing path from peer {}", path.from_peer);
                } else {
                    route.paths.push(path.clone());
                    println!("RIB: Added new path from peer {}", path.from_peer);
                }
            })
            .or_insert_with(|| {
                println!("RIB: Created new route for prefix {:?}", prefix);
                Route {
                    prefix,
                    paths: vec![path],
                }
            });
    }

    fn remove_route(&mut self, prefix: IpNetwork, from_peer: SocketAddr) {
        println!("RIB: Removing route for prefix {:?} from peer {}", prefix, from_peer);

        if let Some(route) = self.routes.get_mut(&prefix) {
            route.paths.retain(|p| p.from_peer != from_peer);

            // If no paths left, remove the entire route
            if route.paths.is_empty() {
                self.routes.remove(&prefix);
                println!("RIB: Removed last path for prefix {:?}", prefix);
            }
        }
    }

    fn remove_routes_from_peer(&mut self, peer_addr: SocketAddr) {
        println!("RIB: Removing all routes from peer {}", peer_addr);

        // Remove all paths from this peer
        for route in self.routes.values_mut() {
            route.paths.retain(|p| p.from_peer != peer_addr);
        }

        // Remove routes that have no paths left
        self.routes.retain(|_, route| !route.paths.is_empty());

        println!("RIB: Cleanup complete. Total routes: {}", self.routes.len());
    }

    fn get_all_routes(&self) -> Vec<Route> {
        self.routes.values().cloned().collect()
    }
}
