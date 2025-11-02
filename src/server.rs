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

use crate::bgp::msg::{read_bgp_message, BgpMessage};
use crate::peer::{Peer, PeerState};
use crate::rib::RibMessage;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

pub struct BgpServer {
    pub peers: Arc<Mutex<Vec<Peer>>>,
    pub rib_tx: mpsc::Sender<RibMessage>,
}

impl BgpServer {
    pub fn new() -> Self {
        // Create channel for RIB communication
        let (rib_tx, rib_rx) = mpsc::channel(100);

        // Create and spawn RIB actor
        let rib = crate::rib::Rib::new();
        tokio::spawn(async move {
            rib.run(rib_rx).await;
        });

        BgpServer {
            peers: Arc::new(Mutex::new(Vec::new())),
            rib_tx,
        }
    }

    pub async fn get_routes(&self) -> Vec<crate::rib::Route> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

        // Send query message to RIB
        let _ = self.rib_tx.send(RibMessage::QueryRoutes { response_tx }).await;

        // Wait for response
        response_rx.await.unwrap_or_else(|_| vec![])
    }

    pub async fn run(&self) {
        self.run_on("127.0.0.1:179").await;
    }

    pub async fn run_on(&self, addr: &str) {
        println!("Bgpgg server is running on {}", addr);
        let listener = TcpListener::bind(addr).await.unwrap();

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    self.add_peer(stream).await;
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }
    }

    async fn add_peer(&self, stream: TcpStream) {
        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("Failed to get peer address: {}", e);
                return;
            }
        };

        println!("New peer connection from: {}", peer_addr);

        let peer = Peer::new(peer_addr);

        // Add peer to the shared list
        {
            let mut peers = self.peers.lock().await;
            peers.push(peer);
            println!("Peer {} added. Total peers: {}", peer_addr, peers.len());
        }

        // Notify RIB about new peer
        let _ = self.rib_tx.send(RibMessage::PeerConnected(peer_addr)).await;

        let peers_arc = Arc::clone(&self.peers);
        let rib_tx = self.rib_tx.clone();

        tokio::spawn(async move {
            Self::handle_peer(stream, peer_addr, peers_arc, rib_tx).await;
        });
    }

    async fn handle_peer(
        stream: TcpStream,
        addr: SocketAddr,
        peers: Arc<Mutex<Vec<Peer>>>,
        rib_tx: mpsc::Sender<RibMessage>,
    ) {
        println!("Handling peer: {}", addr);

        // Convert to std::net::TcpStream for read_bgp_message
        // (since read_bgp_message uses std::io::Read trait)
        let std_stream = stream.into_std().unwrap();

        // Set to blocking mode (into_std() creates a non-blocking stream)
        std_stream.set_nonblocking(false).unwrap();

        loop {
            // Use spawn_blocking to avoid blocking the async runtime
            let result = tokio::task::spawn_blocking({
                let stream_clone = std_stream.try_clone().expect("Failed to clone stream");
                move || read_bgp_message(&stream_clone)
            })
            .await
            .expect("Task panicked");

            match result {
                Ok(message) => {
                    match &message {
                        BgpMessage::Open(open_msg) => {
                            println!(
                                "Received OPEN from {}: ASN={}, Hold Time={}, BGP ID={}",
                                addr, open_msg.asn, open_msg.hold_time, open_msg.bgp_identifier
                            );
                            // Update peer state to OpenConfirm
                            Self::update_peer_state(&peers, addr, PeerState::OpenConfirm).await;
                        }
                        BgpMessage::Update(_) => {
                            println!("Received UPDATE from {}", addr);
                        }
                        BgpMessage::KeepAlive(_) => {
                            println!("Received KEEPALIVE from {}", addr);
                            // Update peer state to Established if not already
                            Self::update_peer_state(&peers, addr, PeerState::Established).await;
                        }
                        BgpMessage::Notification(notif_msg) => {
                            println!("Received NOTIFICATION from {}: {:?}", addr, notif_msg);
                            break;
                        }
                    }

                    // Send message to RIB
                    let _ = rib_tx
                        .send(RibMessage::BgpMessage {
                            from: addr,
                            message,
                        })
                        .await;
                }
                Err(e) => {
                    eprintln!("Error reading message from {}: {:?}", addr, e);
                    break;
                }
            }
        }

        // Remove peer from the list when disconnected
        {
            let mut peer_list = peers.lock().await;
            peer_list.retain(|p| p.addr != addr);
            println!(
                "Peer {} disconnected. Total peers: {}",
                addr,
                peer_list.len()
            );
        }

        // Notify RIB about disconnection
        let _ = rib_tx.send(RibMessage::PeerDisconnected(addr)).await;
    }

    async fn update_peer_state(
        peers: &Arc<Mutex<Vec<Peer>>>,
        addr: SocketAddr,
        new_state: PeerState,
    ) {
        let mut peer_list = peers.lock().await;
        if let Some(peer) = peer_list.iter_mut().find(|p| p.addr == addr) {
            peer.state = new_state;
            println!("Peer {} state updated to {:?}", addr, peer.state);
        }
    }
}
