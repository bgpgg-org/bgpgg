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

use crate::bgp::msg::{read_bgp_message, BgpMessage, Message};
use crate::bgp::msg_keepalive::KeepAliveMessage;
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin, UpdateMessage};
use crate::bgp::utils::IpNetwork;
use crate::peer::{Peer, PeerState};
use crate::rib::RibHandle;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

pub struct BgpServer {
    pub peers: Arc<Mutex<Vec<Peer>>>,
    pub rib: RibHandle,
    local_asn: u16,
    local_bgp_id: u32,
}

impl BgpServer {
    pub fn new(local_asn: u16) -> Self {
        // Generate a BGP ID from the local ASN (simple approach for testing)
        // In production, this would typically be derived from a router ID
        let local_bgp_id = ((local_asn as u32) << 16) | (local_asn as u32);

        BgpServer {
            peers: Arc::new(Mutex::new(Vec::new())),
            rib: RibHandle::spawn(local_asn),
            local_asn,
            local_bgp_id,
        }
    }

    /// Add a peer and initiate BGP session
    pub async fn add_peer(&self, peer_addr: &str) {
        let peers_arc = Arc::clone(&self.peers);
        let rib = self.rib.clone();
        let local_asn = self.local_asn;
        let local_bgp_id = self.local_bgp_id;
        let peer_addr_string = peer_addr.to_string();

        tokio::spawn(async move {
            Self::initiate_peer_connection(
                &peer_addr_string,
                local_asn,
                local_bgp_id,
                peers_arc,
                rib,
            )
            .await;
        });
    }

    async fn initiate_peer_connection(
        peer_addr: &str,
        local_asn: u16,
        local_bgp_id: u32,
        peers: Arc<Mutex<Vec<Peer>>>,
        rib: RibHandle,
    ) {
        println!("Attempting to connect to peer at {}", peer_addr);

        // Connect to the peer
        let stream = match TcpStream::connect(peer_addr).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to connect to peer {}: {}", peer_addr, e);
                return;
            }
        };

        let addr = match stream.peer_addr() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Failed to get peer address: {}", e);
                return;
            }
        };

        println!("Connected to peer at {}", addr);

        let (read_half, mut write_half) = stream.into_split();

        // Send OPEN message
        let open_msg = OpenMessage::new(local_asn, 180, local_bgp_id);
        if let Err(e) = write_half.write_all(&open_msg.serialize()).await {
            eprintln!("Failed to send OPEN to {}: {}", addr, e);
            return;
        }
        println!("Sent OPEN to {}", addr);

        // Send KEEPALIVE message
        let keepalive_msg = KeepAliveMessage {};
        if let Err(e) = write_half.write_all(&keepalive_msg.serialize()).await {
            eprintln!("Failed to send KEEPALIVE to {}: {}", addr, e);
            return;
        }
        println!("Sent KEEPALIVE to {}", addr);

        // Handle incoming messages from this peer (will add peer after receiving OPEN)
        Self::handle_peer(read_half, write_half, addr, peers, rib).await;
    }

    pub async fn get_routes(&self) -> Vec<crate::rib::Route> {
        self.rib.query_loc_rib().await.unwrap_or_else(|_| vec![])
    }

    /// Announce a route to all established peers
    pub async fn announce_route(
        &self,
        prefix: IpNetwork,
        next_hop: Ipv4Addr,
        origin: Origin,
    ) -> Result<(), std::io::Error> {
        // Build AS path with local ASN
        let as_path_segments = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 1,
            asn_list: vec![self.local_asn],
        }];

        // Create UPDATE message
        let update_msg = UpdateMessage::new(origin, as_path_segments, next_hop, vec![prefix]);

        // Send to all established peers
        let mut peers = self.peers.lock().await;
        for peer in peers.iter_mut() {
            if let Err(e) = peer.writer.write_all(&update_msg.serialize()).await {
                eprintln!("Failed to send UPDATE to peer {}: {}", peer.addr, e);
            } else {
                println!(
                    "Announced route {:?} with next hop {} to peer {}",
                    prefix, next_hop, peer.addr
                );
            }
        }

        Ok(())
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
                    self.accept_peer(stream).await;
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }
    }

    async fn accept_peer(&self, stream: TcpStream) {
        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("Failed to get peer address: {}", e);
                return;
            }
        };

        println!("New peer connection from: {}", peer_addr);

        let (read_half, mut write_half) = stream.into_split();

        // Send OPEN message
        let open_msg = OpenMessage::new(self.local_asn, 180, self.local_bgp_id);
        if let Err(e) = write_half.write_all(&open_msg.serialize()).await {
            eprintln!("Failed to send OPEN to {}: {}", peer_addr, e);
            return;
        }
        println!("Sent OPEN to {}", peer_addr);

        // Send KEEPALIVE message
        let keepalive_msg = KeepAliveMessage {};
        if let Err(e) = write_half.write_all(&keepalive_msg.serialize()).await {
            eprintln!("Failed to send KEEPALIVE to {}: {}", peer_addr, e);
            return;
        }
        println!("Sent KEEPALIVE to {}", peer_addr);

        let peers_arc = Arc::clone(&self.peers);
        let rib = self.rib.clone();

        tokio::spawn(async move {
            Self::handle_peer(read_half, write_half, peer_addr, peers_arc, rib).await;
        });
    }

    async fn handle_peer(
        mut read_half: tokio::net::tcp::OwnedReadHalf,
        write_half: tokio::net::tcp::OwnedWriteHalf,
        addr: SocketAddr,
        peers: Arc<Mutex<Vec<Peer>>>,
        rib: RibHandle,
    ) {
        println!("Handling peer: {}", addr);

        // First, wait for OPEN message
        let peer_asn = loop {
            let result = read_bgp_message(&mut read_half).await;

            match result {
                Ok(message) => {
                    match message {
                        BgpMessage::Open(open_msg) => {
                            println!(
                                "Received OPEN from {}: ASN={}, Hold Time={}, BGP ID={}",
                                addr, open_msg.asn, open_msg.hold_time, open_msg.bgp_identifier
                            );
                            break open_msg.asn;
                        }
                        _ => {
                            eprintln!("Expected OPEN as first message from {}, got something else", addr);
                            return;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading first message from {}: {:?}", addr, e);
                    return;
                }
            }
        };

        // Now add the peer with the ASN we received
        let peer = Peer::new(addr, write_half, peer_asn);
        {
            let mut peer_list = peers.lock().await;
            peer_list.push(peer);
            println!("Peer {} added with ASN {}. Total peers: {}", addr, peer_asn, peer_list.len());
        }

        // Notify RIB about new peer
        let _ = rib.peer_connected(addr).await;

        // Update peer state to OpenConfirm
        Self::update_peer_state(&peers, addr, PeerState::OpenConfirm).await;

        // Now continue handling subsequent messages
        loop {
            let result = read_bgp_message(&mut read_half).await;

            match result {
                Ok(message) => {
                    match &message {
                        BgpMessage::Open(_) => {
                            eprintln!("Received duplicate OPEN from {}, ignoring", addr);
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
                    let _ = rib.process_bgp_message(addr, message).await;
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
        let _ = rib.peer_disconnected(addr).await;
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
