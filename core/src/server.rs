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
use crate::config::Config;
use crate::fsm::{BgpEvent, BgpState};
use crate::peer::Peer;
use crate::rib::RibHandle;
use crate::{debug, error, info, warn};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};

// Commands that can be sent to the BGP server
pub enum BgpCommand {
    AddPeer {
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemovePeer {
        addr: SocketAddr,
        response: oneshot::Sender<Result<(), String>>,
    },
    AnnounceRoute {
        prefix: IpNetwork,
        next_hop: Ipv4Addr,
        origin: Origin,
        response: oneshot::Sender<Result<(), String>>,
    },
}

pub struct BgpServer {
    pub peers: Arc<Mutex<Vec<Peer>>>,
    pub rib: RibHandle,
    pub command_tx: mpsc::Sender<BgpCommand>,
    config: Config,
    local_bgp_id: u32,
    command_rx: Option<mpsc::Receiver<BgpCommand>>,
}

impl BgpServer {
    pub fn new(config: Config) -> Self {
        // Convert the configured router_id (Ipv4Addr) to u32 for BGP identifier
        let local_bgp_id = u32::from(config.router_id);

        let (cmd_tx, cmd_rx) = mpsc::channel(100);
        let peers = Arc::new(Mutex::new(Vec::new()));
        let rib = RibHandle::spawn(config.asn);

        BgpServer {
            peers,
            rib,
            command_tx: cmd_tx,
            config,
            local_bgp_id,
            command_rx: Some(cmd_rx),
        }
    }

    /// Add a peer and initiate BGP session
    pub async fn add_peer(&self, peer_addr: &str) {
        let peers_arc = Arc::clone(&self.peers);
        let rib = self.rib.clone();
        let local_asn = self.config.asn;
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
        info!("attempting to connect to peer", "peer_addr" => peer_addr);

        // Connect to the peer
        let stream = match TcpStream::connect(peer_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!("failed to connect to peer", "peer_addr" => peer_addr, "error" => e.to_string());
                return;
            }
        };

        let addr = match stream.peer_addr() {
            Ok(a) => a,
            Err(e) => {
                error!("failed to get peer address", "error" => e.to_string());
                return;
            }
        };

        info!("connected to peer", "peer_addr" => addr.to_string());

        let (read_half, mut write_half) = stream.into_split();

        // Send OPEN message
        let open_msg = OpenMessage::new(local_asn, 180, local_bgp_id);
        if let Err(e) = write_half.write_all(&open_msg.serialize()).await {
            error!("failed to send OPEN", "peer_addr" => addr.to_string(), "error" => e.to_string());
            return;
        }
        info!("sent OPEN", "peer_addr" => addr.to_string());

        // Send KEEPALIVE message
        let keepalive_msg = KeepAliveMessage {};
        if let Err(e) = write_half.write_all(&keepalive_msg.serialize()).await {
            error!("failed to send KEEPALIVE", "peer_addr" => addr.to_string(), "error" => e.to_string());
            return;
        }
        info!("sent KEEPALIVE", "peer_addr" => addr.to_string());

        // Handle incoming messages from this peer (will add peer after receiving OPEN)
        Self::handle_peer(
            read_half,
            write_half,
            addr,
            local_asn,
            local_bgp_id,
            peers,
            rib,
        )
        .await;
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
            asn_list: vec![self.config.asn],
        }];

        // Create UPDATE message
        let update_msg = UpdateMessage::new(origin, as_path_segments, next_hop, vec![prefix]);

        // Send to all established peers
        let mut peers = self.peers.lock().await;
        for peer in peers.iter_mut() {
            // Only send to peers in Established state
            if peer.state() == BgpState::Established {
                if let Err(e) = peer.writer.write_all(&update_msg.serialize()).await {
                    error!("failed to send UPDATE to peer", "peer_addr" => peer.addr.to_string(), "error" => e.to_string());
                } else {
                    info!("announced route to peer", "prefix" => format!("{:?}", prefix), "next_hop" => next_hop.to_string(), "peer_addr" => peer.addr.to_string());
                }
            } else {
                debug!("skipping peer not in established state", "peer_addr" => peer.addr.to_string(), "state" => format!("{:?}", peer.state()));
            }
        }

        Ok(())
    }

    pub async fn run(&mut self) {
        let addr = self.config.listen_addr.clone();
        info!("BGP server starting", "listen_addr" => addr);

        let listener = TcpListener::bind(&addr).await.unwrap();
        let mut cmd_rx = self.command_rx.take().expect("event loop already running");

        // Unified event loop: handle both BGP connections and gRPC commands
        loop {
            tokio::select! {
                // Handle incoming BGP connections
                Ok((stream, _)) = listener.accept() => {
                    self.accept_peer(stream).await;
                }

                // Handle gRPC commands
                Some(cmd) = cmd_rx.recv() => {
                    self.handle_command(cmd).await;
                }
            }
        }
    }

    async fn handle_command(&self, cmd: BgpCommand) {
        match cmd {
            BgpCommand::AddPeer { addr, response } => {
                info!("adding peer via command", "peer_addr" => &addr);
                self.add_peer(&addr).await;
                let _ = response.send(Ok(()));
            }
            BgpCommand::RemovePeer { addr, response } => {
                info!("removing peer via command", "peer_addr" => addr.to_string());

                // Remove peer from list
                let mut peers = self.peers.lock().await;
                let initial_len = peers.len();
                peers.retain(|p| p.addr != addr);
                let removed = initial_len > peers.len();
                drop(peers);

                // Notify RIB
                let _ = self.rib.peer_disconnected(addr).await;

                if removed {
                    let _ = response.send(Ok(()));
                } else {
                    let _ = response.send(Err(format!("peer {} not found", addr)));
                }
            }
            BgpCommand::AnnounceRoute {
                prefix,
                next_hop,
                origin,
                response,
            } => {
                info!("announcing route via command", "prefix" => format!("{:?}", prefix), "next_hop" => next_hop.to_string());
                match self.announce_route(prefix, next_hop, origin).await {
                    Ok(_) => {
                        let _ = response.send(Ok(()));
                    }
                    Err(e) => {
                        let _ = response.send(Err(e.to_string()));
                    }
                }
            }
        }
    }

    async fn accept_peer(&self, stream: TcpStream) {
        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!("failed to get peer address", "error" => e.to_string());
                return;
            }
        };

        info!("new peer connection", "peer_addr" => peer_addr.to_string());

        let (read_half, mut write_half) = stream.into_split();

        // Send OPEN message
        let open_msg = OpenMessage::new(self.config.asn, 180, self.local_bgp_id);
        if let Err(e) = write_half.write_all(&open_msg.serialize()).await {
            error!("failed to send OPEN", "peer_addr" => peer_addr.to_string(), "error" => e.to_string());
            return;
        }
        info!("sent OPEN", "peer_addr" => peer_addr.to_string());

        // Send KEEPALIVE message
        let keepalive_msg = KeepAliveMessage {};
        if let Err(e) = write_half.write_all(&keepalive_msg.serialize()).await {
            error!("failed to send KEEPALIVE", "peer_addr" => peer_addr.to_string(), "error" => e.to_string());
            return;
        }
        info!("sent KEEPALIVE", "peer_addr" => peer_addr.to_string());

        let peers_arc = Arc::clone(&self.peers);
        let rib = self.rib.clone();
        let local_asn = self.config.asn;
        let local_bgp_id = self.local_bgp_id;

        tokio::spawn(async move {
            Self::handle_peer(
                read_half,
                write_half,
                peer_addr,
                local_asn,
                local_bgp_id,
                peers_arc,
                rib,
            )
            .await;
        });
    }

    async fn handle_peer(
        mut read_half: tokio::net::tcp::OwnedReadHalf,
        write_half: tokio::net::tcp::OwnedWriteHalf,
        addr: SocketAddr,
        local_asn: u16,
        local_bgp_id: u32,
        peers: Arc<Mutex<Vec<Peer>>>,
        rib: RibHandle,
    ) {
        debug!("handling peer", "peer_addr" => addr.to_string());

        // First, wait for OPEN message
        let peer_asn = loop {
            let result = read_bgp_message(&mut read_half).await;

            match result {
                Ok(message) => match message {
                    BgpMessage::Open(open_msg) => {
                        info!("received OPEN from peer", "peer_addr" => addr.to_string(), "asn" => open_msg.asn, "hold_time" => open_msg.hold_time, "bgp_identifier" => open_msg.bgp_identifier);
                        break open_msg.asn;
                    }
                    _ => {
                        error!("expected OPEN as first message", "peer_addr" => addr.to_string());
                        return;
                    }
                },
                Err(e) => {
                    error!("error reading first message from peer", "peer_addr" => addr.to_string(), "error" => format!("{:?}", e));
                    return;
                }
            }
        };

        // Now add the peer with the ASN we received
        let mut peer = Peer::new(addr, write_half, peer_asn, local_asn, local_bgp_id);

        // Process FSM events for connection establishment
        if let Err(e) = peer
            .process_events(&[
                BgpEvent::ManualStart,
                BgpEvent::TcpConnectionConfirmed,
                BgpEvent::BgpOpenReceived,
            ])
            .await
        {
            error!("failed to process FSM events", "peer_addr" => addr.to_string(), "error" => e.to_string());
            return;
        }

        {
            let mut peer_list = peers.lock().await;
            peer_list.push(peer);
            info!("peer added", "peer_addr" => addr.to_string(), "peer_asn" => peer_asn, "total_peers" => peer_list.len());
        }

        // Notify RIB about new peer
        let _ = rib.peer_connected(addr).await;

        // Now continue handling subsequent messages
        loop {
            let result = read_bgp_message(&mut read_half).await;

            match result {
                Ok(message) => {
                    // Process FSM events based on message type
                    let event = match &message {
                        BgpMessage::Open(_) => {
                            warn!("received duplicate OPEN, ignoring", "peer_addr" => addr.to_string());
                            None
                        }
                        BgpMessage::Update(_) => {
                            info!("received UPDATE", "peer_addr" => addr.to_string());
                            Some(BgpEvent::BgpUpdateReceived)
                        }
                        BgpMessage::KeepAlive(_) => {
                            debug!("received KEEPALIVE", "peer_addr" => addr.to_string());
                            Some(BgpEvent::BgpKeepaliveReceived)
                        }
                        BgpMessage::Notification(notif_msg) => {
                            warn!("received NOTIFICATION", "peer_addr" => addr.to_string(), "notification" => format!("{:?}", notif_msg));
                            Some(BgpEvent::NotificationReceived)
                        }
                    };

                    // Update FSM state
                    if let Some(event) = event {
                        if let Err(e) = Self::process_peer_event(&peers, addr, event).await {
                            error!("failed to process FSM event", "peer_addr" => addr.to_string(), "error" => e.to_string());
                        }

                        // If notification received, break the loop
                        if event == BgpEvent::NotificationReceived {
                            break;
                        }
                    }

                    // Send message to RIB
                    let _ = rib.process_bgp_message(addr, message).await;
                }
                Err(e) => {
                    error!("error reading message from peer", "peer_addr" => addr.to_string(), "error" => format!("{:?}", e));
                    break;
                }
            }
        }

        // Remove peer from the list when disconnected
        {
            let mut peer_list = peers.lock().await;
            peer_list.retain(|p| p.addr != addr);
            info!("peer disconnected", "peer_addr" => addr.to_string(), "total_peers" => peer_list.len());
        }

        // Notify RIB about disconnection
        let _ = rib.peer_disconnected(addr).await;
    }

    async fn process_peer_event(
        peers: &Arc<Mutex<Vec<Peer>>>,
        addr: SocketAddr,
        event: BgpEvent,
    ) -> Result<(), std::io::Error> {
        let mut peer_list = peers.lock().await;
        if let Some(peer) = peer_list.iter_mut().find(|p| p.addr == addr) {
            peer.process_event(event).await?;
        }
        Ok(())
    }
}
