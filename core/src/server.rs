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
use crate::rib::rib_loc::LocRib;
use crate::rib::Path;
use crate::{debug, error, info, warn};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};

// Requests that can be sent to the BGP server
pub enum BgpRequest {
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
    GetPeers {
        response: oneshot::Sender<Vec<(SocketAddr, u16, BgpState)>>,
    },
    GetRoutes {
        response: oneshot::Sender<Vec<crate::rib::Route>>,
    },
}

pub struct BgpServer {
    pub peers: Arc<Mutex<Vec<Peer>>>,
    pub loc_rib: Arc<Mutex<LocRib>>,
    pub request_tx: mpsc::Sender<BgpRequest>,
    config: Config,
    local_bgp_id: u32,
    request_rx: mpsc::Receiver<BgpRequest>,
}

impl BgpServer {
    pub fn new(config: Config) -> Self {
        // Convert the configured router_id (Ipv4Addr) to u32 for BGP identifier
        let local_bgp_id = u32::from(config.router_id);

        let (req_tx, req_rx) = mpsc::channel(100);
        let peers = Arc::new(Mutex::new(Vec::new()));
        let loc_rib = Arc::new(Mutex::new(LocRib::new(config.asn)));

        BgpServer {
            peers,
            loc_rib,
            request_tx: req_tx,
            config,
            local_bgp_id,
            request_rx: req_rx,
        }
    }

    /// Add a peer and initiate BGP session
    pub async fn add_peer(&self, peer_addr: &str) {
        let peers_arc = Arc::clone(&self.peers);
        let loc_rib = self.loc_rib.clone();
        let local_asn = self.config.asn;
        let local_bgp_id = self.local_bgp_id;
        let peer_addr_string = peer_addr.to_string();

        tokio::spawn(async move {
            Self::initiate_peer_connection(
                &peer_addr_string,
                local_asn,
                local_bgp_id,
                peers_arc,
                loc_rib,
            )
            .await;
        });
    }

    async fn initiate_peer_connection(
        peer_addr: &str,
        local_asn: u16,
        local_bgp_id: u32,
        peers: Arc<Mutex<Vec<Peer>>>,
        loc_rib: Arc<Mutex<LocRib>>,
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
            loc_rib,
        )
        .await;
    }

    pub async fn get_routes(&self) -> Vec<crate::rib::Route> {
        self.loc_rib.lock().await.get_all_routes()
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

    pub async fn run(self) {
        let addr = self.config.listen_addr.clone();
        info!("BGP server starting", "listen_addr" => addr);

        let listener = TcpListener::bind(&addr).await.unwrap();

        // Destructure to avoid partial move issues
        let BgpServer {
            peers,
            loc_rib,
            config,
            local_bgp_id,
            mut request_rx,
            ..
        } = self;

        // Unified event loop: handle both BGP connections and gRPC requests
        loop {
            tokio::select! {
                // Handle incoming BGP connections
                Ok((stream, _)) = listener.accept() => {
                    Self::accept_peer(stream, peers.clone(), loc_rib.clone(), config.asn, local_bgp_id).await;
                }

                // Handle gRPC requests
                Some(req) = request_rx.recv() => {
                    Self::handle_request(req, peers.clone(), loc_rib.clone(), config.asn, local_bgp_id).await;
                }
            }
        }
    }

    async fn handle_request(
        req: BgpRequest,
        peers: Arc<Mutex<Vec<Peer>>>,
        loc_rib: Arc<Mutex<LocRib>>,
        local_asn: u16,
        local_bgp_id: u32,
    ) {
        match req {
            BgpRequest::AddPeer { addr, response } => {
                info!("adding peer via request", "peer_addr" => &addr);

                tokio::spawn(async move {
                    Self::initiate_peer_connection(&addr, local_asn, local_bgp_id, peers, loc_rib).await;
                });
                let _ = response.send(Ok(()));
            }
            BgpRequest::RemovePeer { addr, response } => {
                info!("removing peer via request", "peer_addr" => addr.to_string());

                // Remove peer from list
                let mut peer_list = peers.lock().await;
                let initial_len = peer_list.len();
                peer_list.retain(|p| p.addr != addr);
                let removed = initial_len > peer_list.len();
                drop(peer_list);

                // Notify Loc-RIB to remove routes from this peer
                loc_rib.lock().await.remove_routes_from_peer(addr);

                if removed {
                    let _ = response.send(Ok(()));
                } else {
                    let _ = response.send(Err(format!("peer {} not found", addr)));
                }
            }
            BgpRequest::AnnounceRoute {
                prefix,
                next_hop,
                origin,
                response,
            } => {
                info!("announcing route via request", "prefix" => format!("{:?}", prefix), "next_hop" => next_hop.to_string());

                // Build AS path with local ASN
                let as_path_segments = vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![local_asn],
                }];

                // Create UPDATE message
                let update_msg = UpdateMessage::new(origin, as_path_segments, next_hop, vec![prefix]);

                // Send to all established peers
                let mut peer_list = peers.lock().await;
                let mut success = true;
                for peer in peer_list.iter_mut() {
                    // Only send to peers in Established state
                    if peer.state() == BgpState::Established {
                        if let Err(e) = peer.writer.write_all(&update_msg.serialize()).await {
                            error!("failed to send UPDATE to peer", "peer_addr" => peer.addr.to_string(), "error" => e.to_string());
                            success = false;
                        } else {
                            info!("announced route to peer", "prefix" => format!("{:?}", prefix), "next_hop" => next_hop.to_string(), "peer_addr" => peer.addr.to_string());
                        }
                    } else {
                        debug!("skipping peer not in established state", "peer_addr" => peer.addr.to_string(), "state" => format!("{:?}", peer.state()));
                    }
                }

                if success {
                    let _ = response.send(Ok(()));
                } else {
                    let _ = response.send(Err("failed to announce to some peers".to_string()));
                }
            }
            BgpRequest::GetPeers { response } => {
                let peer_list = peers.lock().await;
                let peer_info: Vec<(SocketAddr, u16, BgpState)> = peer_list
                    .iter()
                    .map(|p| (p.addr, p.asn, p.state()))
                    .collect();
                let _ = response.send(peer_info);
            }
            BgpRequest::GetRoutes { response } => {
                let routes = loc_rib.lock().await.get_all_routes();
                let _ = response.send(routes);
            }
        }
    }

    async fn accept_peer(
        stream: TcpStream,
        peers: Arc<Mutex<Vec<Peer>>>,
        loc_rib: Arc<Mutex<LocRib>>,
        local_asn: u16,
        local_bgp_id: u32,
    ) {
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
        let open_msg = OpenMessage::new(local_asn, 180, local_bgp_id);
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

        tokio::spawn(async move {
            Self::handle_peer(
                read_half,
                write_half,
                peer_addr,
                local_asn,
                local_bgp_id,
                peers,
                loc_rib,
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
        loc_rib: Arc<Mutex<LocRib>>,
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
        for event in &[
            BgpEvent::ManualStart,
            BgpEvent::TcpConnectionConfirmed,
            BgpEvent::BgpOpenReceived,
        ] {
            let transition = peer.fsm.process_event(*event);
            debug!("FSM transition", "peer_addr" => addr.to_string(), "event" => format!("{:?}", event), "new_state" => format!("{:?}", transition.new_state));

            for action in transition.actions {
                if let Err(e) = peer.execute_action(action).await {
                    error!("failed to execute FSM action", "peer_addr" => addr.to_string(), "error" => e.to_string());
                    return;
                }
            }
        }

        {
            let mut peer_list = peers.lock().await;
            peer_list.push(peer);
            info!("peer added", "peer_addr" => addr.to_string(), "peer_asn" => peer_asn, "total_peers" => peer_list.len());
        }

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

                    // Process UPDATE messages
                    if let BgpMessage::Update(update_msg) = message {
                        Self::process_update(&peers, &loc_rib, addr, update_msg).await;
                    }
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

        // Notify Loc-RIB about disconnection
        loc_rib.lock().await.remove_routes_from_peer(addr);
    }

    async fn process_update(
        peers: &Arc<Mutex<Vec<Peer>>>,
        loc_rib: &Arc<Mutex<LocRib>>,
        from: SocketAddr,
        update_msg: UpdateMessage,
    ) {
        // Extract path attributes
        let origin = match update_msg.get_origin() {
            Some(o) => o,
            None => {
                warn!("UPDATE missing Origin attribute, skipping", "peer_addr" => from.to_string());
                return;
            }
        };

        let as_path = match update_msg.get_as_path() {
            Some(p) => p,
            None => {
                warn!("UPDATE missing AS Path attribute, skipping", "peer_addr" => from.to_string());
                return;
            }
        };

        let next_hop = match update_msg.get_next_hop() {
            Some(nh) => nh,
            None => {
                warn!("UPDATE missing Next Hop attribute, skipping", "peer_addr" => from.to_string());
                return;
            }
        };

        // Update peer's Adj-RIB-In
        let mut peer_list = peers.lock().await;
        if let Some(peer) = peer_list.iter_mut().find(|p| p.addr == from) {
            // Process withdrawn routes
            for prefix in update_msg.withdrawn_routes() {
                info!("withdrawing route", "prefix" => format!("{:?}", prefix), "peer_addr" => from.to_string());
                peer.adj_rib_in.remove_route(*prefix);
            }

            // Process announced routes (NLRI)
            for prefix in update_msg.nlri_list() {
                let path = Path {
                    origin,
                    as_path: as_path.clone(),
                    next_hop,
                    from_peer: from,
                    local_pref: None,
                    med: None,
                };
                info!("adding route to Adj-RIB-In", "prefix" => format!("{:?}", prefix), "peer_addr" => from.to_string());
                peer.adj_rib_in.add_route(*prefix, path);
            }

            // Get all routes from this peer's Adj-RIB-In
            let routes = peer.adj_rib_in.get_all_routes();
            drop(peer_list); // Release peers lock before locking loc_rib

            // Update Loc-RIB from peer's routes
            loc_rib.lock().await.update_from_peer(from, routes);
            info!("UPDATE processing complete", "peer_addr" => from.to_string());
        }
    }

    async fn process_peer_event(
        peers: &Arc<Mutex<Vec<Peer>>>,
        addr: SocketAddr,
        event: BgpEvent,
    ) -> Result<(), std::io::Error> {
        let mut peer_list = peers.lock().await;
        if let Some(peer) = peer_list.iter_mut().find(|p| p.addr == addr) {
            let transition = peer.fsm.process_event(event);
            debug!("FSM transition", "peer_addr" => addr.to_string(), "event" => format!("{:?}", event), "new_state" => format!("{:?}", transition.new_state));

            for action in transition.actions {
                peer.execute_action(action).await?;
            }
        }
        Ok(())
    }
}
