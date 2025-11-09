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
use crate::fsm::BgpState;
use crate::peer::Peer;
use crate::rib::rib_loc::LocRib;
use crate::{debug, error, info};
use std::collections::HashMap;
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
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    AnnounceRoute {
        prefix: IpNetwork,
        next_hop: Ipv4Addr,
        origin: Origin,
        response: oneshot::Sender<Result<(), String>>,
    },
    WithdrawRoute {
        prefix: IpNetwork,
        response: oneshot::Sender<Result<(), String>>,
    },
    GetPeers {
        response: oneshot::Sender<Vec<(String, u16, BgpState)>>,
    },
    GetRoutes {
        response: oneshot::Sender<Vec<crate::rib::Route>>,
    },
}

pub struct BgpServer {
    pub peers: Arc<Mutex<HashMap<String, Peer>>>,
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
        let peers = Arc::new(Mutex::new(HashMap::new()));
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

    async fn initiate_peer_connection(
        peer_addr: &str,
        local_bind_ip: &str,
        local_asn: u16,
        local_bgp_id: u32,
        hold_time: u16,
        peers: Arc<Mutex<HashMap<String, Peer>>>,
        loc_rib: Arc<Mutex<LocRib>>,
    ) {
        info!("attempting to connect to peer", "peer_addr" => peer_addr);

        // Parse the configured peer address
        let configured_addr: SocketAddr = match peer_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                error!("invalid peer address", "peer_addr" => peer_addr, "error" => e.to_string());
                return;
            }
        };

        // Extract just the IP address (no port) to use as peer identifier
        let peer_ip = configured_addr.ip().to_string();

        // Bind to local IP before connecting (so remote sees us from the correct IP)
        use tokio::net::TcpSocket;
        let socket = if configured_addr.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
        .unwrap();

        let local_bind_addr: SocketAddr = format!("{}:0", local_bind_ip).parse().unwrap();
        if let Err(e) = socket.bind(local_bind_addr) {
            error!("failed to bind to local address", "local_addr" => local_bind_ip, "error" => e.to_string());
            return;
        }

        // Connect to the peer
        let stream = match socket.connect(configured_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!("failed to connect to peer", "peer_addr" => peer_addr, "error" => e.to_string());
                return;
            }
        };

        info!("connected to peer", "peer_ip" => &peer_ip);

        let (read_half, mut write_half) = stream.into_split();

        // Send OPEN message
        let open_msg = OpenMessage::new(local_asn, hold_time, local_bgp_id);
        if let Err(e) = write_half.write_all(&open_msg.serialize()).await {
            error!("failed to send OPEN", "peer_ip" => &peer_ip, "error" => e.to_string());
            return;
        }
        info!("sent OPEN", "peer_ip" => &peer_ip);

        // Send KEEPALIVE message
        let keepalive_msg = KeepAliveMessage {};
        if let Err(e) = write_half.write_all(&keepalive_msg.serialize()).await {
            error!("failed to send KEEPALIVE", "peer_ip" => &peer_ip, "error" => e.to_string());
            return;
        }
        info!("sent KEEPALIVE", "peer_ip" => &peer_ip);

        // Handle incoming messages from this peer (will add peer after receiving OPEN)
        // Use the peer IP address (not socket address) as identifier
        Self::handle_peer(
            read_half,
            write_half,
            peer_ip,
            local_asn,
            hold_time,
            peers,
            loc_rib,
        )
        .await;
    }

    pub async fn get_routes(&self) -> Vec<crate::rib::Route> {
        self.loc_rib.lock().await.get_all_routes()
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
                    Self::accept_peer(stream, peers.clone(), loc_rib.clone(), config.asn, local_bgp_id, config.hold_time_secs as u16).await;
                }

                // Handle gRPC requests
                Some(req) = request_rx.recv() => {
                    // Extract local bind IP from listen address
                    let local_bind_ip = config.listen_addr.split(':').next().unwrap_or("127.0.0.1");
                    Self::handle_request(req, local_bind_ip, peers.clone(), loc_rib.clone(), config.asn, local_bgp_id, config.hold_time_secs as u16).await;
                }
            }
        }
    }

    async fn handle_request(
        req: BgpRequest,
        local_bind_ip: &str,
        peers: Arc<Mutex<HashMap<String, Peer>>>,
        loc_rib: Arc<Mutex<LocRib>>,
        local_asn: u16,
        local_bgp_id: u32,
        hold_time: u16,
    ) {
        match req {
            BgpRequest::AddPeer { addr, response } => {
                info!("adding peer via request", "peer_addr" => &addr);

                let local_bind_ip = local_bind_ip.to_string();
                tokio::spawn(async move {
                    Self::initiate_peer_connection(
                        &addr,
                        &local_bind_ip,
                        local_asn,
                        local_bgp_id,
                        hold_time,
                        peers,
                        loc_rib,
                    )
                    .await;
                });
                let _ = response.send(Ok(()));
            }
            BgpRequest::RemovePeer { addr, response } => {
                info!("removing peer via request", "peer_ip" => &addr);

                // Remove peer from map
                let mut peer_map = peers.lock().await;
                let removed = peer_map.remove(&addr).is_some();
                drop(peer_map);

                // Notify Loc-RIB to remove routes from this peer
                let changed_prefixes = loc_rib.lock().await.remove_routes_from_peer(addr.clone());

                // Propagate route changes (withdrawals or new best paths) to all remaining peers
                Self::propagate_routes(
                    changed_prefixes,
                    None, // Don't exclude any peer since the removed peer is already gone
                    peers.clone(),
                    loc_rib.clone(),
                    local_asn,
                )
                .await;

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

                // Add route to Loc-RIB as locally originated
                loc_rib
                    .lock()
                    .await
                    .add_local_route(prefix, next_hop, origin);

                // Propagate to all peers using the common propagation logic
                Self::propagate_routes(
                    vec![prefix],
                    None,
                    peers.clone(),
                    loc_rib.clone(),
                    local_asn,
                )
                .await;

                let _ = response.send(Ok(()));
            }
            BgpRequest::WithdrawRoute { prefix, response } => {
                info!("withdrawing route via request", "prefix" => format!("{:?}", prefix));

                // Remove local route from Loc-RIB
                loc_rib.lock().await.remove_local_route(prefix);

                // Propagate to all peers using the common propagation logic
                // This will automatically send withdrawal if no alternate path exists,
                // or announce the new best path if an alternate path is available
                Self::propagate_routes(
                    vec![prefix],
                    None,
                    peers.clone(),
                    loc_rib.clone(),
                    local_asn,
                )
                .await;

                let _ = response.send(Ok(()));
            }
            BgpRequest::GetPeers { response } => {
                let peer_map = peers.lock().await;
                let peer_info: Vec<(String, u16, BgpState)> = peer_map
                    .values()
                    .map(|p| (p.addr.clone(), p.asn, p.state()))
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
        peers: Arc<Mutex<HashMap<String, Peer>>>,
        loc_rib: Arc<Mutex<LocRib>>,
        local_asn: u16,
        local_bgp_id: u32,
        hold_time: u16,
    ) {
        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!("failed to get peer address", "error" => e.to_string());
                return;
            }
        };

        // Extract just the IP address (no port) to use as peer identifier
        let peer_ip = peer_addr.ip().to_string();

        info!("new peer connection", "peer_ip" => &peer_ip);

        let (read_half, mut write_half) = stream.into_split();

        // Send OPEN message
        let open_msg = OpenMessage::new(local_asn, hold_time, local_bgp_id);
        if let Err(e) = write_half.write_all(&open_msg.serialize()).await {
            error!("failed to send OPEN", "peer_ip" => &peer_ip, "error" => e.to_string());
            return;
        }
        info!("sent OPEN", "peer_ip" => &peer_ip);

        // Send KEEPALIVE message
        let keepalive_msg = KeepAliveMessage {};
        if let Err(e) = write_half.write_all(&keepalive_msg.serialize()).await {
            error!("failed to send KEEPALIVE", "peer_ip" => &peer_ip, "error" => e.to_string());
            return;
        }
        info!("sent KEEPALIVE", "peer_ip" => &peer_ip);

        tokio::spawn(async move {
            Self::handle_peer(
                read_half,
                write_half,
                peer_ip,
                local_asn,
                hold_time,
                peers,
                loc_rib,
            )
            .await;
        });
    }

    async fn handle_peer(
        mut read_half: tokio::net::tcp::OwnedReadHalf,
        write_half: tokio::net::tcp::OwnedWriteHalf,
        peer_ip: String,
        local_asn: u16,
        hold_time: u16,
        peers: Arc<Mutex<HashMap<String, Peer>>>,
        loc_rib: Arc<Mutex<LocRib>>,
    ) {
        debug!("handling peer", "peer_ip" => &peer_ip);

        // First, wait for OPEN message
        let (peer_asn, peer_hold_time) = loop {
            let result = read_bgp_message(&mut read_half).await;

            match result {
                Ok(message) => match message {
                    BgpMessage::Open(open_msg) => {
                        info!("received OPEN from peer", "peer_ip" => &peer_ip, "asn" => open_msg.asn, "hold_time" => open_msg.hold_time, "bgp_identifier" => open_msg.bgp_identifier);
                        break (open_msg.asn, open_msg.hold_time);
                    }
                    _ => {
                        error!("expected OPEN as first message", "peer_ip" => &peer_ip);
                        return;
                    }
                },
                Err(e) => {
                    error!("error reading first message from peer", "peer_ip" => &peer_ip, "error" => format!("{:?}", e));
                    return;
                }
            }
        };

        // Negotiate hold time: use minimum of our hold time and peer's hold time (RFC 4271)
        let negotiated_hold_time = hold_time.min(peer_hold_time);

        // Determine session type based on AS numbers
        let session_type = if peer_asn == local_asn {
            crate::peer::SessionType::Ibgp
        } else {
            crate::peer::SessionType::Ebgp
        };

        // Now add the peer with the ASN we received and negotiated hold time
        let mut peer = Peer::new(peer_ip.clone(), write_half, peer_asn, session_type);

        // Set the negotiated hold time in FSM timers
        peer.set_negotiated_hold_time(negotiated_hold_time);

        // Initialize the BGP connection
        if let Err(e) = peer.initialize_connection().await {
            error!("failed to initialize connection", "peer_ip" => &peer_ip, "error" => e.to_string());
            return;
        }

        {
            let mut peer_map = peers.lock().await;
            peer_map.insert(peer_ip.clone(), peer);
            info!("peer added", "peer_ip" => &peer_ip, "peer_asn" => peer_asn, "total_peers" => peer_map.len());
        }

        // Create keepalive interval timer (RFC 4271)
        let mut keepalive_interval = if negotiated_hold_time > 0 {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // Skip first immediate tick
            Some(interval)
        } else {
            None
        };

        // RFC 4271: Hold timer - track last KEEPALIVE or UPDATE received
        let hold_timeout = tokio::time::Duration::from_secs(negotiated_hold_time as u64);
        let mut last_keepalive_or_update = tokio::time::Instant::now();

        // Check hold timer every 500ms
        let mut hold_check_interval =
            tokio::time::interval(tokio::time::Duration::from_millis(500));
        hold_check_interval.tick().await; // Skip first immediate tick

        // Now continue handling subsequent messages
        loop {
            tokio::select! {
                // Read messages from peer
                result = read_bgp_message(&mut read_half) => {
                    let mut peer_map = peers.lock().await;
                    let Some(peer) = peer_map.get_mut(&peer_ip) else {
                        error!("peer not found in map", "peer_ip" => &peer_ip);
                        break;
                    };

                    match result {
                        Ok(message) => {
                            // RFC 4271: Only restart hold timer on KEEPALIVE or UPDATE
                            let is_keepalive_or_update = matches!(&message, BgpMessage::KeepAlive(_) | BgpMessage::Update(_));
                            let is_notification = matches!(&message, BgpMessage::Notification(_));

                            // Process message with peer
                            let delta = match peer.process_message(message).await {
                                Ok(delta) => delta,
                                Err(e) => {
                                    error!("failed to process message", "peer_ip" => &peer_ip, "error" => e.to_string());
                                    None
                                }
                            };
                            drop(peer_map);

                            // RFC 4271: Restart hold timer on KEEPALIVE or UPDATE
                            if is_keepalive_or_update {
                                last_keepalive_or_update = tokio::time::Instant::now();
                            }

                            // Update Loc-RIB if we have route changes (withdrawn or announced)
                            if let Some((withdrawn, announced)) = delta {
                                let changed_prefixes = loc_rib
                                    .lock()
                                    .await
                                    .update_from_peer(peer_ip.clone(), withdrawn, announced);
                                info!("UPDATE processing complete", "peer_ip" => &peer_ip);

                                // Propagate changed routes to other peers
                                if !changed_prefixes.is_empty() {
                                    Self::propagate_routes(
                                        changed_prefixes,
                                        Some(peer_ip.clone()),
                                        peers.clone(),
                                        loc_rib.clone(),
                                        local_asn,
                                    )
                                    .await;
                                }
                            }

                            // If notification received, break the loop
                            if is_notification {
                                break;
                            }
                        }
                        Err(e) => {
                            drop(peer_map);
                            error!("error reading message from peer", "peer_ip" => &peer_ip, "error" => format!("{:?}", e));
                            break;
                        }
                    }
                }

                // RFC 4271: Check if hold timer expired (no KEEPALIVE/UPDATE received)
                _ = hold_check_interval.tick() => {
                    if last_keepalive_or_update.elapsed() > hold_timeout {
                        error!("hold timer expired (no KEEPALIVE or UPDATE received)", "peer_ip" => &peer_ip);
                        break;
                    }
                }

                // Periodic KEEPALIVE check
                _ = async {
                    match &mut keepalive_interval {
                        Some(interval) => interval.tick().await,
                        None => std::future::pending().await,
                    }
                } => {
                    let mut peer_map = peers.lock().await;
                    if let Some(peer) = peer_map.get_mut(&peer_ip) {
                        if peer.fsm.timers.keepalive_timer_expired() {
                            if let Err(e) = peer.process_event(crate::fsm::BgpEvent::KeepaliveTimerExpires).await {
                                error!("failed to send keepalive", "peer_ip" => &peer_ip, "error" => e.to_string());
                                drop(peer_map);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Remove peer from the map when disconnected
        {
            let mut peer_map = peers.lock().await;
            peer_map.remove(&peer_ip);
            info!("peer disconnected", "peer_ip" => &peer_ip, "total_peers" => peer_map.len());
        }

        // Notify Loc-RIB about disconnection and get affected prefixes
        let changed_prefixes = loc_rib
            .lock()
            .await
            .remove_routes_from_peer(peer_ip.clone());

        // Propagate withdrawals to other peers
        if !changed_prefixes.is_empty() {
            Self::propagate_routes(changed_prefixes, Some(peer_ip), peers, loc_rib, local_asn)
                .await;
        }
    }

    /// Propagate route changes to all established peers (except the originating peer)
    /// If originating_peer is None, propagates to all peers (used for locally originated routes)
    async fn propagate_routes(
        changed_prefixes: Vec<IpNetwork>,
        originating_peer: Option<String>,
        peers: Arc<Mutex<HashMap<String, Peer>>>,
        loc_rib: Arc<Mutex<LocRib>>,
        local_asn: u16,
    ) {
        let rib = loc_rib.lock().await;

        // For each changed prefix, determine what to send
        let mut to_announce = Vec::new();
        let mut to_withdraw = Vec::new();

        for prefix in changed_prefixes {
            if let Some(best_path) = rib.get_best_path(&prefix) {
                // We have a best path - prepare announcement
                to_announce.push((prefix, best_path.clone()));
            } else {
                // No path exists - prepare withdrawal
                to_withdraw.push(prefix);
            }
        }
        drop(rib);

        // Send updates to all established peers (except the originating peer)
        let mut peer_map = peers.lock().await;
        for (peer_addr, peer) in peer_map.iter_mut() {
            // Skip the peer that sent us the original update (if any)
            if let Some(ref orig_peer) = originating_peer {
                if peer_addr == orig_peer {
                    continue;
                }
            }

            // Only send to established peers
            if peer.state() != BgpState::Established {
                continue;
            }

            // Send withdrawals if any
            if !to_withdraw.is_empty() {
                let withdraw_msg = UpdateMessage::new_withdraw(to_withdraw.clone());
                if let Err(e) = peer.send_update(withdraw_msg).await {
                    error!("failed to send WITHDRAW to peer", "peer_ip" => &peer.addr, "error" => e.to_string());
                } else {
                    info!("propagated withdrawals to peer", "count" => to_withdraw.len(), "peer_ip" => &peer.addr);
                }
            }

            // Send announcements if any
            for (prefix, path) in &to_announce {
                // Build AS path for export
                // For locally originated routes, AS_PATH already contains local ASN - don't prepend
                // For routes learned from peers, prepend local ASN
                let new_as_path = if matches!(path.source, crate::rib::RouteSource::Local) {
                    path.as_path.clone()
                } else {
                    let mut as_path = vec![local_asn];
                    as_path.extend_from_slice(&path.as_path);
                    as_path
                };

                let as_path_segments = vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: new_as_path.len() as u8,
                    asn_list: new_as_path,
                }];

                // Create UPDATE message with the modified AS path
                let update_msg =
                    UpdateMessage::new(path.origin, as_path_segments, path.next_hop, vec![*prefix]);

                if let Err(e) = peer.send_update(update_msg).await {
                    error!("failed to send UPDATE to peer", "peer_ip" => &peer.addr, "error" => e.to_string());
                } else {
                    info!("propagated route to peer", "prefix" => format!("{:?}", prefix), "peer_ip" => &peer.addr);
                }
            }
        }
    }
}
