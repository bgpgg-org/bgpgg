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
use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin, UpdateMessage};
use crate::bgp::utils::IpNetwork;
use crate::config::Config;
use crate::fsm::{BgpEvent, BgpState};
use crate::net::create_and_bind_tcp_socket;
use crate::peer::Peer;
use crate::rib::rib_loc::LocRib;
use crate::{debug, error, info};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

// Management requests that can be sent to the BGP server
pub enum MgmtRequest {
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
    GetPeer {
        addr: String,
        response: oneshot::Sender<Option<(String, u16, BgpState, crate::peer::PeerStatistics)>>,
    },
    GetRoutes {
        response: oneshot::Sender<Vec<crate::rib::Route>>,
    },
}

// Messages that can be sent to a peer task
pub enum PeerMessage {
    SendUpdate(UpdateMessage),
}

// Information about an established peer
pub struct PeerHandle {
    pub addr: String,
    pub asn: u16,
    pub state: BgpState,
    pub statistics: crate::peer::PeerStatistics,
    pub message_tx: mpsc::UnboundedSender<PeerMessage>,
}

// RIB update events sent from peer tasks to the main server loop
pub enum RibUpdate {
    PeerEstablished {
        peer_ip: String,
        asn: u16,
        handle: PeerHandle,
    },
    PeerUpdate {
        peer_ip: String,
        withdrawn: Vec<IpNetwork>,
        announced: Vec<(IpNetwork, crate::rib::Path)>,
    },
    PeerDisconnected {
        peer_ip: String,
    },
}

pub struct BgpServer {
    pub peers: HashMap<String, PeerHandle>,
    pub loc_rib: LocRib,
    pub request_tx: mpsc::Sender<MgmtRequest>,
    pub rib_update_tx: mpsc::UnboundedSender<RibUpdate>,
    config: Config,
    local_bgp_id: u32,
    request_rx: mpsc::Receiver<MgmtRequest>,
    rib_update_rx: mpsc::UnboundedReceiver<RibUpdate>,
}

impl BgpServer {
    pub fn new(config: Config) -> Self {
        // Convert the configured router_id (Ipv4Addr) to u32 for BGP identifier
        let local_bgp_id = u32::from(config.router_id);

        let (req_tx, req_rx) = mpsc::channel(100);
        let (rib_update_tx, rib_update_rx) = mpsc::unbounded_channel();
        let peers = HashMap::new();
        let loc_rib = LocRib::new(config.asn);

        BgpServer {
            peers,
            loc_rib,
            request_tx: req_tx,
            rib_update_tx,
            config,
            local_bgp_id,
            request_rx: req_rx,
            rib_update_rx,
        }
    }

    pub async fn run(mut self) {
        let addr = self.config.listen_addr.clone();
        info!("BGP server starting", "listen_addr" => addr);

        let listener = TcpListener::bind(&addr).await.unwrap();

        // Get local bind address for outgoing connections
        let local_addr = self
            .config
            .get_local_addr()
            .expect("invalid listen address");
        let local_asn = self.config.asn;
        let local_bgp_id = self.local_bgp_id;
        let hold_time = self.config.hold_time_secs as u16;
        let rib_update_tx = self.rib_update_tx.clone();

        // Unified event loop: handle BGP connections, management requests, and RIB updates
        loop {
            tokio::select! {
                // Handle incoming BGP connections
                Ok((stream, _)) = listener.accept() => {
                    Self::accept_peer(stream, rib_update_tx.clone(), local_asn, local_bgp_id, hold_time).await;
                }

                // Handle management requests
                Some(req) = self.request_rx.recv() => {
                    self.handle_mgmt_req(req, local_addr).await;
                }

                // Handle RIB updates from peers
                Some(update) = self.rib_update_rx.recv() => {
                    self.handle_rib_update(update).await;
                }
            }
        }
    }

    async fn handle_rib_update(&mut self, update: RibUpdate) {
        match update {
            RibUpdate::PeerEstablished {
                peer_ip,
                asn,
                handle,
            } => {
                self.peers.insert(peer_ip.clone(), handle);
                info!("peer established", "peer_ip" => &peer_ip, "peer_asn" => asn, "total_peers" => self.peers.len());
            }
            RibUpdate::PeerUpdate {
                peer_ip,
                withdrawn,
                announced,
            } => {
                let changed_prefixes =
                    self.loc_rib
                        .update_from_peer(peer_ip.clone(), withdrawn, announced);
                info!("UPDATE processing complete", "peer_ip" => &peer_ip);

                // Propagate changed routes to other peers
                if !changed_prefixes.is_empty() {
                    self.propagate_routes(changed_prefixes, Some(peer_ip)).await;
                }
            }
            RibUpdate::PeerDisconnected { peer_ip } => {
                // Remove peer from the map
                self.peers.remove(&peer_ip);
                info!("peer disconnected", "peer_ip" => &peer_ip, "total_peers" => self.peers.len());

                // Notify Loc-RIB about disconnection and get affected prefixes
                let changed_prefixes = self.loc_rib.remove_routes_from_peer(peer_ip.clone());

                // Propagate withdrawals to other peers
                if !changed_prefixes.is_empty() {
                    self.propagate_routes(changed_prefixes, Some(peer_ip)).await;
                }
            }
        }
    }

    async fn handle_mgmt_req(&mut self, req: MgmtRequest, local_addr: SocketAddr) {
        let local_asn = self.config.asn;
        let local_bgp_id = self.local_bgp_id;
        let hold_time = self.config.hold_time_secs as u16;
        match req {
            MgmtRequest::AddPeer { addr, response } => {
                info!("adding peer via request", "peer_addr" => &addr);

                // Parse peer address before spawning task
                let peer_addr = match addr.parse::<SocketAddr>() {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = response.send(Err(format!("invalid peer address: {}", e)));
                        return;
                    }
                };

                let rib_update_tx = self.rib_update_tx.clone();
                tokio::spawn(async move {
                    Self::connect_to_peer(
                        peer_addr,
                        local_addr,
                        local_asn,
                        local_bgp_id,
                        hold_time,
                        rib_update_tx,
                    )
                    .await;
                });
                let _ = response.send(Ok(()));
            }
            MgmtRequest::RemovePeer { addr, response } => {
                info!("removing peer via request", "peer_ip" => &addr);

                // Remove peer from map
                let removed = self.peers.remove(&addr).is_some();

                if !removed {
                    let _ = response.send(Err(format!("peer {} not found", addr)));
                    return;
                }

                // Notify Loc-RIB to remove routes from this peer
                let changed_prefixes = self.loc_rib.remove_routes_from_peer(addr.clone());

                // Propagate route changes (withdrawals or new best paths) to all remaining peers
                self.propagate_routes(
                    changed_prefixes,
                    None, // Don't exclude any peer since the removed peer is already gone
                )
                .await;

                let _ = response.send(Ok(()));
            }
            MgmtRequest::AnnounceRoute {
                prefix,
                next_hop,
                origin,
                response,
            } => {
                info!("announcing route via request", "prefix" => format!("{:?}", prefix), "next_hop" => next_hop.to_string());

                // Add route to Loc-RIB as locally originated
                self.loc_rib.add_local_route(prefix, next_hop, origin);

                // Propagate to all peers using the common propagation logic
                self.propagate_routes(vec![prefix], None).await;

                let _ = response.send(Ok(()));
            }
            MgmtRequest::WithdrawRoute { prefix, response } => {
                info!("withdrawing route via request", "prefix" => format!("{:?}", prefix));

                // Remove local route from Loc-RIB
                let removed = self.loc_rib.remove_local_route(prefix);

                // Only propagate if something was actually removed
                if removed {
                    // Propagate to all peers using the common propagation logic
                    // This will automatically send withdrawal if no alternate path exists,
                    // or announce the new best path if an alternate path is available
                    self.propagate_routes(vec![prefix], None).await;
                }

                let _ = response.send(Ok(()));
            }
            MgmtRequest::GetPeers { response } => {
                let peer_info: Vec<(String, u16, BgpState)> = self
                    .peers
                    .values()
                    .map(|p| (p.addr.clone(), p.asn, p.state))
                    .collect();
                let _ = response.send(peer_info);
            }
            MgmtRequest::GetPeer { addr, response } => {
                let peer_info = self
                    .peers
                    .get(&addr)
                    .map(|p| (p.addr.clone(), p.asn, p.state, p.statistics.clone()));
                let _ = response.send(peer_info);
            }
            MgmtRequest::GetRoutes { response } => {
                let routes = self.loc_rib.get_all_routes();
                let _ = response.send(routes);
            }
        }
    }

    async fn connect_to_peer(
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        local_asn: u16,
        local_bgp_id: u32,
        hold_time: u16,
        rib_update_tx: mpsc::UnboundedSender<RibUpdate>,
    ) {
        // Create socket, bind to local address, and connect to peer
        let stream = match create_and_bind_tcp_socket(local_addr, peer_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!("failed to connect to peer", "peer_addr" => peer_addr, "error" => e.to_string());
                return;
            }
        };

        let peer_ip = peer_addr.ip().to_string();
        info!("connected to peer", "peer_ip" => &peer_ip);

        let (read_half, write_half) = stream.into_split();

        // Handle incoming messages from this peer (will create Peer after receiving OPEN)
        Self::handle_peer(
            peer_ip,
            read_half,
            write_half,
            local_asn,
            hold_time,
            local_bgp_id,
            rib_update_tx,
        )
        .await;
    }

    async fn accept_peer(
        stream: TcpStream,
        rib_update_tx: mpsc::UnboundedSender<RibUpdate>,
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

        let (read_half, write_half) = stream.into_split();

        tokio::spawn(async move {
            Self::handle_peer(
                peer_ip,
                read_half,
                write_half,
                local_asn,
                hold_time,
                local_bgp_id,
                rib_update_tx,
            )
            .await;
        });
    }

    async fn handle_peer(
        peer_ip: String,
        mut reader: tokio::net::tcp::OwnedReadHalf,
        writer: tokio::net::tcp::OwnedWriteHalf,
        local_asn: u16,
        hold_time: u16,
        local_bgp_id: u32,
        rib_update_tx: mpsc::UnboundedSender<RibUpdate>,
    ) {
        debug!("handling peer", "peer_ip" => &peer_ip);

        // Create a placeholder Peer to send OPEN immediately (we don't know peer_asn yet)
        let mut peer = Peer::new(peer_ip.clone(), writer, 0, crate::peer::SessionType::Ebgp);

        // Send OPEN via FSM to avoid deadlock
        if let Err(e) = peer.process_event(&BgpEvent::ManualStart).await {
            error!("failed to start FSM", "peer_ip" => &peer_ip, "error" => e.to_string());
            return;
        }

        if let Err(e) = peer
            .process_event(&BgpEvent::TcpConnectionConfirmed {
                local_asn,
                hold_time,
                bgp_id: local_bgp_id,
            })
            .await
        {
            error!("failed to send OPEN", "peer_ip" => &peer_ip, "error" => e.to_string());
            return;
        }

        // Wait for peer's OPEN message
        let (peer_asn, peer_hold_time) = loop {
            let result = read_bgp_message(&mut reader).await;

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

        // Determine session type
        let session_type = if peer_asn == local_asn {
            crate::peer::SessionType::Ibgp
        } else {
            crate::peer::SessionType::Ebgp
        };

        // Update peer with correct ASN and session type
        peer.asn = peer_asn;
        peer.session_type = session_type;

        // Track that we received OPEN (it was received before peer was fully created)
        peer.statistics.open_received += 1;

        // Process receiving peer's OPEN (sends KEEPALIVE)
        if let Err(e) = peer
            .process_event(&BgpEvent::BgpOpenReceived {
                peer_asn,
                peer_hold_time: negotiated_hold_time,
            })
            .await
        {
            error!("failed to complete connection", "peer_ip" => &peer_ip, "error" => e.to_string());
            return;
        }

        // Create channel for receiving messages from the server (route updates to send)
        let (message_tx, mut message_rx) = mpsc::unbounded_channel();

        // Track whether we've registered with the server yet
        let mut peer_registered = false;

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

        // Main event loop for this peer
        loop {
            tokio::select! {
                // Read messages from peer
                result = read_bgp_message(&mut reader) => {
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

                            // RFC 4271: Restart hold timer on KEEPALIVE or UPDATE
                            if is_keepalive_or_update {
                                last_keepalive_or_update = tokio::time::Instant::now();
                            }

                            // Register with server once we reach Established state
                            if !peer_registered && peer.state() == BgpState::Established {
                                let handle = PeerHandle {
                                    addr: peer_ip.clone(),
                                    asn: peer_asn,
                                    state: BgpState::Established,
                                    statistics: peer.statistics.clone(),
                                    message_tx: message_tx.clone(),
                                };

                                if let Err(e) = rib_update_tx.send(RibUpdate::PeerEstablished {
                                    peer_ip: peer_ip.clone(),
                                    asn: peer_asn,
                                    handle,
                                }) {
                                    error!("failed to register peer with server", "peer_ip" => &peer_ip, "error" => e.to_string());
                                    break;
                                }
                                peer_registered = true;
                            }

                            // Send RIB update to server if we have route changes
                            if let Some((withdrawn, announced)) = delta {
                                if let Err(e) = rib_update_tx.send(RibUpdate::PeerUpdate {
                                    peer_ip: peer_ip.clone(),
                                    withdrawn,
                                    announced,
                                }) {
                                    error!("failed to send RIB update to server", "peer_ip" => &peer_ip, "error" => e.to_string());
                                    break;
                                }
                            }

                            // If notification received, break the loop
                            if is_notification {
                                break;
                            }
                        }
                        Err(e) => {
                            error!("error reading message from peer", "peer_ip" => &peer_ip, "error" => format!("{:?}", e));
                            break;
                        }
                    }
                }

                // Receive messages from server (route updates to send to peer)
                Some(msg) = message_rx.recv() => {
                    match msg {
                        PeerMessage::SendUpdate(update_msg) => {
                            if let Err(e) = peer.send_update(update_msg).await {
                                error!("failed to send UPDATE to peer", "peer_ip" => &peer_ip, "error" => e.to_string());
                                break;
                            }
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
                    if peer.fsm.timers.keepalive_timer_expired() {
                        if let Err(e) = peer.process_event(&crate::fsm::BgpEvent::KeepaliveTimerExpires).await {
                            error!("failed to send keepalive", "peer_ip" => &peer_ip, "error" => e.to_string());
                            break;
                        }
                    }
                }
            }
        }

        // Notify server that peer disconnected
        let _ = rib_update_tx.send(RibUpdate::PeerDisconnected {
            peer_ip: peer_ip.clone(),
        });
    }

    /// Propagate route changes to all established peers (except the originating peer)
    /// If originating_peer is None, propagates to all peers (used for locally originated routes)
    async fn propagate_routes(
        &mut self,
        changed_prefixes: Vec<IpNetwork>,
        originating_peer: Option<String>,
    ) {
        let local_asn = self.config.asn;

        // For each changed prefix, determine what to send
        let mut to_announce = Vec::new();
        let mut to_withdraw = Vec::new();

        for prefix in changed_prefixes {
            if let Some(best_path) = self.loc_rib.get_best_path(&prefix) {
                // We have a best path - prepare announcement
                to_announce.push((prefix, best_path.clone()));
            } else {
                // No path exists - prepare withdrawal
                to_withdraw.push(prefix);
            }
        }

        // Send updates to all established peers (except the originating peer)
        for (peer_addr, handle) in self.peers.iter() {
            // Skip the peer that sent us the original update (if any)
            if let Some(ref orig_peer) = originating_peer {
                if peer_addr == orig_peer {
                    continue;
                }
            }

            // Only send to established peers
            if handle.state != BgpState::Established {
                continue;
            }

            // Send withdrawals if any
            if !to_withdraw.is_empty() {
                let withdraw_msg = UpdateMessage::new_withdraw(to_withdraw.clone());
                if let Err(e) = handle
                    .message_tx
                    .send(PeerMessage::SendUpdate(withdraw_msg))
                {
                    error!("failed to send WITHDRAW to peer", "peer_ip" => &handle.addr, "error" => e.to_string());
                } else {
                    info!("propagated withdrawals to peer", "count" => to_withdraw.len(), "peer_ip" => &handle.addr);
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

                if let Err(e) = handle.message_tx.send(PeerMessage::SendUpdate(update_msg)) {
                    error!("failed to send UPDATE to peer", "peer_ip" => &handle.addr, "error" => e.to_string());
                } else {
                    info!("propagated route to peer", "prefix" => format!("{:?}", prefix), "peer_ip" => &handle.addr);
                }
            }
        }
    }
}
