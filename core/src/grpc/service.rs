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

use crate::bgp::msg_update::Origin;
use crate::bgp::utils::{IpNetwork, Ipv4Net};
use crate::peer::Peer;
use crate::rib::RibHandle;
use crate::server::BgpCommand;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tonic::{Request, Response, Status};

use super::proto::{
    bgp_service_server::BgpService, AddPeerRequest, AddPeerResponse, AnnounceRouteRequest,
    AnnounceRouteResponse, GetPeersRequest, GetPeersResponse, GetRoutesRequest,
    GetRoutesResponse, Path as ProtoPath, Peer as ProtoPeer, RemovePeerRequest,
    RemovePeerResponse, Route as ProtoRoute,
};

#[derive(Clone)]
pub struct BgpGrpcService {
    peers: Arc<Mutex<Vec<Peer>>>,
    rib: RibHandle,
    command_tx: mpsc::Sender<BgpCommand>,
}

impl BgpGrpcService {
    pub fn new(
        peers: Arc<Mutex<Vec<Peer>>>,
        rib: RibHandle,
        command_tx: mpsc::Sender<BgpCommand>,
    ) -> Self {
        Self {
            peers,
            rib,
            command_tx,
        }
    }
}

#[tonic::async_trait]
impl BgpService for BgpGrpcService {
    async fn add_peer(
        &self,
        request: Request<AddPeerRequest>,
    ) -> Result<Response<AddPeerResponse>, Status> {
        let addr = request.into_inner().address;

        // Send command to BGP server via channel
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BgpCommand::AddPeer {
            addr: addr.clone(),
            response: tx,
        };

        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::internal("failed to send command"))?;

        // Wait for response
        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AddPeerResponse {
                success: true,
                message: format!("Peer {} added", addr),
            })),
            Ok(Err(e)) => Ok(Response::new(AddPeerResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("command processing failed")),
        }
    }

    async fn remove_peer(
        &self,
        request: Request<RemovePeerRequest>,
    ) -> Result<Response<RemovePeerResponse>, Status> {
        let addr_str = request.into_inner().address;

        // Parse address
        let addr: std::net::SocketAddr = addr_str
            .parse()
            .map_err(|_| Status::invalid_argument("invalid address format"))?;

        // Send command to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BgpCommand::RemovePeer { addr, response: tx };

        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::internal("failed to send command"))?;

        // Wait for response
        match rx.await {
            Ok(Ok(())) => Ok(Response::new(RemovePeerResponse {
                success: true,
                message: format!("Peer {} removed", addr),
            })),
            Ok(Err(e)) => Ok(Response::new(RemovePeerResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("command processing failed")),
        }
    }

    async fn get_peers(
        &self,
        _request: Request<GetPeersRequest>,
    ) -> Result<Response<GetPeersResponse>, Status> {
        // Direct read access to peers
        let peers = self.peers.lock().await;

        let proto_peers: Vec<ProtoPeer> = peers
            .iter()
            .map(|p| ProtoPeer {
                address: p.addr.to_string(),
                asn: p.asn as u32,
                state: format!("{:?}", p.state()),
            })
            .collect();

        Ok(Response::new(GetPeersResponse { peers: proto_peers }))
    }

    async fn announce_route(
        &self,
        request: Request<AnnounceRouteRequest>,
    ) -> Result<Response<AnnounceRouteResponse>, Status> {
        let req = request.into_inner();

        // Parse prefix (CIDR format like "10.0.0.0/24")
        let parts: Vec<&str> = req.prefix.split('/').collect();
        if parts.len() != 2 {
            return Ok(Response::new(AnnounceRouteResponse {
                success: false,
                message: "Invalid prefix format, expected CIDR (e.g., 10.0.0.0/24)".to_string(),
            }));
        }

        let address: Ipv4Addr = parts[0]
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid IP address in prefix"))?;
        let prefix_length: u8 = parts[1]
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid prefix length"))?;

        let prefix = IpNetwork::V4(Ipv4Net {
            address,
            prefix_length,
        });

        // Parse next_hop
        let next_hop: Ipv4Addr = req
            .next_hop
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid next_hop IP address"))?;

        // Convert proto Origin to Rust Origin
        let origin = match req.origin {
            0 => Origin::IGP,
            1 => Origin::EGP,
            2 => Origin::INCOMPLETE,
            _ => return Err(Status::invalid_argument("Invalid origin value")),
        };

        // Send command to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BgpCommand::AnnounceRoute {
            prefix,
            next_hop,
            origin,
            response: tx,
        };

        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::internal("failed to send command"))?;

        // Wait for response
        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AnnounceRouteResponse {
                success: true,
                message: format!("Route {} announced", req.prefix),
            })),
            Ok(Err(e)) => Ok(Response::new(AnnounceRouteResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("command processing failed")),
        }
    }

    async fn get_routes(
        &self,
        _request: Request<GetRoutesRequest>,
    ) -> Result<Response<GetRoutesResponse>, Status> {
        // Query Loc-RIB for all routes
        let routes = self
            .rib
            .query_loc_rib()
            .await
            .map_err(|_| Status::internal("failed to query RIB"))?;

        // Convert Rust routes to proto routes
        let proto_routes: Vec<ProtoRoute> = routes
            .into_iter()
            .map(|route| {
                let prefix_str = match route.prefix {
                    IpNetwork::V4(v4) => {
                        format!("{}/{}", v4.address, v4.prefix_length)
                    }
                    IpNetwork::V6(_) => {
                        // IPv6 not yet supported
                        "".to_string()
                    }
                };

                let proto_paths: Vec<ProtoPath> = route
                    .paths
                    .into_iter()
                    .map(|path| ProtoPath {
                        origin: match path.origin {
                            Origin::IGP => 0,
                            Origin::EGP => 1,
                            Origin::INCOMPLETE => 2,
                        },
                        as_path: path.as_path.into_iter().map(|asn| asn as u32).collect(),
                        next_hop: path.next_hop.to_string(),
                        from_peer: path.from_peer.to_string(),
                        local_pref: path.local_pref,
                        med: path.med,
                    })
                    .collect();

                ProtoRoute {
                    prefix: prefix_str,
                    paths: proto_paths,
                }
            })
            .collect();

        Ok(Response::new(GetRoutesResponse {
            routes: proto_routes,
        }))
    }
}
