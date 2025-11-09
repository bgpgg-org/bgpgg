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
use crate::fsm::BgpState;
use crate::rib::RouteSource;
use crate::server::BgpRequest;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

use super::proto::{
    bgp_service_server::BgpService, AddPeerRequest, AddPeerResponse, AnnounceRouteRequest,
    AnnounceRouteResponse, BgpState as ProtoBgpState, GetPeersRequest, GetPeersResponse,
    GetRoutesRequest, GetRoutesResponse, Path as ProtoPath, Peer as ProtoPeer, RemovePeerRequest,
    RemovePeerResponse, Route as ProtoRoute, WithdrawRouteRequest, WithdrawRouteResponse,
};

const LOCAL_ROUTE_SOURCE_STR: &str = "127.0.0.1";

/// Convert internal BgpState to proto BgpState
fn to_proto_state(state: BgpState) -> i32 {
    match state {
        BgpState::Idle => ProtoBgpState::Idle as i32,
        BgpState::Connect => ProtoBgpState::Connect as i32,
        BgpState::Active => ProtoBgpState::Active as i32,
        BgpState::OpenSent => ProtoBgpState::OpenSent as i32,
        BgpState::OpenConfirm => ProtoBgpState::OpenConfirm as i32,
        BgpState::Established => ProtoBgpState::Established as i32,
    }
}

#[derive(Clone)]
pub struct BgpGrpcService {
    bgp_request_tx: mpsc::Sender<BgpRequest>,
}

impl BgpGrpcService {
    pub fn new(bgp_request_tx: mpsc::Sender<BgpRequest>) -> Self {
        Self { bgp_request_tx }
    }
}

#[tonic::async_trait]
impl BgpService for BgpGrpcService {
    async fn add_peer(
        &self,
        request: Request<AddPeerRequest>,
    ) -> Result<Response<AddPeerResponse>, Status> {
        let addr = request.into_inner().address;

        // Send request to BGP server via channel
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = BgpRequest::AddPeer {
            addr: addr.clone(),
            response: tx,
        };

        self.bgp_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

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
            Err(_) => Err(Status::internal("request processing failed")),
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

        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = BgpRequest::RemovePeer { addr, response: tx };

        self.bgp_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

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
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn get_peers(
        &self,
        _request: Request<GetPeersRequest>,
    ) -> Result<Response<GetPeersResponse>, Status> {
        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = BgpRequest::GetPeers { response: tx };

        self.bgp_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        let peers = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        let proto_peers: Vec<ProtoPeer> = peers
            .iter()
            .map(|(addr, asn, state)| ProtoPeer {
                address: addr.to_string(),
                asn: *asn as u32,
                state: to_proto_state(*state),
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

        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let prefix_str = req.prefix.clone();
        let bgp_req = BgpRequest::AnnounceRoute {
            prefix,
            next_hop,
            origin,
            response: tx,
        };

        self.bgp_request_tx
            .send(bgp_req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AnnounceRouteResponse {
                success: true,
                message: format!("Route {} announced", prefix_str),
            })),
            Ok(Err(e)) => Ok(Response::new(AnnounceRouteResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn withdraw_route(
        &self,
        request: Request<WithdrawRouteRequest>,
    ) -> Result<Response<WithdrawRouteResponse>, Status> {
        let req = request.into_inner();

        // Parse prefix (CIDR format like "10.0.0.0/24")
        let parts: Vec<&str> = req.prefix.split('/').collect();
        if parts.len() != 2 {
            return Ok(Response::new(WithdrawRouteResponse {
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

        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let prefix_str = req.prefix.clone();
        let bgp_req = BgpRequest::WithdrawRoute {
            prefix,
            response: tx,
        };

        self.bgp_request_tx
            .send(bgp_req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        match rx.await {
            Ok(Ok(())) => Ok(Response::new(WithdrawRouteResponse {
                success: true,
                message: format!("Route {} withdrawn", prefix_str),
            })),
            Ok(Err(e)) => Ok(Response::new(WithdrawRouteResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn get_routes(
        &self,
        _request: Request<GetRoutesRequest>,
    ) -> Result<Response<GetRoutesResponse>, Status> {
        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = BgpRequest::GetRoutes { response: tx };

        self.bgp_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        let routes = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

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
                        peer_address: match path.source {
                            RouteSource::Ebgp(addr) | RouteSource::Ibgp(addr) => addr.to_string(),
                            RouteSource::Local => LOCAL_ROUTE_SOURCE_STR.to_string(),
                        },
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
