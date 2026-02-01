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

use crate::bgp::msg_update::{
    AsPathSegment, AsPathSegmentType, NextHopAddr, Origin, PathAttrValue,
};
use crate::config::{MaxPrefixAction, MaxPrefixSetting, PeerConfig};
use crate::net::{IpNetwork, Ipv4Net, Ipv6Net};
use crate::peer::BgpState;
use crate::rib::RouteSource;
use crate::server::{AdminState, MgmtOp};
use std::net::IpAddr;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

use super::proto::{
    self, bgp_service_server::BgpService, AddBmpServerRequest, AddBmpServerResponse,
    AddDefinedSetRequest, AddDefinedSetResponse, AddPeerRequest, AddPeerResponse, AddPolicyRequest,
    AddPolicyResponse, AddRouteRequest, AddRouteResponse, AddRouteStreamResponse,
    AdminState as ProtoAdminState, BgpState as ProtoBgpState, DisablePeerRequest,
    DisablePeerResponse, EnablePeerRequest, EnablePeerResponse, GetPeerRequest, GetPeerResponse,
    GetServerInfoRequest, GetServerInfoResponse, ListBmpServersRequest, ListBmpServersResponse,
    ListDefinedSetsRequest, ListDefinedSetsResponse, ListPeersRequest, ListPeersResponse,
    ListPoliciesRequest, ListPoliciesResponse, ListRoutesRequest, ListRoutesResponse,
    Path as ProtoPath, Peer as ProtoPeer, PeerStatistics as ProtoPeerStatistics,
    RemoveBmpServerRequest, RemoveBmpServerResponse, RemoveDefinedSetRequest,
    RemoveDefinedSetResponse, RemovePeerRequest, RemovePeerResponse, RemovePolicyRequest,
    RemovePolicyResponse, RemoveRouteRequest, RemoveRouteResponse, ResetPeerRequest,
    ResetPeerResponse, Route as ProtoRoute, SessionConfig as ProtoSessionConfig,
    SetPolicyAssignmentRequest, SetPolicyAssignmentResponse,
};

// Proto conversion functions from sibling modules
use super::proto_community::{
    internal_to_proto_large_community, proto_extcomm_to_u64, proto_large_community_to_internal,
    u64_to_proto_extcomm,
};
use super::proto_policy::{
    defined_set_config_to_proto, policy_info_to_proto, proto_to_defined_set_config,
    proto_to_statement_config,
};

const LOCAL_ROUTE_SOURCE_STR: &str = "127.0.0.1";

type PeerStream =
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<ProtoPeer, Status>> + Send>>;
type RouteStream =
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<ProtoRoute, Status>> + Send>>;

/// Convert internal route to proto Route
fn route_to_proto(route: crate::rib::Route) -> ProtoRoute {
    let prefix_str = match route.prefix {
        IpNetwork::V4(v4) => {
            format!("{}/{}", v4.address, v4.prefix_length)
        }
        IpNetwork::V6(v6) => {
            format!("{}/{}", v6.address, v6.prefix_length)
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
            as_path: path
                .as_path
                .iter()
                .filter_map(|segment| {
                    // Filter out confederation segments per RFC 5065 (not exposed externally)
                    match segment.segment_type {
                        AsPathSegmentType::AsSet => Some(proto::AsPathSegment {
                            segment_type: proto::AsPathSegmentType::AsSet as i32,
                            asns: segment.asn_list.clone(),
                        }),
                        AsPathSegmentType::AsSequence => Some(proto::AsPathSegment {
                            segment_type: proto::AsPathSegmentType::AsSequence as i32,
                            asns: segment.asn_list.clone(),
                        }),
                        AsPathSegmentType::AsConfedSequence | AsPathSegmentType::AsConfedSet => {
                            None
                        }
                    }
                })
                .collect(),
            next_hop: path.next_hop.to_string(),
            peer_address: match path.source {
                RouteSource::Ebgp(addr) | RouteSource::Ibgp(addr) => addr.to_string(),
                RouteSource::Local => LOCAL_ROUTE_SOURCE_STR.to_string(),
            },
            local_pref: path.local_pref,
            med: path.med,
            atomic_aggregate: path.atomic_aggregate,
            unknown_attributes: path
                .unknown_attrs
                .iter()
                .filter_map(|attr| {
                    if let PathAttrValue::Unknown {
                        type_code,
                        flags,
                        data,
                    } = &attr.value
                    {
                        Some(proto::UnknownAttribute {
                            attr_type: *type_code as u32,
                            flags: *flags as u32,
                            value: data.clone(),
                        })
                    } else {
                        None
                    }
                })
                .collect(),
            communities: path.communities.clone(),
            extended_communities: path
                .extended_communities
                .iter()
                .map(|&ec| u64_to_proto_extcomm(ec))
                .collect(),
            large_communities: path
                .large_communities
                .iter()
                .map(internal_to_proto_large_community)
                .collect(),
        })
        .collect();

    ProtoRoute {
        prefix: prefix_str,
        paths: proto_paths,
    }
}

/// Parse an AddRouteRequest into internal types
fn parse_add_route_request(
    req: &AddRouteRequest,
) -> Result<(IpNetwork, NextHopAddr, Origin, Vec<AsPathSegment>), String> {
    // Parse prefix (CIDR format like "10.0.0.0/24" or "2001:db8::/32")
    let parts: Vec<&str> = req.prefix.split('/').collect();
    if parts.len() != 2 {
        return Err(
            "Invalid prefix format, expected CIDR (e.g., 10.0.0.0/24 or 2001:db8::/32)".to_string(),
        );
    }

    let address: IpAddr = parts[0]
        .parse()
        .map_err(|_| "Invalid IP address in prefix".to_string())?;
    let prefix_length: u8 = parts[1]
        .parse()
        .map_err(|_| "Invalid prefix length".to_string())?;

    let prefix = match address {
        IpAddr::V4(ipv4) => {
            if prefix_length > 32 {
                return Err(format!("IPv4 prefix length {} exceeds 32", prefix_length));
            }
            IpNetwork::V4(Ipv4Net {
                address: ipv4,
                prefix_length,
            })
        }
        IpAddr::V6(ipv6) => {
            if prefix_length > 128 {
                return Err(format!("IPv6 prefix length {} exceeds 128", prefix_length));
            }
            IpNetwork::V6(Ipv6Net {
                address: ipv6,
                prefix_length,
            })
        }
    };

    // Parse next_hop
    let next_hop_addr: IpAddr = req
        .next_hop
        .parse()
        .map_err(|_| "Invalid next_hop IP address".to_string())?;
    let next_hop = match next_hop_addr {
        IpAddr::V4(ipv4) => NextHopAddr::Ipv4(ipv4),
        IpAddr::V6(ipv6) => NextHopAddr::Ipv6(ipv6),
    };

    // Convert proto Origin to Rust Origin
    let origin = match req.origin {
        0 => Origin::IGP,
        1 => Origin::EGP,
        2 => Origin::INCOMPLETE,
        _ => return Err("Invalid origin value".to_string()),
    };

    // Convert proto AS_PATH segments to internal format
    let as_path: Vec<AsPathSegment> = req
        .as_path
        .iter()
        .map(|seg| AsPathSegment {
            segment_type: match seg.segment_type {
                0 => AsPathSegmentType::AsSet,
                1 => AsPathSegmentType::AsSequence,
                _ => AsPathSegmentType::AsSequence, // Default to AS_SEQUENCE
            },
            segment_len: seg.asns.len() as u8,
            asn_list: seg.asns.to_vec(),
        })
        .collect();

    Ok((prefix, next_hop, origin, as_path))
}

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

/// Convert internal AdminState to proto AdminState
fn to_proto_admin_state(state: AdminState) -> i32 {
    match state {
        AdminState::Up => ProtoAdminState::Up as i32,
        AdminState::Down => ProtoAdminState::Down as i32,
        AdminState::PrefixLimitReached => ProtoAdminState::PrefixLimitExceeded as i32,
    }
}

/// Convert proto SessionConfig to internal PeerConfig
fn proto_to_peer_config(proto: Option<ProtoSessionConfig>) -> PeerConfig {
    let defaults = PeerConfig::default();
    let Some(cfg) = proto else {
        return defaults;
    };

    let max_prefix = cfg.max_prefix.map(|p| MaxPrefixSetting {
        limit: p.limit,
        action: match p.action {
            1 => MaxPrefixAction::Discard,
            _ => MaxPrefixAction::Terminate,
        },
    });

    let graceful_restart = if let Some(gr) = cfg.graceful_restart {
        crate::config::GracefulRestartConfig {
            enabled: gr.enabled.unwrap_or(defaults.graceful_restart.enabled),
            restart_time: gr
                .restart_time_secs
                .unwrap_or(defaults.graceful_restart.restart_time as u32)
                as u16,
        }
    } else {
        defaults.graceful_restart
    };

    PeerConfig {
        address: String::new(),
        idle_hold_time_secs: cfg.idle_hold_time_secs.or(defaults.idle_hold_time_secs),
        damp_peer_oscillations: cfg
            .damp_peer_oscillations
            .unwrap_or(defaults.damp_peer_oscillations),
        allow_automatic_stop: cfg
            .allow_automatic_stop
            .unwrap_or(defaults.allow_automatic_stop),
        passive_mode: cfg.passive_mode.unwrap_or(defaults.passive_mode),
        delay_open_time_secs: cfg.delay_open_time_secs,
        max_prefix,
        send_notification_without_open: cfg
            .send_notification_without_open
            .unwrap_or(defaults.send_notification_without_open),
        collision_detect_established_state: cfg
            .collision_detect_established_state
            .unwrap_or(defaults.collision_detect_established_state),
        min_route_advertisement_interval_secs: cfg.min_route_advertisement_interval_secs,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        graceful_restart,
    }
}

#[derive(Clone)]
pub struct BgpGrpcService {
    mgmt_request_tx: mpsc::Sender<MgmtOp>,
}

impl BgpGrpcService {
    pub fn new(mgmt_request_tx: mpsc::Sender<MgmtOp>) -> Self {
        Self { mgmt_request_tx }
    }
}

#[tonic::async_trait]
impl BgpService for BgpGrpcService {
    type ListPeersStreamStream = PeerStream;
    type ListRoutesStreamStream = RouteStream;

    async fn add_peer(
        &self,
        request: Request<AddPeerRequest>,
    ) -> Result<Response<AddPeerResponse>, Status> {
        let inner = request.into_inner();
        let addr = inner.address;

        let config = proto_to_peer_config(inner.config);

        // Send request to BGP server via channel
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::AddPeer {
            addr: addr.clone(),
            config,
            response: tx,
        };

        self.mgmt_request_tx
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
        let peer_ip = request.into_inner().address;

        // Validate that it's a valid IP address
        peer_ip
            .parse::<std::net::IpAddr>()
            .map_err(|_| Status::invalid_argument("invalid IP address format"))?;

        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::RemovePeer {
            addr: peer_ip.clone(),
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        match rx.await {
            Ok(Ok(())) => Ok(Response::new(RemovePeerResponse {
                success: true,
                message: format!("Peer {} removed", peer_ip),
            })),
            Ok(Err(e)) => Ok(Response::new(RemovePeerResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn disable_peer(
        &self,
        request: Request<DisablePeerRequest>,
    ) -> Result<Response<DisablePeerResponse>, Status> {
        let addr = request.into_inner().address;

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.mgmt_request_tx
            .send(MgmtOp::DisablePeer { addr, response: tx })
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(DisablePeerResponse {})),
            Ok(Err(e)) => Err(Status::not_found(e)),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn enable_peer(
        &self,
        request: Request<EnablePeerRequest>,
    ) -> Result<Response<EnablePeerResponse>, Status> {
        let addr = request.into_inner().address;

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.mgmt_request_tx
            .send(MgmtOp::EnablePeer { addr, response: tx })
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(EnablePeerResponse {})),
            Ok(Err(e)) => Err(Status::not_found(e)),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn reset_peer(
        &self,
        request: Request<ResetPeerRequest>,
    ) -> Result<Response<ResetPeerResponse>, Status> {
        use crate::bgp::multiprotocol::{Afi, Safi};
        use crate::server::ResetType;

        let req = request.into_inner();

        let reset_type = match proto::ResetType::try_from(req.reset_type) {
            Ok(proto::ResetType::SoftIn) => ResetType::SoftIn,
            Ok(proto::ResetType::SoftOut) => ResetType::SoftOut,
            Ok(proto::ResetType::Soft) => ResetType::Soft,
            Ok(proto::ResetType::Hard) => ResetType::Hard,
            Err(_) => return Err(Status::invalid_argument("invalid reset type")),
        };

        let afi = req.afi.and_then(|a| match proto::Afi::try_from(a) {
            Ok(proto::Afi::Ipv4) => Some(Afi::Ipv4),
            Ok(proto::Afi::Ipv6) => Some(Afi::Ipv6),
            Err(_) => None,
        });

        let safi = req.safi.and_then(|s| match proto::Safi::try_from(s) {
            Ok(proto::Safi::Unicast) => Some(Safi::Unicast),
            Err(_) => None,
        });

        let (tx, rx) = oneshot::channel();
        self.mgmt_request_tx
            .send(MgmtOp::ResetPeer {
                addr: req.address,
                reset_type,
                afi,
                safi,
                response: tx,
            })
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(ResetPeerResponse {})),
            Ok(Err(e)) => Err(Status::not_found(e)),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn list_peers(
        &self,
        _request: Request<ListPeersRequest>,
    ) -> Result<Response<ListPeersResponse>, Status> {
        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::GetPeers { response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        let peers = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        let proto_peers: Vec<ProtoPeer> = peers
            .iter()
            .map(|peer| ProtoPeer {
                address: peer.address.clone(),
                asn: peer.asn.unwrap_or(0), // 0 for peers still in handshake
                state: to_proto_state(peer.state),
                admin_state: to_proto_admin_state(peer.admin_state),
                configured: peer.configured,
                import_policies: peer.import_policies.clone(),
                export_policies: peer.export_policies.clone(),
            })
            .collect();

        Ok(Response::new(ListPeersResponse { peers: proto_peers }))
    }

    async fn list_peers_stream(
        &self,
        _request: Request<ListPeersRequest>,
    ) -> Result<Response<Self::ListPeersStreamStream>, Status> {
        use tokio_stream::wrappers::UnboundedReceiverStream;
        use tokio_stream::StreamExt;

        let (tx, rx) = mpsc::unbounded_channel();

        // Send streaming request to BGP server
        let mgmt_req = MgmtOp::GetPeersStream { tx };
        self.mgmt_request_tx
            .send(mgmt_req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Convert channel receiver to gRPC stream
        let stream = UnboundedReceiverStream::new(rx).map(|peer| {
            Ok(ProtoPeer {
                address: peer.address,
                asn: peer.asn.unwrap_or(0),
                state: to_proto_state(peer.state),
                admin_state: to_proto_admin_state(peer.admin_state),
                configured: peer.configured,
                import_policies: peer.import_policies,
                export_policies: peer.export_policies,
            })
        });

        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_peer(
        &self,
        request: Request<GetPeerRequest>,
    ) -> Result<Response<GetPeerResponse>, Status> {
        let addr = request.into_inner().address;

        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::GetPeer {
            addr: addr.clone(),
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        let peer_info = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        match peer_info {
            Some(peer) => {
                let proto_peer = ProtoPeer {
                    address: peer.address.clone(),
                    asn: peer.asn.unwrap_or(0), // 0 for peers still in handshake
                    state: to_proto_state(peer.state),
                    admin_state: to_proto_admin_state(peer.admin_state),
                    configured: peer.configured,
                    import_policies: peer.import_policies.clone(),
                    export_policies: peer.export_policies.clone(),
                };

                let proto_statistics = ProtoPeerStatistics {
                    open_sent: peer.statistics.open_sent,
                    keepalive_sent: peer.statistics.keepalive_sent,
                    update_sent: peer.statistics.update_sent,
                    notification_sent: peer.statistics.notification_sent,
                    open_received: peer.statistics.open_received,
                    keepalive_received: peer.statistics.keepalive_received,
                    update_received: peer.statistics.update_received,
                    notification_received: peer.statistics.notification_received,
                };

                Ok(Response::new(GetPeerResponse {
                    peer: Some(proto_peer),
                    statistics: Some(proto_statistics),
                }))
            }
            None => Err(Status::not_found(format!("Peer {} not found", addr))),
        }
    }

    async fn add_route(
        &self,
        request: Request<AddRouteRequest>,
    ) -> Result<Response<AddRouteResponse>, Status> {
        let req = request.into_inner();
        let prefix_str = req.prefix.clone();

        // Parse request using helper
        let (prefix, next_hop, origin, as_path) = match parse_add_route_request(&req) {
            Ok(parsed) => parsed,
            Err(e) => {
                return Ok(Response::new(AddRouteResponse {
                    success: false,
                    message: e,
                }))
            }
        };

        // Convert proto extended communities to internal u64
        let extended_communities: Vec<u64> = req
            .extended_communities
            .iter()
            .map(proto_extcomm_to_u64)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Status::invalid_argument(format!("Invalid extended community: {}", e)))?;

        // Convert proto large communities to internal LargeCommunity
        let large_communities = req
            .large_communities
            .iter()
            .map(proto_large_community_to_internal)
            .collect();

        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mgmt_req = MgmtOp::AddRoute {
            prefix,
            next_hop,
            origin,
            as_path,
            local_pref: req.local_pref,
            med: req.med,
            atomic_aggregate: req.atomic_aggregate,
            communities: req.communities,
            extended_communities,
            large_communities,
            response: tx,
        };

        self.mgmt_request_tx
            .send(mgmt_req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AddRouteResponse {
                success: true,
                message: format!("Route {} added", prefix_str),
            })),
            Ok(Err(e)) => Ok(Response::new(AddRouteResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn add_route_stream(
        &self,
        request: Request<tonic::Streaming<AddRouteRequest>>,
    ) -> Result<Response<AddRouteStreamResponse>, Status> {
        let mut stream = request.into_inner();
        let mut count = 0u64;

        while let Some(req) = stream.next().await {
            let req = req?;

            // Parse request using helper
            let (prefix, next_hop, origin, as_path) = match parse_add_route_request(&req) {
                Ok(parsed) => parsed,
                Err(_) => continue, // Skip invalid routes
            };

            // Convert proto extended communities to internal u64
            let extended_communities: Vec<u64> = match req
                .extended_communities
                .iter()
                .map(proto_extcomm_to_u64)
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(ec) => ec,
                Err(_) => continue, // Skip routes with invalid extended communities
            };

            // Convert proto large communities to internal LargeCommunity
            let large_communities = req
                .large_communities
                .iter()
                .map(proto_large_community_to_internal)
                .collect();

            // Send request to BGP server
            let (tx, rx) = tokio::sync::oneshot::channel();
            let mgmt_req = MgmtOp::AddRoute {
                prefix,
                next_hop,
                origin,
                as_path,
                local_pref: req.local_pref,
                med: req.med,
                atomic_aggregate: req.atomic_aggregate,
                communities: req.communities,
                extended_communities,
                large_communities,
                response: tx,
            };

            if self.mgmt_request_tx.send(mgmt_req).await.is_err() {
                break;
            }

            // Wait for response
            if let Ok(Ok(())) = rx.await {
                count += 1;
            }
        }

        Ok(Response::new(AddRouteStreamResponse {
            count,
            message: format!("{} routes added", count),
        }))
    }

    async fn remove_route(
        &self,
        request: Request<RemoveRouteRequest>,
    ) -> Result<Response<RemoveRouteResponse>, Status> {
        let req = request.into_inner();

        // Parse prefix (CIDR format like "10.0.0.0/24" or "2001:db8::/32")
        let parts: Vec<&str> = req.prefix.split('/').collect();
        if parts.len() != 2 {
            return Ok(Response::new(RemoveRouteResponse {
                success: false,
                message:
                    "Invalid prefix format, expected CIDR (e.g., 10.0.0.0/24 or 2001:db8::/32)"
                        .to_string(),
            }));
        }

        let address: IpAddr = parts[0]
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid IP address in prefix"))?;
        let prefix_length: u8 = parts[1]
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid prefix length"))?;

        let prefix = match address {
            IpAddr::V4(ipv4) => IpNetwork::V4(Ipv4Net {
                address: ipv4,
                prefix_length,
            }),
            IpAddr::V6(ipv6) => IpNetwork::V6(Ipv6Net {
                address: ipv6,
                prefix_length,
            }),
        };

        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let prefix_str = req.prefix.clone();
        let mgmt_req = MgmtOp::RemoveRoute {
            prefix,
            response: tx,
        };

        self.mgmt_request_tx
            .send(mgmt_req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        match rx.await {
            Ok(Ok(())) => Ok(Response::new(RemoveRouteResponse {
                success: true,
                message: format!("Route {} removed", prefix_str),
            })),
            Ok(Err(e)) => Ok(Response::new(RemoveRouteResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn list_routes(
        &self,
        request: Request<ListRoutesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        let req = request.into_inner();

        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mgmt_req = MgmtOp::GetRoutes {
            rib_type: req.rib_type,
            peer_address: req.peer_address,
            response: tx,
        };

        self.mgmt_request_tx
            .send(mgmt_req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        let routes = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?
            .map_err(Status::invalid_argument)?;

        // Convert Rust routes to proto routes
        let proto_routes: Vec<ProtoRoute> = routes.into_iter().map(route_to_proto).collect();

        Ok(Response::new(ListRoutesResponse {
            routes: proto_routes,
        }))
    }

    async fn list_routes_stream(
        &self,
        request: Request<ListRoutesRequest>,
    ) -> Result<Response<Self::ListRoutesStreamStream>, Status> {
        use tokio_stream::wrappers::UnboundedReceiverStream;
        use tokio_stream::StreamExt;

        let req = request.into_inner();
        let (tx, rx) = mpsc::unbounded_channel();

        // Send streaming request to BGP server
        let mgmt_req = MgmtOp::GetRoutesStream {
            rib_type: req.rib_type,
            peer_address: req.peer_address,
            tx,
        };
        self.mgmt_request_tx
            .send(mgmt_req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Convert channel receiver to gRPC stream
        let stream = UnboundedReceiverStream::new(rx).map(|route| Ok(route_to_proto(route)));

        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_server_info(
        &self,
        _request: Request<GetServerInfoRequest>,
    ) -> Result<Response<GetServerInfoResponse>, Status> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::GetServerInfo { response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        let (listen_addr, listen_port, num_routes) = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        Ok(Response::new(GetServerInfoResponse {
            listen_addr: listen_addr.to_string(),
            listen_port: listen_port as u32,
            num_routes,
        }))
    }

    async fn add_bmp_server(
        &self,
        request: Request<AddBmpServerRequest>,
    ) -> Result<Response<AddBmpServerResponse>, Status> {
        let inner = request.into_inner();
        let addr = inner
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid BMP server address: {}", e)))?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::AddBmpServer {
            addr,
            statistics_timeout: inner.statistics_timeout,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AddBmpServerResponse {
                success: true,
                message: format!("BMP server {} added", addr),
            })),
            Ok(Err(e)) => Ok(Response::new(AddBmpServerResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn remove_bmp_server(
        &self,
        request: Request<RemoveBmpServerRequest>,
    ) -> Result<Response<RemoveBmpServerResponse>, Status> {
        let addr_str = request.into_inner().address;
        let addr = addr_str
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid BMP server address: {}", e)))?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::RemoveBmpServer { addr, response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(RemoveBmpServerResponse {
                success: true,
                message: format!("BMP server {} removed", addr),
            })),
            Ok(Err(e)) => Ok(Response::new(RemoveBmpServerResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn list_bmp_servers(
        &self,
        _request: Request<ListBmpServersRequest>,
    ) -> Result<Response<ListBmpServersResponse>, Status> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::GetBmpServers { response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        let addresses = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        Ok(Response::new(ListBmpServersResponse { addresses }))
    }

    async fn add_defined_set(
        &self,
        request: Request<AddDefinedSetRequest>,
    ) -> Result<Response<AddDefinedSetResponse>, Status> {
        let inner = request.into_inner();
        let set_config = inner
            .set
            .ok_or_else(|| Status::invalid_argument("set config required"))?;

        // Convert proto to internal types
        let set = proto_to_defined_set_config(&set_config)
            .map_err(|e| Status::invalid_argument(format!("invalid set config: {}", e)))?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::AddDefinedSet { set, response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AddDefinedSetResponse {
                success: true,
                message: "defined set added".to_string(),
            })),
            Ok(Err(e)) => Ok(Response::new(AddDefinedSetResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn remove_defined_set(
        &self,
        request: Request<RemoveDefinedSetRequest>,
    ) -> Result<Response<RemoveDefinedSetResponse>, Status> {
        use crate::policy::DefinedSetType;

        let inner = request.into_inner();

        let set_type = DefinedSetType::parse(&inner.set_type).map_err(Status::invalid_argument)?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::RemoveDefinedSet {
            set_type,
            name: inner.name,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(RemoveDefinedSetResponse {
                success: true,
                message: "defined set removed".to_string(),
            })),
            Ok(Err(e)) => Ok(Response::new(RemoveDefinedSetResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn list_defined_sets(
        &self,
        request: Request<ListDefinedSetsRequest>,
    ) -> Result<Response<ListDefinedSetsResponse>, Status> {
        use crate::policy::DefinedSetType;

        let inner = request.into_inner();

        let set_type = if let Some(st) = inner.set_type {
            Some(DefinedSetType::parse(&st).map_err(Status::invalid_argument)?)
        } else {
            None
        };

        let (tx, rx) = tokio::sync::oneshot::channel();

        let req = MgmtOp::ListDefinedSets {
            set_type,
            name: inner.name,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(results) => {
                let sets = results
                    .into_iter()
                    .map(defined_set_config_to_proto)
                    .collect();
                Ok(Response::new(ListDefinedSetsResponse { sets }))
            }
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn add_policy(
        &self,
        request: Request<AddPolicyRequest>,
    ) -> Result<Response<AddPolicyResponse>, Status> {
        let inner = request.into_inner();

        // Convert proto statements to internal format
        let statements = inner
            .statements
            .into_iter()
            .map(proto_to_statement_config)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Status::invalid_argument(format!("invalid statement config: {}", e)))?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::AddPolicy {
            name: inner.name,
            statements,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AddPolicyResponse {
                success: true,
                message: "policy added".to_string(),
            })),
            Ok(Err(e)) => Ok(Response::new(AddPolicyResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn remove_policy(
        &self,
        request: Request<RemovePolicyRequest>,
    ) -> Result<Response<RemovePolicyResponse>, Status> {
        let inner = request.into_inner();

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::RemovePolicy {
            name: inner.name,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(RemovePolicyResponse {
                success: true,
                message: "policy removed".to_string(),
            })),
            Ok(Err(e)) => Ok(Response::new(RemovePolicyResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn list_policies(
        &self,
        request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        let inner = request.into_inner();
        let (tx, rx) = tokio::sync::oneshot::channel();

        let req = MgmtOp::ListPolicies {
            name: inner.name,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(results) => {
                let policies = results.into_iter().map(policy_info_to_proto).collect();
                Ok(Response::new(ListPoliciesResponse { policies }))
            }
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn set_policy_assignment(
        &self,
        request: Request<SetPolicyAssignmentRequest>,
    ) -> Result<Response<SetPolicyAssignmentResponse>, Status> {
        let inner = request.into_inner();

        // Parse peer address
        let peer_addr = inner
            .peer_address
            .parse::<std::net::IpAddr>()
            .map_err(|_| Status::invalid_argument("invalid peer address"))?;

        // Parse direction
        let direction = match inner.direction.as_str() {
            "import" => crate::server::PolicyDirection::Import,
            "export" => crate::server::PolicyDirection::Export,
            _ => {
                return Err(Status::invalid_argument(
                    "direction must be 'import' or 'export'",
                ))
            }
        };

        // Parse default action
        let default_action = inner
            .default_action
            .as_ref()
            .map(|action| match action.as_str() {
                "accept" => crate::policy::PolicyResult::Accept,
                "reject" => crate::policy::PolicyResult::Reject,
                _ => crate::policy::PolicyResult::Reject, // Default to reject
            });

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::SetPolicyAssignment {
            peer_addr,
            direction,
            policy_names: inner.policy_names,
            default_action,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(SetPolicyAssignmentResponse {
                success: true,
                message: "policy assignment set".to_string(),
            })),
            Ok(Err(e)) => Ok(Response::new(SetPolicyAssignmentResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }
}
