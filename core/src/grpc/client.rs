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

use super::proto::{
    self, bgp_service_client::BgpServiceClient, AddBmpServerRequest, AddDefinedSetRequest,
    AddPeerRequest, AddPolicyRequest, AddRouteRequest, AsPathSegment, DefinedSetConfig,
    DefinedSetInfo, DisablePeerRequest, EnablePeerRequest, GetPeerRequest, GetServerInfoRequest,
    ListBmpServersRequest, ListDefinedSetsRequest, ListPeersRequest, ListPoliciesRequest,
    ListRoutesRequest, Origin, Peer, PeerStatistics, PolicyInfo, RemoveBmpServerRequest,
    RemoveDefinedSetRequest, RemovePeerRequest, RemovePolicyRequest, RemoveRouteRequest,
    ResetPeerRequest, Route, SessionConfig, SetPolicyAssignmentRequest, StatementConfig,
};
use std::net::Ipv4Addr;
use tonic::transport::Channel;

/// Convert internal u64 representation to proto ExtendedCommunity
fn u64_to_proto_extcomm(extcomm: u64) -> super::proto::ExtendedCommunity {
    use super::proto;
    use crate::bgp::ext_community::*;

    let typ = ext_type(extcomm);
    let subtype = ext_subtype(extcomm);
    let value_bytes = ext_value(extcomm);
    let is_transitive = (typ & TYPE_NON_TRANSITIVE_BIT) == 0;
    let base_type = typ & !TYPE_NON_TRANSITIVE_BIT;

    let community = match base_type {
        TYPE_TWO_OCTET_AS => {
            let asn = u16::from_be_bytes([value_bytes[0], value_bytes[1]]);
            let local_admin_bytes = u32::from_be_bytes([
                value_bytes[2],
                value_bytes[3],
                value_bytes[4],
                value_bytes[5],
            ]);

            // Link Bandwidth has same base type but different subtype
            if subtype == SUBTYPE_LINK_BANDWIDTH {
                let bandwidth = f32::from_bits(local_admin_bytes);
                proto::extended_community::Community::LinkBandwidth(
                    proto::extended_community::LinkBandwidth {
                        is_transitive,
                        asn: asn as u32,
                        bandwidth,
                    },
                )
            } else {
                proto::extended_community::Community::TwoOctetAs(
                    proto::extended_community::TwoOctetAsSpecific {
                        is_transitive,
                        sub_type: subtype as u32,
                        asn: asn as u32,
                        local_admin: local_admin_bytes,
                    },
                )
            }
        }

        TYPE_IPV4_ADDRESS => {
            let ip = Ipv4Addr::new(
                value_bytes[0],
                value_bytes[1],
                value_bytes[2],
                value_bytes[3],
            );
            let local_admin = u16::from_be_bytes([value_bytes[4], value_bytes[5]]);
            proto::extended_community::Community::Ipv4Address(
                proto::extended_community::IPv4AddressSpecific {
                    is_transitive,
                    sub_type: subtype as u32,
                    address: ip.to_string(),
                    local_admin: local_admin as u32,
                },
            )
        }

        TYPE_FOUR_OCTET_AS => {
            let asn = u32::from_be_bytes([
                value_bytes[0],
                value_bytes[1],
                value_bytes[2],
                value_bytes[3],
            ]);
            let local_admin = u16::from_be_bytes([value_bytes[4], value_bytes[5]]);
            proto::extended_community::Community::FourOctetAs(
                proto::extended_community::FourOctetAsSpecific {
                    is_transitive,
                    sub_type: subtype as u32,
                    asn,
                    local_admin: local_admin as u32,
                },
            )
        }

        TYPE_OPAQUE => {
            proto::extended_community::Community::Opaque(proto::extended_community::Opaque {
                is_transitive,
                value: value_bytes.to_vec(),
            })
        }

        _ => {
            // Unknown type - preserve all 7 bytes (subtype + value)
            let mut value = vec![subtype];
            value.extend_from_slice(&value_bytes);
            proto::extended_community::Community::Unknown(proto::extended_community::Unknown {
                type_code: typ as u32,
                value,
            })
        }
    };

    proto::ExtendedCommunity {
        community: Some(community),
    }
}

/// Simplified wrapper around the gRPC client that hides boilerplate
pub struct BgpClient {
    inner: BgpServiceClient<Channel>,
    /// Router ID of the BGP server this client is connected to.
    pub router_id: Ipv4Addr,
}

impl BgpClient {
    /// Connect to a BGP gRPC server
    pub async fn connect(addr: impl Into<String>) -> Result<Self, tonic::transport::Error> {
        let inner = BgpServiceClient::connect(addr.into()).await?;
        Ok(Self {
            inner,
            router_id: Ipv4Addr::UNSPECIFIED,
        })
    }

    /// Connect to a BGP gRPC server with a known router ID
    pub async fn connect_with_router_id(
        addr: impl Into<String>,
        router_id: Ipv4Addr,
    ) -> Result<Self, tonic::transport::Error> {
        let inner = BgpServiceClient::connect(addr.into()).await?;
        Ok(Self { inner, router_id })
    }

    /// Get all routes from the Loc-RIB
    pub async fn get_routes(&self) -> Result<Vec<Route>, tonic::Status> {
        Ok(self
            .inner
            .clone()
            .list_routes(ListRoutesRequest {
                rib_type: None,
                peer_address: None,
            })
            .await?
            .into_inner()
            .routes)
    }

    /// Get all routes from the Loc-RIB using streaming
    pub async fn get_routes_stream(&self) -> Result<Vec<Route>, tonic::Status> {
        use tokio_stream::StreamExt;

        let mut stream = self
            .inner
            .clone()
            .list_routes_stream(ListRoutesRequest {
                rib_type: None,
                peer_address: None,
            })
            .await?
            .into_inner();

        let mut routes = Vec::new();
        while let Some(route) = stream.next().await {
            routes.push(route?);
        }
        Ok(routes)
    }

    /// Get routes from a specific peer's Adj-RIB-In
    pub async fn get_adj_rib_in(&self, peer_address: &str) -> Result<Vec<Route>, tonic::Status> {
        use super::proto::RibType;

        Ok(self
            .inner
            .clone()
            .list_routes(ListRoutesRequest {
                rib_type: Some(RibType::AdjIn as i32),
                peer_address: Some(peer_address.to_string()),
            })
            .await?
            .into_inner()
            .routes)
    }

    /// Get routes from a specific peer's Adj-RIB-Out (computed on-demand)
    pub async fn get_adj_rib_out(&self, peer_address: &str) -> Result<Vec<Route>, tonic::Status> {
        use super::proto::RibType;

        Ok(self
            .inner
            .clone()
            .list_routes(ListRoutesRequest {
                rib_type: Some(RibType::AdjOut as i32),
                peer_address: Some(peer_address.to_string()),
            })
            .await?
            .into_inner()
            .routes)
    }

    /// Get routes from Adj-RIB-In using streaming
    pub async fn get_adj_rib_in_stream(
        &self,
        peer_address: &str,
    ) -> Result<Vec<Route>, tonic::Status> {
        use super::proto::RibType;
        use tokio_stream::StreamExt;

        let mut stream = self
            .inner
            .clone()
            .list_routes_stream(ListRoutesRequest {
                rib_type: Some(RibType::AdjIn as i32),
                peer_address: Some(peer_address.to_string()),
            })
            .await?
            .into_inner();

        let mut routes = Vec::new();
        while let Some(route) = stream.next().await {
            routes.push(route?);
        }
        Ok(routes)
    }

    /// Get routes from Adj-RIB-Out using streaming
    pub async fn get_adj_rib_out_stream(
        &self,
        peer_address: &str,
    ) -> Result<Vec<Route>, tonic::Status> {
        use super::proto::RibType;
        use tokio_stream::StreamExt;

        let mut stream = self
            .inner
            .clone()
            .list_routes_stream(ListRoutesRequest {
                rib_type: Some(RibType::AdjOut as i32),
                peer_address: Some(peer_address.to_string()),
            })
            .await?
            .into_inner();

        let mut routes = Vec::new();
        while let Some(route) = stream.next().await {
            routes.push(route?);
        }
        Ok(routes)
    }

    /// Get all configured peers
    pub async fn get_peers(&self) -> Result<Vec<Peer>, tonic::Status> {
        Ok(self
            .inner
            .clone()
            .list_peers(ListPeersRequest {})
            .await?
            .into_inner()
            .peers)
    }

    /// Get all configured peers using streaming
    pub async fn get_peers_stream(&self) -> Result<Vec<Peer>, tonic::Status> {
        use tokio_stream::StreamExt;

        let mut stream = self
            .inner
            .clone()
            .list_peers_stream(ListPeersRequest {})
            .await?
            .into_inner();

        let mut peers = Vec::new();
        while let Some(peer) = stream.next().await {
            peers.push(peer?);
        }
        Ok(peers)
    }

    /// Get a specific peer with statistics
    pub async fn get_peer(
        &self,
        address: String,
    ) -> Result<(Option<Peer>, Option<PeerStatistics>), tonic::Status> {
        let resp = self
            .inner
            .clone()
            .get_peer(GetPeerRequest { address })
            .await?
            .into_inner();

        Ok((resp.peer, resp.statistics))
    }

    /// Add a new BGP peer. Pass None for config to use all defaults.
    pub async fn add_peer(
        &mut self,
        address: String,
        config: Option<SessionConfig>,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .add_peer(AddPeerRequest { address, config })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Remove a BGP peer
    pub async fn remove_peer(&mut self, address: String) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .remove_peer(RemovePeerRequest { address })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Disable a BGP peer (RFC 4486 Administrative Shutdown)
    pub async fn disable_peer(&mut self, address: String) -> Result<(), tonic::Status> {
        self.inner
            .disable_peer(DisablePeerRequest { address })
            .await?;
        Ok(())
    }

    /// Enable a BGP peer (undo Administrative Shutdown)
    pub async fn enable_peer(&mut self, address: String) -> Result<(), tonic::Status> {
        self.inner
            .enable_peer(EnablePeerRequest { address })
            .await?;
        Ok(())
    }

    /// Reset a BGP peer with flexible reset types and AFI/SAFI support
    pub async fn reset_peer(
        &mut self,
        address: String,
        reset_type: proto::ResetType,
        afi: Option<proto::Afi>,
        safi: Option<proto::Safi>,
    ) -> Result<(), tonic::Status> {
        self.inner
            .reset_peer(ResetPeerRequest {
                address,
                reset_type: reset_type as i32,
                afi: afi.map(|a| a as i32),
                safi: safi.map(|s| s as i32),
            })
            .await?;
        Ok(())
    }

    /// Add a route to the global RIB
    #[allow(clippy::too_many_arguments)]
    pub async fn add_route(
        &mut self,
        prefix: String,
        next_hop: String,
        origin: Origin,
        as_path: Vec<AsPathSegment>,
        local_pref: Option<u32>,
        med: Option<u32>,
        atomic_aggregate: bool,
        communities: Vec<u32>,
        extended_communities: Vec<u64>,
    ) -> Result<String, tonic::Status> {
        // Convert u64 extended communities to proto format
        let extended_communities_proto = extended_communities
            .into_iter()
            .map(u64_to_proto_extcomm)
            .collect();

        let resp = self
            .inner
            .add_route(AddRouteRequest {
                prefix,
                next_hop,
                origin: origin.into(),
                as_path,
                local_pref,
                med,
                atomic_aggregate,
                communities,
                extended_communities: extended_communities_proto,
            })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Add multiple routes using streaming API for better performance
    #[allow(clippy::type_complexity)]
    pub async fn add_route_stream(
        &mut self,
        routes: Vec<(
            String,
            String,
            Origin,
            Vec<AsPathSegment>,
            Option<u32>,
            Option<u32>,
            bool,
            Vec<u32>,
            Vec<u64>,
        )>,
    ) -> Result<u64, tonic::Status> {
        let requests = routes.into_iter().map(
            |(
                prefix,
                next_hop,
                origin,
                as_path,
                local_pref,
                med,
                atomic_aggregate,
                communities,
                extended_communities,
            )| {
                // Convert u64 extended communities to proto format
                let extended_communities_proto = extended_communities
                    .into_iter()
                    .map(u64_to_proto_extcomm)
                    .collect();

                AddRouteRequest {
                    prefix,
                    next_hop,
                    origin: origin.into(),
                    as_path,
                    local_pref,
                    med,
                    atomic_aggregate,
                    communities,
                    extended_communities: extended_communities_proto,
                }
            },
        );

        let stream = tokio_stream::iter(requests);
        let resp = self.inner.add_route_stream(stream).await?.into_inner();

        Ok(resp.count)
    }

    /// Remove a route from all established peers
    pub async fn remove_route(&mut self, prefix: String) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .remove_route(RemoveRouteRequest { prefix })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Get server info including the listen address, port, and route count
    pub async fn get_server_info(&self) -> Result<(std::net::IpAddr, u16, u64), tonic::Status> {
        let resp = self
            .inner
            .clone()
            .get_server_info(GetServerInfoRequest {})
            .await?
            .into_inner();

        let addr: std::net::IpAddr = resp
            .listen_addr
            .parse()
            .map_err(|_| tonic::Status::internal("invalid listen_addr"))?;
        Ok((addr, resp.listen_port as u16, resp.num_routes))
    }

    /// Add a BMP server destination
    pub async fn add_bmp_server(
        &mut self,
        address: String,
        statistics_timeout: Option<u64>,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .add_bmp_server(AddBmpServerRequest {
                address,
                statistics_timeout,
            })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Remove a BMP server destination
    pub async fn remove_bmp_server(&mut self, address: String) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .remove_bmp_server(RemoveBmpServerRequest { address })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Get all BMP server destinations
    pub async fn get_bmp_servers(&self) -> Result<Vec<String>, tonic::Status> {
        Ok(self
            .inner
            .clone()
            .list_bmp_servers(ListBmpServersRequest {})
            .await?
            .into_inner()
            .addresses)
    }

    /// Add a policy definition
    pub async fn add_policy(
        &mut self,
        name: String,
        statements: Vec<StatementConfig>,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .add_policy(AddPolicyRequest { name, statements })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// List all policy definitions
    pub async fn list_policies(&self) -> Result<Vec<PolicyInfo>, tonic::Status> {
        Ok(self
            .inner
            .clone()
            .list_policies(ListPoliciesRequest { name: None })
            .await?
            .into_inner()
            .policies)
    }

    /// Add a defined set
    pub async fn add_defined_set(
        &mut self,
        set: DefinedSetConfig,
        replace: bool,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .add_defined_set(AddDefinedSetRequest {
                set: Some(set),
                replace,
            })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// List all defined sets
    pub async fn list_defined_sets(&self) -> Result<Vec<DefinedSetInfo>, tonic::Status> {
        Ok(self
            .inner
            .clone()
            .list_defined_sets(ListDefinedSetsRequest {
                set_type: None,
                name: None,
            })
            .await?
            .into_inner()
            .sets)
    }

    /// Remove a defined set
    pub async fn remove_defined_set(
        &mut self,
        set_type: String,
        name: String,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .remove_defined_set(RemoveDefinedSetRequest {
                set_type,
                name,
                all: false,
            })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Remove a policy
    pub async fn remove_policy(&mut self, name: String) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .remove_policy(RemovePolicyRequest { name })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Set policy assignment for a peer
    pub async fn set_policy_assignment(
        &mut self,
        peer_address: String,
        direction: String,
        policy_names: Vec<String>,
        default_action: Option<String>,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .set_policy_assignment(SetPolicyAssignmentRequest {
                peer_address,
                direction,
                policy_names,
                default_action,
            })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }
}
