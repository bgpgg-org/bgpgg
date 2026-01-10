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
    bgp_service_client::BgpServiceClient, AddBmpServerRequest, AddPeerRequest, AddRouteRequest,
    AsPathSegment, DisablePeerRequest, EnablePeerRequest, GetPeerRequest, GetServerInfoRequest,
    ListBmpServersRequest, ListPeersRequest, ListRoutesRequest, Origin, Peer, PeerStatistics,
    RemoveBmpServerRequest, RemovePeerRequest, RemoveRouteRequest, Route, SessionConfig,
};
use std::net::Ipv4Addr;
use tonic::transport::Channel;

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
            .list_routes(ListRoutesRequest {})
            .await?
            .into_inner()
            .routes)
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
    ) -> Result<String, tonic::Status> {
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
            )| {
                AddRouteRequest {
                    prefix,
                    next_hop,
                    origin: origin.into(),
                    as_path,
                    local_pref,
                    med,
                    atomic_aggregate,
                    communities,
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

    /// Get server info including the listen address and port
    pub async fn get_server_info(&self) -> Result<(Ipv4Addr, u16), tonic::Status> {
        let resp = self
            .inner
            .clone()
            .get_server_info(GetServerInfoRequest {})
            .await?
            .into_inner();

        let addr: Ipv4Addr = resp
            .listen_addr
            .parse()
            .map_err(|_| tonic::Status::internal("invalid listen_addr"))?;
        Ok((addr, resp.listen_port as u16))
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
}
