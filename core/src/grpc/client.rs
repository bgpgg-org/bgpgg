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
    bgp_service_client::BgpServiceClient, AddPeerRequest, AddRouteRequest, AsPathSegment,
    DisablePeerRequest, EnablePeerRequest, GetPeerRequest, GetPeersRequest, GetRoutesRequest,
    GetServerInfoRequest, MaxPrefixSetting, Origin, Peer, PeerStatistics, RemovePeerRequest,
    RemoveRouteRequest, Route,
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
            .get_routes(GetRoutesRequest {})
            .await?
            .into_inner()
            .routes)
    }

    /// Get all configured peers
    pub async fn get_peers(&self) -> Result<Vec<Peer>, tonic::Status> {
        Ok(self
            .inner
            .clone()
            .get_peers(GetPeersRequest {})
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

    /// Add a new BGP peer with defaults
    pub async fn add_peer(&mut self, address: String) -> Result<String, tonic::Status> {
        self.add_peer_with_config(address, None, None, None).await
    }

    /// Add a new BGP peer with custom session config
    pub async fn add_peer_with_config(
        &mut self,
        address: String,
        max_prefix: Option<MaxPrefixSetting>,
        idle_hold_time_secs: Option<u64>,
        allow_automatic_start: Option<bool>,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .add_peer(AddPeerRequest {
                address,
                max_prefix,
                idle_hold_time_secs,
                allow_automatic_start,
            })
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
    pub async fn add_route(
        &mut self,
        prefix: String,
        next_hop: String,
        origin: Origin,
        as_path: Vec<AsPathSegment>,
        local_pref: Option<u32>,
        med: Option<u32>,
        atomic_aggregate: bool,
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
            })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
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
}
