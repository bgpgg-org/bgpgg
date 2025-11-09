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
    bgp_service_client::BgpServiceClient, AddPeerRequest, AnnounceRouteRequest, GetPeersRequest,
    GetRoutesRequest, Peer, RemovePeerRequest, Route, WithdrawRouteRequest,
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

    /// Add a new BGP peer
    pub async fn add_peer(&mut self, address: String) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .add_peer(AddPeerRequest { address })
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

    /// Announce a route to all established peers
    pub async fn announce_route(
        &mut self,
        prefix: String,
        next_hop: String,
        origin: i32,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .announce_route(AnnounceRouteRequest {
                prefix,
                next_hop,
                origin,
            })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Withdraw a route from all established peers
    pub async fn withdraw_route(&mut self, prefix: String) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .withdraw_route(WithdrawRouteRequest { prefix })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }
}
