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

use crate::server::{BgpCommand, BgpServerHandle};
use tonic::{Request, Response, Status};

use super::proto::{
    peer_service_server::PeerService, AddPeerRequest, AddPeerResponse, GetPeersRequest,
    GetPeersResponse, Peer as ProtoPeer, RemovePeerRequest, RemovePeerResponse,
};

#[derive(Clone)]
pub struct BgpGrpcService {
    handle: BgpServerHandle,
}

impl BgpGrpcService {
    pub fn new(handle: BgpServerHandle) -> Self {
        Self { handle }
    }
}

#[tonic::async_trait]
impl PeerService for BgpGrpcService {
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

        self.handle
            .send_command(cmd)
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

        self.handle
            .send_command(cmd)
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
        // Direct read access to peers via handle
        let peers = self.handle.peers.lock().await;

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
}
