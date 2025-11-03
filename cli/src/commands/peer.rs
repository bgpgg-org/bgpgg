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

use bgpgg::grpc::proto::{
    peer_service_client::PeerServiceClient, AddPeerRequest, GetPeersRequest, RemovePeerRequest,
};
use tonic::transport::Channel;

use crate::PeerCommands;

pub async fn handle(channel: Channel, cmd: PeerCommands) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = PeerServiceClient::new(channel);

    match cmd {
        PeerCommands::Add { address } => {
            let request = tonic::Request::new(AddPeerRequest {
                address: address.clone(),
            });
            let response = client.add_peer(request).await?;
            let resp = response.into_inner();

            if resp.success {
                println!("✓ {}", resp.message);
            } else {
                println!("✗ {}", resp.message);
            }
        }

        PeerCommands::Remove { address } => {
            let request = tonic::Request::new(RemovePeerRequest {
                address: address.clone(),
            });
            let response = client.remove_peer(request).await?;
            let resp = response.into_inner();

            if resp.success {
                println!("✓ {}", resp.message);
            } else {
                println!("✗ {}", resp.message);
            }
        }

        PeerCommands::List => {
            let request = tonic::Request::new(GetPeersRequest {});
            let response = client.get_peers(request).await?;

            let peers = response.into_inner().peers;

            if peers.is_empty() {
                println!("No peers configured");
            } else {
                println!("{:<30} {:<10} {:<15}", "Address", "ASN", "State");
                println!("{}", "-".repeat(60));

                for peer in peers {
                    println!("{:<30} {:<10} {:<15}", peer.address, peer.asn, peer.state);
                }
            }
        }
    }

    Ok(())
}
