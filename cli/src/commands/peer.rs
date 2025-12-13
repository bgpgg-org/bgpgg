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

use bgpgg::grpc::proto::{MaxPrefixAction, MaxPrefixSetting};
use bgpgg::grpc::BgpClient;

use crate::PeerCommands;

pub async fn handle(addr: String, cmd: PeerCommands) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = BgpClient::connect(addr.clone())
        .await
        .map_err(|e| format!("Failed to connect to BGP daemon at {}: {}", addr, e))?;

    match cmd {
        PeerCommands::Add {
            address,
            max_prefix_limit,
            max_prefix_action,
        } => {
            let max_prefix = max_prefix_limit.map(|limit| MaxPrefixSetting {
                limit,
                action: match max_prefix_action.as_str() {
                    "discard" => MaxPrefixAction::Discard.into(),
                    _ => MaxPrefixAction::Terminate.into(),
                },
            });
            match client
                .add_peer_with_config(address, max_prefix, None, None, None, None, None)
                .await
            {
                Ok(message) => println!("✓ {}", message),
                Err(e) => println!("✗ {}", e.message()),
            }
        }

        PeerCommands::Remove { address } => match client.remove_peer(address).await {
            Ok(message) => println!("✓ {}", message),
            Err(e) => println!("✗ {}", e.message()),
        },

        PeerCommands::List => {
            let peers = client.get_peers().await?;

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
