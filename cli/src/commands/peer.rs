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

use bgpgg::grpc::proto::{AdminState, BgpState, MaxPrefixAction, MaxPrefixSetting, SessionConfig};
use bgpgg::grpc::BgpClient;

use crate::PeerCommands;

pub async fn handle(addr: String, cmd: PeerCommands) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = BgpClient::connect(addr.clone())
        .await
        .map_err(|e| format!("Failed to connect to BGP daemon at {}: {}", addr, e))?;

    match cmd {
        PeerCommands::Add {
            address,
            remote_as: _,
            max_prefix_limit,
            max_prefix_action,
        } => {
            // Append standard BGP port if not provided
            let full_address = if address.contains(':') {
                address
            } else {
                format!("{}:179", address)
            };

            let config = max_prefix_limit.map(|limit| SessionConfig {
                max_prefix: Some(MaxPrefixSetting {
                    limit,
                    action: match max_prefix_action.as_str() {
                        "discard" => MaxPrefixAction::Discard.into(),
                        _ => MaxPrefixAction::Terminate.into(),
                    },
                }),
                ..Default::default()
            });
            match client.add_peer(full_address, config).await {
                Ok(message) => println!("{}", message),
                Err(e) => eprintln!("Error: {}", e.message()),
            }
        }

        PeerCommands::Del { address } => {
            // Accept both IP and IP:PORT, extract just the IP
            let peer_ip = if let Ok(sock_addr) = address.parse::<std::net::SocketAddr>() {
                sock_addr.ip().to_string()
            } else {
                address
            };

            match client.remove_peer(peer_ip).await {
                Ok(message) => println!("{}", message),
                Err(e) => eprintln!("Error: {}", e.message()),
            }
        }

        PeerCommands::Show { address } => {
            // Accept both IP and IP:PORT, extract just the IP
            let peer_ip = if let Ok(sock_addr) = address.parse::<std::net::SocketAddr>() {
                sock_addr.ip().to_string()
            } else {
                address.clone()
            };

            let (peer_opt, stats_opt) = client.get_peer(peer_ip.clone()).await?;

            match (peer_opt, stats_opt) {
                (Some(peer), Some(stats)) => {
                    println!("Peer: {}", peer_ip);
                    println!("  ASN:         {}", peer.asn);
                    println!("  State:       {}", format_state(peer.state()));
                    println!("  Admin State: {}", format_admin_state(peer.admin_state()));
                    println!(
                        "  Configured:  {}",
                        if peer.configured { "yes" } else { "no" }
                    );
                    println!();
                    println!("Statistics:");
                    println!("  Messages Sent:");
                    println!("    OPEN:         {}", stats.open_sent);
                    println!("    KEEPALIVE:    {}", stats.keepalive_sent);
                    println!("    UPDATE:       {}", stats.update_sent);
                    println!("    NOTIFICATION: {}", stats.notification_sent);
                    println!("  Messages Received:");
                    println!("    OPEN:         {}", stats.open_received);
                    println!("    KEEPALIVE:    {}", stats.keepalive_received);
                    println!("    UPDATE:       {}", stats.update_received);
                    println!("    NOTIFICATION: {}", stats.notification_received);
                }
                _ => {
                    eprintln!("Peer not found: {}", peer_ip);
                }
            }
        }

        PeerCommands::List => {
            let peers = client.get_peers().await?;

            if peers.is_empty() {
                println!("No peers configured");
            } else {
                println!("{:<30} {:<10} {:<15}", "Address", "ASN", "State");
                println!("{}", "-".repeat(60));

                for peer in peers {
                    let asn_str = if peer.asn == 0 {
                        "-".to_string()
                    } else {
                        peer.asn.to_string()
                    };
                    println!(
                        "{:<30} {:<10} {:<15}",
                        peer.address,
                        asn_str,
                        format_state(peer.state())
                    );
                }
            }
        }
    }

    Ok(())
}

fn format_state(state: BgpState) -> &'static str {
    match state {
        BgpState::Idle => "Idle",
        BgpState::Connect => "Connect",
        BgpState::Active => "Active",
        BgpState::OpenSent => "OpenSent",
        BgpState::OpenConfirm => "OpenConfirm",
        BgpState::Established => "Established",
    }
}

fn format_admin_state(state: AdminState) -> &'static str {
    match state {
        AdminState::Up => "Up",
        AdminState::Down => "Down",
        AdminState::PrefixLimitExceeded => "PrefixLimitExceeded",
    }
}
