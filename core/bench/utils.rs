// Copyright 2026 bgpgg Authors
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

use crate::server::{Server, ServerConfig};
use bgpgg::config::Config;
use bgpgg::grpc::proto::Origin;
use std::fs;
use std::net::Ipv4Addr;

#[path = "../tests/utils/common.rs"]
#[allow(dead_code)]
mod common;

pub use common::{poll_until, poll_until_with_timeout, start_test_server, TestServer};

// Memory utilities

#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub rss_kb: usize,
    #[allow(dead_code)]
    pub vms_kb: usize,
}

pub fn get_process_memory() -> MemoryStats {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();

    let mut rss_kb = 0;
    let mut vms_kb = 0;

    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            rss_kb = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        } else if line.starts_with("VmSize:") {
            vms_kb = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }

    MemoryStats { rss_kb, vms_kb }
}

// Route generation utilities

pub fn generate_routes_for_spoke(
    spoke_id: u32,
    count: usize,
) -> Vec<(
    String,
    String,
    Origin,
    Vec<bgpgg::grpc::proto::AsPathSegment>,
    Option<u32>,
    Option<u32>,
    bool,
    Vec<u32>,
)> {
    let mut routes = Vec::with_capacity(count);

    let base_offset = spoke_id * count as u32;

    for i in 0..count {
        let prefix_num = base_offset + i as u32;
        let octet1 = 10 + (prefix_num / 65536) as u8;
        let octet2 = ((prefix_num / 256) % 256) as u8;
        let octet3 = (prefix_num % 256) as u8;

        let prefix = format!("{}.{}.{}.0/24", octet1, octet2, octet3);

        // Vary next_hop every 50 routes - keeps batches smaller
        let next_hop_variant = (i / 50) as u8;
        let next_hop = format!("192.168.{}.{}", spoke_id % 256, next_hop_variant);

        // Vary communities every 25 routes - combined with next_hop gives ~25 routes per batch
        let community = if (i / 25) % 2 == 0 {
            vec![65000u32 << 16 | 100]
        } else {
            vec![65000u32 << 16 | 200]
        };

        // (prefix, next_hop, origin, as_path, local_pref, med, atomic_aggregate, communities)
        routes.push((
            prefix,
            next_hop,
            Origin::Igp,
            vec![],
            None,
            None,
            false,
            community,
        ));
    }

    routes
}

// Topology utilities

pub async fn setup_topology(
    num_senders: usize,
    num_receivers: usize,
    server_config: ServerConfig,
) -> Result<(Server, Vec<TestServer>, Vec<TestServer>), Box<dyn std::error::Error>> {
    println!("Creating server...");
    let server_asn = 65000;
    let server_router_id = Ipv4Addr::new(0, 0, 0, 1);
    let server_bind_addr = "127.0.1.1:0".to_string();
    let server_grpc_port = 50051;

    let mut server = Server::start(
        server_asn,
        server_router_id,
        server_bind_addr.clone(),
        server_grpc_port,
        server_config,
    )
    .await?;

    println!("Creating {} senders...", num_senders);
    let mut senders = Vec::with_capacity(num_senders);
    for i in 0..num_senders {
        let asn = (i + 1) as u16;
        // Start from 127.0.2.1 to avoid conflicts with hub at 127.0.1.1
        let offset = i + 1;
        let octet = (offset % 254) as u8 + 1; // 1-254
        let router_id = Ipv4Addr::new(0, 0, 2, octet);
        let bind_addr = format!("127.0.2.{}:0", octet);

        let mut config = Config::new(asn, &bind_addr, router_id, 90, true);
        config.log_level = "error".to_string(); // Suppress logs during load test
        let sender = start_test_server(config).await;

        senders.push(sender);

        if (i + 1) % 100 == 0 {
            println!("  Created {} senders", i + 1);
        }
    }

    println!("Creating {} receivers...", num_receivers);
    let mut receivers = Vec::with_capacity(num_receivers);
    for i in 0..num_receivers {
        let asn = (70001 + i) as u16;
        let octet = (i + 4) as u8;
        let router_id = Ipv4Addr::new(0, 4, 0, octet);
        let bind_addr = format!("127.0.4.{}:0", octet);

        let mut config = Config::new(asn, &bind_addr, router_id, 90, true);
        config.log_level = "error".to_string(); // Suppress logs during load test
        let receiver = start_test_server(config).await;

        receivers.push(receiver);
    }

    println!(
        "Peering server with {} senders and {} receivers...",
        num_senders, num_receivers
    );
    for sender in &senders {
        let peer_addr = format!("{}:{}", sender.address, sender.bgp_port);
        server.add_peer(peer_addr, None).await?;
    }
    for receiver in &receivers {
        let peer_addr = format!("{}:{}", receiver.address, receiver.bgp_port);
        server.add_peer(peer_addr, None).await?;
    }

    // Wait for BGP sessions to establish
    println!("Waiting for BGP sessions to establish...");
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    println!("Topology created!");
    Ok((server, senders, receivers))
}
