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

use bgpgg::bgp::msg_update::Origin;
use bgpgg::bgp::utils::{IpNetwork, Ipv4Net};
use bgpgg::rib::{Path, Route};
use bgpgg::server::BgpServer;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

/// Poll until routes match expected set (ignoring order)
async fn poll_for_routes(server: &BgpServer, expected: &HashSet<Route>) {
    for _ in 0..100 {
        let routes = server.rib.query_loc_rib().await.unwrap();
        let actual: HashSet<Route> = routes.into_iter().collect();
        if actual == *expected {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }

    let routes = server.rib.query_loc_rib().await.unwrap();
    let actual: HashSet<Route> = routes.into_iter().collect();
    panic!("Timeout waiting for routes. Expected: {:?}, Got: {:?}", expected, actual);
}

/// Utility function to set up two BGP servers with peering established
/// Returns (server1, server2) where server2 has connected to server1
async fn setup_two_peered_servers(
    asn1: u16,
    asn2: u16,
    port1: u16,
    port2: u16,
) -> (Arc<BgpServer>, Arc<BgpServer>) {
    let server1 = Arc::new(BgpServer::new(asn1));
    let server2 = Arc::new(BgpServer::new(asn2));

    tokio::spawn({
        let server = Arc::clone(&server1);
        async move { server.run_on(&format!("127.0.0.1:{}", port1)).await }
    });
    tokio::spawn({
        let server = Arc::clone(&server2);
        async move { server.run_on(&format!("127.0.0.1:{}", port2)).await }
    });

    // Server2 connects to Server1
    server2.add_peer(&format!("127.0.0.1:{}", port1)).await;

    // Wait for peering to establish
    for _ in 0..100 {
        let peers1 = server1.peers.lock().await.len();
        let peers2 = server2.peers.lock().await.len();
        if peers1 == 1 && peers2 == 1 {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    (server1, server2)
}

#[tokio::test]
async fn test_two_bgp_servers_peering() {
    let (server1, server2) = setup_two_peered_servers(65100, 65200, 1790, 1791).await;

    // Verify that both servers have peers
    assert_eq!(server1.peers.lock().await.len(), 1, "Server 1 should have 1 peer");
    assert_eq!(server2.peers.lock().await.len(), 1, "Server 2 should have 1 peer");
}

#[tokio::test]
async fn test_announce_one_route() {
    let (server1, server2) = setup_two_peered_servers(65100, 65001, 1792, 1793).await;

    // Server2 announces a route to Server1
    let prefix = IpNetwork::V4(Ipv4Net {
        address: Ipv4Addr::new(10, 0, 0, 0),
        prefix_length: 24,
    });
    let next_hop = Ipv4Addr::new(192, 168, 1, 1);

    server2
        .announce_route(prefix, next_hop, Origin::IGP)
        .await
        .expect("Failed to announce route");

    // Get the peer address (server2's connection to server1)
    let peer_addr = server1.peers.lock().await[0].addr;

    // Build expected routes set
    let expected: HashSet<Route> = [Route {
        prefix,
        paths: vec![Path {
            origin: Origin::IGP,
            as_path: vec![65001],
            next_hop,
            from_peer: peer_addr,
            local_pref: Some(100),
            med: None,
        }],
    }]
    .into_iter()
    .collect();

    // Poll and verify server1 received the route
    poll_for_routes(&server1, &expected).await;
}
