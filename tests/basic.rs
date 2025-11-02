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
use bgpgg::config::Config;
use bgpgg::fsm::BgpState;
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
    panic!(
        "Timeout waiting for routes. Expected: {:?}, Got: {:?}",
        expected, actual
    );
}

/// Utility function to set up two BGP servers with peering established
/// Returns (server1, server2) where server2 has connected to server1
async fn setup_two_peered_servers(
    asn1: u16,
    asn2: u16,
    port1: u16,
    port2: u16,
) -> (Arc<BgpServer>, Arc<BgpServer>) {
    let server1 = Arc::new(BgpServer::new(Config::new(
        asn1,
        &format!("127.0.0.1:{}", port1),
        Ipv4Addr::new(1, 1, 1, 1),
    )));
    let server2 = Arc::new(BgpServer::new(Config::new(
        asn2,
        &format!("127.0.0.1:{}", port2),
        Ipv4Addr::new(2, 2, 2, 2),
    )));

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
        let established = {
            let peers1 = server1.peers.lock().await;
            let peers2 = server2.peers.lock().await;

            let both_have_peers = peers1.len() == 1 && peers2.len() == 1;
            let both_established = peers1.first().map(|p| p.state()) == Some(BgpState::Established)
                && peers2.first().map(|p| p.state()) == Some(BgpState::Established);

            both_have_peers && both_established
        };

        if established {
            return (server1, server2);
        }
        sleep(Duration::from_millis(100)).await;
    }

    // Timeout - collect state for error message
    let peers1 = server1.peers.lock().await;
    let peers2 = server2.peers.lock().await;
    panic!(
        "Timeout waiting for peers to establish. Server1: {} peers (state: {:?}), Server2: {} peers (state: {:?})",
        peers1.len(),
        peers1.first().map(|p| p.state()),
        peers2.len(),
        peers2.first().map(|p| p.state())
    );
}

#[tokio::test]
async fn test_two_bgp_servers_peering() {
    let (server1, server2) = setup_two_peered_servers(65100, 65200, 1790, 1791).await;

    // Verify that both servers have peers
    let peers1 = server1.peers.lock().await;
    let peers2 = server2.peers.lock().await;

    assert_eq!(peers1.len(), 1, "Server 1 should have 1 peer");
    assert_eq!(peers2.len(), 1, "Server 2 should have 1 peer");

    // Verify FSM state is Established
    assert_eq!(
        peers1[0].state(),
        BgpState::Established,
        "Server 1 peer should be in Established state"
    );
    assert_eq!(
        peers2[0].state(),
        BgpState::Established,
        "Server 2 peer should be in Established state"
    );
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
