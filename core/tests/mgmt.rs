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

//! Basic management operation tests

mod utils;
pub use utils::*;

use bgpgg::config::Config;
use bgpgg::grpc::proto::{AdminState, BgpState, Origin};
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_add_peer_failure() {
    let mut server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    // Initially no peers
    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 0);

    // Add peer via gRPC (succeeds, connection attempt is async)
    let result = server1
        .client
        .add_peer(format!("127.0.0.1:{}", server1.bgp_port + 1000), None)
        .await;
    assert!(result.is_ok());

    // RFC 4271 Event 18: Connection fails without DelayOpenTimer -> Idle
    poll_until(
        || async {
            let peers = server1.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Idle as i32
        },
        "Peer should reach Idle state after connection failure",
    )
    .await;

    // Verify peer stays in Idle (will retry via IdleHoldTimer)
    poll_while(
        || async {
            let peers = server1.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Idle as i32
        },
        std::time::Duration::from_secs(1),
        "Peer should stay in Idle state",
    )
    .await;
}

#[tokio::test]
async fn test_add_peer_success() {
    let mut server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;
    let server2 = start_test_server(Config::new(
        65002,
        "127.0.0.1:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
        true,
    ))
    .await;

    // Add peer via gRPC (should succeed - server2 is listening)
    server1.add_peer(&server2).await;

    // Wait for peering to establish
    // server1 connected to server2, so server2 is configured from server1's view
    poll_until(
        || async {
            verify_peers(&server1, vec![server2.to_peer(BgpState::Established, true)]).await
                && verify_peers(
                    &server2,
                    vec![server1.to_peer(BgpState::Established, false)],
                )
                .await
        },
        "Timeout waiting for peers to establish",
    )
    .await;
}

#[tokio::test]
async fn test_remove_peer_not_found() {
    let mut server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    // Remove non-existent peer
    let result = server1.client.remove_peer("192.168.1.1".to_string()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_remove_peer_success() {
    let (mut server1, server2) = setup_two_peered_servers(None).await;

    // Verify peer exists
    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 1);

    // Remove peer
    server1.remove_peer(&server2).await;

    // Verify peer is gone
    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 0);
}

#[tokio::test]
async fn test_get_peers_empty() {
    let server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 0);
}

#[tokio::test]
async fn test_get_peers_with_peers() {
    let (server1, server2) = setup_two_peered_servers(None).await;

    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address, server2.address);
    assert_eq!(peers[0].asn, server2.asn as u32);
    assert_eq!(peers[0].state, BgpState::Established as i32);
}

#[tokio::test]
async fn test_get_peer_not_found() {
    let server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    let result = server1.client.get_peer("192.168.1.1".to_string()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_peer_success() {
    let (server1, server2) = setup_two_peered_servers(None).await;

    let (peer_opt, stats_opt) = server1
        .client
        .get_peer(server2.address.clone())
        .await
        .unwrap();

    let peer = peer_opt.unwrap();
    assert_eq!(peer.address, server2.address);
    assert_eq!(peer.asn, server2.asn as u32);
    assert_eq!(peer.state, BgpState::Established as i32);

    // Verify statistics exist
    let stats = stats_opt.unwrap();
    assert!(stats.open_sent > 0);
    assert!(stats.open_received > 0);
}

#[tokio::test]
async fn test_get_routes_empty() {
    let server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    let routes = server1.client.get_routes().await.unwrap();
    assert_eq!(routes.len(), 0);
}

#[tokio::test]
async fn test_announce_withdraw_route() {
    let mut server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    // Announce route first
    server1
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            None,
            false,
            vec![],
        )
        .await
        .unwrap();

    // Verify route exists
    let routes = server1.client.get_routes().await.unwrap();
    assert_eq!(routes.len(), 1);

    // Withdraw route
    let result = server1.client.remove_route("10.0.0.0/24".to_string()).await;
    assert!(result.is_ok());

    // Route should be gone
    let routes = server1.client.get_routes().await.unwrap();
    assert_eq!(routes.len(), 0);
}

#[tokio::test]
async fn test_withdraw_nonexistent_route() {
    let mut server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    // Withdraw route that was never announced (should succeed - idempotent)
    let result = server1.client.remove_route("10.0.0.0/24".to_string()).await;
    assert!(result.is_ok());

    // Routes should still be empty
    let routes = server1.client.get_routes().await.unwrap();
    assert_eq!(routes.len(), 0);
}

#[tokio::test]
async fn test_disable_enable_peer() {
    let (mut server1, server2) = setup_two_peered_servers(None).await;

    // Disable peer
    server1
        .client
        .disable_peer(server2.address.clone())
        .await
        .unwrap();

    // Peer should go to Idle with admin_state Down
    poll_until(
        || async {
            let peers = server1.client.get_peers().await.unwrap();
            peers.len() == 1
                && peers[0].state == BgpState::Idle as i32
                && peers[0].admin_state == AdminState::Down as i32
        },
        "Peer should be Idle with admin_state Down",
    )
    .await;

    // Enable peer
    server1
        .client
        .enable_peer(server2.address.clone())
        .await
        .unwrap();

    // Peer should reconnect and reach Established with admin_state Up
    poll_until(
        || async {
            let peers = server1.client.get_peers().await.unwrap();
            peers.len() == 1
                && peers[0].state == BgpState::Established as i32
                && peers[0].admin_state == AdminState::Up as i32
        },
        "Peer should be Established with admin_state Up",
    )
    .await;
}

#[tokio::test]
async fn test_add_bmp_server() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    let servers = server.client.get_bmp_servers().await.unwrap();
    assert_eq!(servers.len(), 0);

    let result = server
        .client
        .add_bmp_server("127.0.0.1:11019".to_string())
        .await;
    assert!(result.is_ok());

    let result = server
        .client
        .add_bmp_server("127.0.0.1:11020".to_string())
        .await;
    assert!(result.is_ok());

    let servers = server.client.get_bmp_servers().await.unwrap();
    assert_eq!(servers.len(), 2);
    assert!(servers.contains(&"127.0.0.1:11019".to_string()));
    assert!(servers.contains(&"127.0.0.1:11020".to_string()));
}

#[tokio::test]
async fn test_remove_bmp_server() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    server
        .client
        .add_bmp_server("127.0.0.1:11019".to_string())
        .await
        .unwrap();

    let servers = server.client.get_bmp_servers().await.unwrap();
    assert_eq!(servers.len(), 1);

    let result = server
        .client
        .remove_bmp_server("127.0.0.1:11019".to_string())
        .await;
    assert!(result.is_ok());

    let servers = server.client.get_bmp_servers().await.unwrap();
    assert_eq!(servers.len(), 0);
}

#[tokio::test]
async fn test_get_bmp_servers_empty() {
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    let servers = server.client.get_bmp_servers().await.unwrap();
    assert_eq!(servers.len(), 0);
}
