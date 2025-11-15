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

mod common;
pub use common::*;

use bgpgg::grpc::proto::BgpState;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_add_peer_failure() {
    let mut server1 = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), None, "127.0.0.1").await;

    // Initially no peers
    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 0);

    // Add peer via gRPC (should fail - no peer listening at that address)
    let result = server1
        .client
        .add_peer(format!("127.0.0.1:{}", server1.bgp_port + 1000))
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_add_peer_success() {
    let mut server1 = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), None, "127.0.0.1").await;
    let server2 = start_test_server(65002, Ipv4Addr::new(2, 2, 2, 2), None, "127.0.0.1").await;

    // Add peer via gRPC (should succeed - server2 is listening)
    let result = server1
        .client
        .add_peer(format!("127.0.0.1:{}", server2.bgp_port))
        .await;
    assert!(result.is_ok());

    // Wait for peering to establish
    poll_until(
        || async {
            verify_peers(&server1, vec![server2.to_peer(BgpState::Established)]).await
                && verify_peers(&server2, vec![server1.to_peer(BgpState::Established)]).await
        },
        "Timeout waiting for peers to establish",
    )
    .await;
}

#[tokio::test]
async fn test_remove_peer_not_found() {
    let mut server1 = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), None, "127.0.0.1").await;

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
    let result = server1.client.remove_peer(server2.address.clone()).await;
    assert!(result.is_ok());

    // Verify peer is gone
    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 0);
}

#[tokio::test]
async fn test_get_peers_empty() {
    let server1 = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), None, "127.0.0.1").await;

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
    let server1 = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), None, "127.0.0.1").await;

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
    let server1 = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), None, "127.0.0.1").await;

    let routes = server1.client.get_routes().await.unwrap();
    assert_eq!(routes.len(), 0);
}

#[tokio::test]
async fn test_announce_withdraw_route() {
    let mut server1 = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), None, "127.0.0.1").await;

    // Announce route first
    server1
        .client
        .announce_route("10.0.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .unwrap();

    // Verify route exists
    let routes = server1.client.get_routes().await.unwrap();
    assert_eq!(routes.len(), 1);

    // Withdraw route
    let result = server1
        .client
        .withdraw_route("10.0.0.0/24".to_string())
        .await;
    assert!(result.is_ok());

    // Route should be gone
    let routes = server1.client.get_routes().await.unwrap();
    assert_eq!(routes.len(), 0);
}

#[tokio::test]
async fn test_withdraw_nonexistent_route() {
    let mut server1 = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), None, "127.0.0.1").await;

    // Withdraw route that was never announced (should succeed - idempotent)
    let result = server1
        .client
        .withdraw_route("10.0.0.0/24".to_string())
        .await;
    assert!(result.is_ok());

    // Routes should still be empty
    let routes = server1.client.get_routes().await.unwrap();
    assert_eq!(routes.len(), 0);
}
