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

mod common;

use bgpgg::grpc::proto::{BgpState, Origin, Path};
use common::{
    peer_in_state, poll_route_propagation, poll_route_withdrawal, setup_four_meshed_servers,
    setup_three_meshed_servers, setup_two_peered_servers, verify_peers_established,
};

#[tokio::test]
async fn test_announce_withdraw() {
    let (server1, mut server2) = setup_two_peered_servers(None).await;

    // Server2 announces a route to Server1 via gRPC
    server2
        .client
        .announce_route("10.0.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route");

    // Get the actual peer address (with OS-allocated port)
    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    // Poll for route to appear in Server1's RIB
    poll_route_propagation(
        &[(
            &server1.client,
            vec![Path {
                origin: Origin::Igp.into(),
                as_path: vec![65002],
                next_hop: "192.168.1.1".to_string(),
                peer_address: peer_addr.clone(),
                local_pref: Some(100),
                med: None,
            }],
        )],
        "10.0.0.0/24",
    )
    .await;

    // Server2 withdraws the route
    server2
        .client
        .withdraw_route("10.0.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route");

    // Poll for withdrawal and verify peers
    poll_route_withdrawal(&[&server1]).await;
    verify_peers_established(&[&server1, &server2], 1).await;
}

#[tokio::test]
async fn test_announce_withdraw_mesh() {
    let (mut server1, server2, server3) = setup_three_meshed_servers(None).await;

    // Server1 announces a route
    server1
        .client
        .announce_route("10.1.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route propagation with expected AS paths
    // After best path selection, only the best path (shortest AS_PATH) should remain

    // Get actual peer addresses
    let peers2 = server2.client.get_peers().await.unwrap();
    let peer2_from_server1 = peers2.iter().find(|p| p.asn == 65001).unwrap();

    let peers3 = server3.client.get_peers().await.unwrap();
    let peer3_from_server1 = peers3.iter().find(|p| p.asn == 65001).unwrap();

    poll_route_propagation(
        &[
            (
                &server2.client,
                vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: peer2_from_server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            ),
            (
                &server3.client,
                vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: peer3_from_server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            ),
        ],
        "10.1.0.0/24",
    )
    .await;

    // Server1 withdraws the route
    server1
        .client
        .withdraw_route("10.1.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route from server 1");

    // Poll for withdrawal and verify peers
    poll_route_withdrawal(&[&server2, &server3]).await;
    verify_peers_established(&[&server1, &server2, &server3], 2).await;
}

#[tokio::test]
async fn test_announce_withdraw_mesh_2() {
    let (mut server1, server2, server3, server4) = setup_four_meshed_servers(None).await;

    // Server1 announces a route
    server1
        .client
        .announce_route("10.1.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route propagation with expected AS paths
    // After best path selection, only the best path (shortest AS_PATH) should remain

    // Get actual peer addresses
    let peers2 = server2.client.get_peers().await.unwrap();
    let peer2_from_server1 = peers2.iter().find(|p| p.asn == 65001).unwrap();

    let peers3 = server3.client.get_peers().await.unwrap();
    let peer3_from_server1 = peers3.iter().find(|p| p.asn == 65001).unwrap();

    let peers4 = server4.client.get_peers().await.unwrap();
    let peer4_from_server1 = peers4.iter().find(|p| p.asn == 65001).unwrap();

    poll_route_propagation(
        &[
            (
                &server2.client,
                vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: peer2_from_server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            ),
            (
                &server3.client,
                vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: peer3_from_server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            ),
            (
                &server4.client,
                vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: peer4_from_server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            ),
        ],
        "10.1.0.0/24",
    )
    .await;

    // Server1 withdraws the route
    server1
        .client
        .withdraw_route("10.1.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route from server 1");

    // Poll for withdrawal and verify peers
    poll_route_withdrawal(&[&server2, &server3, &server4]).await;
    verify_peers_established(&[&server1, &server2, &server3, &server4], 3).await;
}

#[tokio::test]
async fn test_peer_down() {
    let (server1, mut server2) = setup_two_peered_servers(Some(3)).await;

    // Server2 announces a route to Server1 via gRPC
    server2
        .client
        .announce_route("10.0.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route");

    // Get the actual peer address (with OS-allocated port)
    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    // Poll for route to appear in Server1's RIB
    poll_route_propagation(
        &[(
            &server1.client,
            vec![Path {
                origin: Origin::Igp.into(),
                as_path: vec![65002],
                next_hop: "192.168.1.1".to_string(),
                peer_address: peer_addr.clone(),
                local_pref: Some(100),
                med: None,
            }],
        )],
        "10.0.0.0/24",
    )
    .await;

    // Kill Server2 to simulate peer going down (drops runtime, killing ALL tasks)
    server2.kill();

    // Give some time for Server1 to detect the disconnection
    // With a 3-second hold time, the peer should be detected as down
    // when the next keepalive fails (keepalive is sent every hold_time/3 = 1 second)
    tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;

    // Poll for route withdrawal - route should be withdrawn when peer goes down
    poll_route_withdrawal(&[&server1]).await;

    // Verify Server1 has no peers in Established state anymore
    let peers = server1.client.get_peers().await.unwrap();
    assert!(
        peers.is_empty()
            || !peers
                .iter()
                .any(|p| peer_in_state(p, BgpState::Established)),
        "Server1 should have no established peers after Server2 is killed"
    );
}

#[tokio::test]
async fn test_peer_up() {
    let hold_timer_secs = 3;
    let (server1, server2) = setup_two_peered_servers(Some(hold_timer_secs)).await;

    // Wait for 3x hold timer to ensure multiple keepalives are exchanged and the connection stays up
    tokio::time::sleep(tokio::time::Duration::from_secs(hold_timer_secs as u64 * 3)).await;

    // Verify both peers are still in Established state
    verify_peers_established(&[&server1, &server2], 1).await;
}
