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

use bgpgg::grpc::proto::{Origin, Path, Route};
use common::{
    poll_route_propagation, poll_route_withdrawal, setup_four_meshed_servers,
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
    poll_route_propagation(&[(
        &server1,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![Path {
                origin: Origin::Igp.into(),
                as_path: vec![65002],
                next_hop: "192.168.1.1".to_string(),
                peer_address: peer_addr.clone(),
                local_pref: Some(100),
                med: None,
            }],
        }],
    )])
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
async fn test_announce_withdraw_three_node_mesh() {
    let (mut server1, server2, server3) = setup_three_meshed_servers(None).await;

    // Server1 announces a route
    server1
        .client
        .announce_route("10.1.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route propagation with expected AS paths
    // After best path selection, only the best path (shortest AS_PATH) should remain
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
    ])
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
async fn test_announce_withdraw_four_node_mesh() {
    let (mut server1, server2, server3, server4) = setup_four_meshed_servers(None).await;

    // Server1 announces a route
    server1
        .client
        .announce_route("10.1.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route propagation with expected AS paths
    // After best path selection, only the best path (shortest AS_PATH) should remain
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
        (
            &server4,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
    ])
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

