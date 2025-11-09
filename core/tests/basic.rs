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

use bgpgg::grpc::proto::{Origin, Path};
use common::{
    poll_route_propagation, poll_route_withdrawal, setup_four_meshed_servers,
    setup_three_meshed_servers, setup_two_peered_servers, verify_peers_established,
};

#[tokio::test]
async fn test_announce_withdraw() {
    let (client1, mut client2) = setup_two_peered_servers().await;

    // Server2 announces a route to Server1 via gRPC
    client2
        .announce_route("10.0.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route");

    // Get the actual peer address (with OS-allocated port)
    let peers = client1.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    // Poll for route to appear in Server1's RIB
    poll_route_propagation(
        &[(
            &client1,
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
    client2
        .withdraw_route("10.0.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route");

    // Poll for withdrawal and verify peers
    poll_route_withdrawal(&[&client1]).await;
    verify_peers_established(&[&client1, &client2], 1).await;
}

#[tokio::test]
async fn test_announce_withdraw_mesh() {
    let (mut client1, client2, client3) = setup_three_meshed_servers().await;

    // Server1 announces a route
    client1
        .announce_route("10.1.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route propagation with expected AS paths
    // After best path selection, only the best path (shortest AS_PATH) should remain

    // Get actual peer addresses
    let peers2 = client2.get_peers().await.unwrap();
    let peer2_from_server1 = peers2.iter().find(|p| p.asn == 65001).unwrap();

    let peers3 = client3.get_peers().await.unwrap();
    let peer3_from_server1 = peers3.iter().find(|p| p.asn == 65001).unwrap();

    poll_route_propagation(
        &[
            (
                &client2,
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
                &client3,
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
    client1
        .withdraw_route("10.1.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route from server 1");

    // Poll for withdrawal and verify peers
    poll_route_withdrawal(&[&client2, &client3]).await;
    verify_peers_established(&[&client1, &client2, &client3], 2).await;
}

#[tokio::test]
async fn test_announce_withdraw_mesh_2() {
    let (mut client1, client2, client3, client4) = setup_four_meshed_servers().await;

    // Server1 announces a route
    client1
        .announce_route("10.1.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route propagation with expected AS paths
    // After best path selection, only the best path (shortest AS_PATH) should remain

    // Get actual peer addresses
    let peers2 = client2.get_peers().await.unwrap();
    let peer2_from_server1 = peers2.iter().find(|p| p.asn == 65001).unwrap();

    let peers3 = client3.get_peers().await.unwrap();
    let peer3_from_server1 = peers3.iter().find(|p| p.asn == 65001).unwrap();

    let peers4 = client4.get_peers().await.unwrap();
    let peer4_from_server1 = peers4.iter().find(|p| p.asn == 65001).unwrap();

    poll_route_propagation(
        &[
            (
                &client2,
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
                &client3,
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
                &client4,
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
    client1
        .withdraw_route("10.1.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route from server 1");

    // Poll for withdrawal and verify peers
    poll_route_withdrawal(&[&client2, &client3, &client4]).await;
    verify_peers_established(&[&client1, &client2, &client3, &client4], 3).await;
}
