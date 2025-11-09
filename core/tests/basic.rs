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

    // Poll for route to appear in Server1's RIB
    poll_route_propagation(&[(&client1, vec![vec![65002_u32]])], "10.0.0.0/24", 1).await;

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
    poll_route_propagation(
        &[
            (&client2, vec![vec![65001_u32], vec![65003, 65001]]),
            (&client3, vec![vec![65001_u32], vec![65002, 65001]]),
        ],
        "10.1.0.0/24",
        2,
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
    poll_route_propagation(
        &[
            (
                &client2,
                vec![vec![65001_u32], vec![65003, 65001], vec![65004, 65001]],
            ),
            (
                &client3,
                vec![vec![65001_u32], vec![65002, 65001], vec![65004, 65001]],
            ),
            (
                &client4,
                vec![vec![65001_u32], vec![65002, 65001], vec![65003, 65001]],
            ),
        ],
        "10.1.0.0/24",
        3,
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
