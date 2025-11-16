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
pub use common::*;

use bgpgg::grpc::proto::{BgpState, Origin, Route};
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_announce_withdraw() {
    let (server1, mut server2) = setup_two_peered_servers(None).await;

    // Server2 announces a route to Server1 via gRPC
    server2
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            0,
            vec![],
        )
        .await
        .expect("Failed to announce route");

    // Get the actual peer address (with OS-allocated port)
    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    // Poll for route to appear in Server1's RIB
    // eBGP: NEXT_HOP rewritten to router ID
    poll_route_propagation(&[(
        &server1,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65002])],
                "2.2.2.2", // eBGP: NEXT_HOP rewritten to server2's router ID
                peer_addr.clone(),
                Origin::Igp,
            )],
        }],
    )])
    .await;

    // Server2 withdraws the route
    server2
        .client
        .remove_route("10.0.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route");

    // Poll for withdrawal and verify peers are still established
    poll_route_withdrawal(&[&server1]).await;
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established)],).await);
    assert!(verify_peers(&server2, vec![server1.to_peer(BgpState::Established)],).await);
}

#[tokio::test]
async fn test_announce_withdraw_mesh() {
    let (mut server1, server2, server3) = setup_three_meshed_servers(None).await;

    // Server1 announces a route
    server1
        .client
        .add_route(
            "10.1.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            0,
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route propagation with expected AS paths
    // eBGP: NEXT_HOP rewritten to router ID
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])],
                    "1.1.1.1", // eBGP: NEXT_HOP rewritten to server1's router ID
                    server1.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])],
                    "1.1.1.1", // eBGP: NEXT_HOP rewritten to server1's router ID
                    server1.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
    ])
    .await;

    // Server1 withdraws the route
    server1
        .client
        .remove_route("10.1.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route from server 1");

    // Poll for withdrawal and verify peers are still established
    poll_route_withdrawal(&[&server2, &server3]).await;
    assert!(
        verify_peers(
            &server1,
            vec![
                server2.to_peer(BgpState::Established),
                server3.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![
                server1.to_peer(BgpState::Established),
                server3.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server3,
            vec![
                server1.to_peer(BgpState::Established),
                server2.to_peer(BgpState::Established),
            ],
        )
        .await
    );
}

#[tokio::test]
async fn test_announce_withdraw_four_node_mesh() {
    let (mut server1, server2, server3, server4) = setup_four_meshed_servers(None).await;

    // Server1 announces a route
    server1
        .client
        .add_route(
            "10.1.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            0,
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route propagation with expected AS paths
    // eBGP: NEXT_HOP rewritten to router IDs
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])],
                    "1.1.1.1", // eBGP: NEXT_HOP rewritten to server1's router ID
                    server1.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])],
                    "1.1.1.1", // eBGP: NEXT_HOP rewritten to server1's router ID
                    server1.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
        (
            &server4,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])],
                    "1.1.1.1", // eBGP: NEXT_HOP rewritten to server1's router ID
                    server1.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
    ])
    .await;

    // Server1 withdraws the route
    server1
        .client
        .remove_route("10.1.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route from server 1");

    // Poll for withdrawal with extended timeout (40s) for full mesh path hunting
    poll_until_with_timeout(
        || async {
            for server in [&server2, &server3, &server4] {
                let Ok(routes) = server.client.get_routes().await else {
                    return false;
                };
                if !routes.is_empty() {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for route withdrawal",
        400,
    )
    .await;
    assert!(
        verify_peers(
            &server1,
            vec![
                server2.to_peer(BgpState::Established),
                server3.to_peer(BgpState::Established),
                server4.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![
                server1.to_peer(BgpState::Established),
                server3.to_peer(BgpState::Established),
                server4.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server3,
            vec![
                server1.to_peer(BgpState::Established),
                server2.to_peer(BgpState::Established),
                server4.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server4,
            vec![
                server1.to_peer(BgpState::Established),
                server2.to_peer(BgpState::Established),
                server3.to_peer(BgpState::Established),
            ],
        )
        .await
    );
}

#[tokio::test]
async fn test_ibgp_split_horizon() {
    // Linear topology: A--B--C (all same ASN for iBGP)
    // Tests that routes learned via iBGP are not advertised to other iBGP peers
    let [mut server1, server2, server3] = chain_servers([
        start_test_server(
            65001, // Same ASN
            Ipv4Addr::new(1, 1, 1, 1),
            None,
            "127.0.0.1",
        )
        .await,
        start_test_server(
            65001, // Same ASN (iBGP)
            Ipv4Addr::new(2, 2, 2, 2),
            None,
            "127.0.0.2",
        )
        .await,
        start_test_server(
            65001, // Same ASN (iBGP)
            Ipv4Addr::new(3, 3, 3, 3),
            None,
            "127.0.0.3",
        )
        .await,
    ])
    .await;

    // Server1 announces a route
    server1
        .client
        .add_route(
            "10.1.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            0,
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // Server2 should receive the route from Server1
    // Server3 should NOT receive the route (iBGP split horizon)
    // iBGP: NEXT_HOP preserved (not rewritten)
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![], // Empty AS_PATH for locally originated route in iBGP
                    "192.168.1.1", // iBGP: NEXT_HOP preserved
                    server1.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
        (&server3, vec![]), // Server3 should have no routes due to split horizon
    ])
    .await;

    // Verify all peers are still established
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established)],).await);
    assert!(
        verify_peers(
            &server2,
            vec![
                server1.to_peer(BgpState::Established),
                server3.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(verify_peers(&server3, vec![server2.to_peer(BgpState::Established)],).await);
}
