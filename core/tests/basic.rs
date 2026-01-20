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

mod utils;
pub use utils::*;

use bgpgg::config::Config;
use bgpgg::grpc::proto::{BgpState, Origin, Route};
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_announce_withdraw() {
    let (server1, mut server2) = setup_two_peered_servers(None).await;

    // Server2 announces a route to Server1
    let server2_addr = server2.address.to_string();
    announce_and_verify_route(
        &mut server2,
        &[&server1],
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
        PathParams {
            as_path: vec![as_sequence(vec![65002])],
            next_hop: server2_addr.clone(),
            peer_address: server2_addr,
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            ..Default::default()
        },
    )
    .await;

    // Server2 withdraws the route
    server2
        .client
        .remove_route("10.0.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route");

    // Poll for withdrawal and verify peers are still established
    poll_route_withdrawal(&[&server1]).await;
    // chain_servers: server1 connected to server2, so server2 is configured from server1's view
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established, true)],).await);
    assert!(
        verify_peers(
            &server2,
            vec![server1.to_peer(BgpState::Established, false)],
        )
        .await
    );
}

#[tokio::test]
async fn test_announce_withdraw_mesh() {
    let (mut server1, server2, server3) = setup_three_meshed_servers(None).await;

    // Server1 announces a route to both server2 and server3
    let server1_addr = server1.address.to_string();
    announce_and_verify_route(
        &mut server1,
        &[&server2, &server3],
        RouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
        PathParams {
            as_path: vec![as_sequence(vec![65001])],
            next_hop: server1_addr.clone(),
            peer_address: server1_addr,
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            ..Default::default()
        },
    )
    .await;

    // Server1 withdraws the route
    server1
        .client
        .remove_route("10.1.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route from server 1");

    // Poll for withdrawal and verify peers are still established
    // mesh_servers: lower index connects to higher index
    // From connector's view: configured=true; from acceptor's view: configured=false
    poll_route_withdrawal(&[&server2, &server3]).await;
    assert!(
        verify_peers(
            &server1,
            vec![
                server2.to_peer(BgpState::Established, true),
                server3.to_peer(BgpState::Established, true),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![
                server1.to_peer(BgpState::Established, false),
                server3.to_peer(BgpState::Established, true),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server3,
            vec![
                server1.to_peer(BgpState::Established, false),
                server2.to_peer(BgpState::Established, false),
            ],
        )
        .await
    );
}

#[tokio::test]
async fn test_announce_withdraw_four_node_mesh() {
    let (mut server1, server2, server3, server4) = setup_four_meshed_servers(None).await;

    // Server1 announces a route
    announce_route(
        &mut server1,
        RouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Expected route for convergence check
    let expected_route = vec![Route {
        prefix: "10.1.0.0/24".to_string(),
        paths: vec![build_path(PathParams {
            as_path: vec![as_sequence(vec![65001])],
            next_hop: server1.address.to_string(),
            peer_address: server1.address.to_string(),
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            ..Default::default()
        })],
    }];
    let recv_1 = ExpectedStats {
        min_update_received: Some(1),
        ..Default::default()
    };
    let sent_1 = ExpectedStats {
        min_update_sent: Some(1),
        ..Default::default()
    };
    wait_convergence(
        &[
            (&server2, expected_route.clone()),
            (&server3, expected_route.clone()),
            (&server4, expected_route.clone()),
        ],
        &[
            // Each server receives UPDATE from all peers
            (&server2, &server1, recv_1),
            (&server2, &server3, recv_1),
            (&server2, &server4, recv_1),
            (&server3, &server1, recv_1),
            (&server3, &server2, recv_1),
            (&server3, &server4, recv_1),
            (&server4, &server1, recv_1),
            (&server4, &server2, recv_1),
            (&server4, &server3, recv_1),
            // Each server sends UPDATE to non-originating peers
            (&server2, &server3, sent_1),
            (&server2, &server4, sent_1),
            (&server3, &server2, sent_1),
            (&server3, &server4, sent_1),
            (&server4, &server2, sent_1),
            (&server4, &server3, sent_1),
        ],
    )
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
    // mesh_servers: lower index connects to higher index
    // From connector's view: configured=true; from acceptor's view: configured=false
    assert!(
        verify_peers(
            &server1,
            vec![
                server2.to_peer(BgpState::Established, true),
                server3.to_peer(BgpState::Established, true),
                server4.to_peer(BgpState::Established, true),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![
                server1.to_peer(BgpState::Established, false),
                server3.to_peer(BgpState::Established, true),
                server4.to_peer(BgpState::Established, true),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server3,
            vec![
                server1.to_peer(BgpState::Established, false),
                server2.to_peer(BgpState::Established, false),
                server4.to_peer(BgpState::Established, true),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server4,
            vec![
                server1.to_peer(BgpState::Established, false),
                server2.to_peer(BgpState::Established, false),
                server3.to_peer(BgpState::Established, false),
            ],
        )
        .await
    );
}

#[tokio::test]
async fn test_ibgp_split_horizon() {
    // Linear topology: A--B--C (all same ASN for iBGP)
    // Tests that routes learned via iBGP are not advertised to other iBGP peers
    // iBGP: all same ASN
    let [mut server1, server2, server3] = chain_servers([
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65001,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65001,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            90,
            true,
        ))
        .await,
    ])
    .await;

    // Server1 announces a route
    announce_route(
        &mut server1,
        RouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Server2 should receive the route from Server1
    // Server3 should NOT receive the route (iBGP split horizon)
    // iBGP: NEXT_HOP preserved (not rewritten)
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(PathParams {
                    as_path: vec![], // Empty AS_PATH for locally originated route in iBGP
                    next_hop: "192.168.1.1".to_string(), // iBGP: NEXT_HOP preserved
                    peer_address: server1.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                })],
            }],
        ),
        (&server3, vec![]), // Server3 should have no routes due to split horizon
    ])
    .await;

    // Verify all peers are still established
    // chain_servers: s1 -> s2 -> s3
    // From connector's view: configured=true; from acceptor's view: configured=false
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established, true)],).await);
    assert!(
        verify_peers(
            &server2,
            vec![
                server1.to_peer(BgpState::Established, false),
                server3.to_peer(BgpState::Established, true),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server3,
            vec![server2.to_peer(BgpState::Established, false)],
        )
        .await
    );
}

#[tokio::test]
async fn test_as_loop_prevention() {
    // Topology: AS1_A -> AS2 -> AS1_B (different speakers in AS1)
    // Test that when AS1_A announces a route, it propagates to AS2,
    // but when AS2 tries to send it to AS1_B, AS1_B rejects it due to AS loop detection
    let [mut server1_a, server2, server1_b] = chain_servers([
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65001,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            90,
            true,
        ))
        .await, // Same AS as server1_a
    ])
    .await;

    // Server1_A announces a route to server2
    let server1_a_addr = server1_a.address.to_string();
    announce_and_verify_route(
        &mut server1_a,
        &[&server2],
        RouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
        PathParams {
            as_path: vec![as_sequence(vec![65001])],
            next_hop: server1_a_addr.clone(),
            peer_address: server1_a_addr,
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            ..Default::default()
        },
    )
    .await;

    // Wait for server1_b to receive UPDATE from server2
    // This proves server2 sent it, and we can then verify server1_b rejected it
    poll_until(
        || async {
            let (_, stats) = server1_b
                .client
                .get_peer(server2.address.to_string())
                .await
                .expect("Failed to get peer");
            stats.is_some_and(|s| s.update_received == 1)
        },
        "Timeout waiting for server1_b to receive UPDATE from server2",
    )
    .await;

    // Server1_B should have NO routes in its RIB (rejected due to AS loop prevention)
    // The route from server2 was received but rejected because AS_PATH would be [65002, 65001]
    // which contains server1_b's own ASN (65001)
    let routes = server1_b
        .client
        .get_routes()
        .await
        .expect("Failed to get routes from server 1_B");
    assert_eq!(
        routes.len(),
        0,
        "Server1_B should have no routes due to AS loop prevention"
    );

    // Verify all peers are still established
    // chain_servers: server1_a -> server2 -> server1_b
    // From connector's view: configured=true; from acceptor's view: configured=false
    assert!(
        verify_peers(
            &server1_a,
            vec![server2.to_peer(BgpState::Established, true)],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![
                server1_a.to_peer(BgpState::Established, false),
                server1_b.to_peer(BgpState::Established, true),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server1_b,
            vec![server2.to_peer(BgpState::Established, false)],
        )
        .await
    );
}

#[tokio::test]
async fn test_ipv6_route_exchange() {
    let (server1, mut server2) = setup_two_peered_servers(None).await;

    // Server2 announces both IPv4 and IPv6 routes to Server1 via gRPC
    announce_route(
        &mut server2,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    announce_route(
        &mut server2,
        RouteParams {
            prefix: "2001:db8::/32".to_string(),
            next_hop: "2001:db8::1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Get the actual peer address
    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    // Poll for both IPv4 and IPv6 routes to appear in Server1's RIB
    // eBGP: IPv4 next hop rewritten to sender's address
    // Cross-family (IPv6 route over IPv4 session): IPv6 next hop preserved
    poll_route_propagation(&[(
        &server1,
        vec![
            Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(PathParams {
                    as_path: vec![as_sequence(vec![65002])],
                    next_hop: server2.address.to_string(),
                    peer_address: peer_addr.clone(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                })],
            },
            Route {
                prefix: "2001:db8::/32".to_string(),
                paths: vec![build_path(PathParams {
                    as_path: vec![as_sequence(vec![65002])],
                    next_hop: "2001:db8::1".to_string(), // IPv6 next hop preserved
                    peer_address: peer_addr.clone(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                })],
            },
        ],
    )])
    .await;

    // Server2 withdraws both routes
    server2
        .client
        .remove_route("10.0.0.0/24".to_string())
        .await
        .expect("Failed to withdraw IPv4 route");

    server2
        .client
        .remove_route("2001:db8::/32".to_string())
        .await
        .expect("Failed to withdraw IPv6 route");

    // Poll for withdrawal and verify peers are still established
    poll_route_withdrawal(&[&server1]).await;
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established, true)],).await);
    assert!(
        verify_peers(
            &server2,
            vec![server1.to_peer(BgpState::Established, false)],
        )
        .await
    );
}

#[tokio::test]
async fn test_ipv6_nexthop_rewrite() {
    let server1 = start_test_server(Config::new(
        65001,
        "[::ffff:127.0.0.1]:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    let server2 = start_test_server(Config::new(
        65002,
        "[::ffff:127.0.0.2]:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
        true,
    ))
    .await;

    let [server1, mut server2] = chain_servers([server1, server2]).await;

    // Server2 announces IPv6 route with explicit next-hop
    let server2_addr = server2.address.to_string();
    announce_and_verify_route(
        &mut server2,
        &[&server1],
        RouteParams {
            prefix: "2001:db8::/32".to_string(),
            next_hop: "2001:db8::1".to_string(),
            ..Default::default()
        },
        PathParams {
            as_path: vec![as_sequence(vec![65002])],
            next_hop: server2_addr.clone(),
            peer_address: server2_addr,
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            ..Default::default()
        },
    )
    .await;

    // Withdraw the route
    server2
        .client
        .remove_route("2001:db8::/32".to_string())
        .await
        .expect("Failed to withdraw IPv6 route");

    poll_route_withdrawal(&[&server1]).await;
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established, true)],).await);
    assert!(
        verify_peers(
            &server2,
            vec![server1.to_peer(BgpState::Established, false)],
        )
        .await
    );
}
#[tokio::test]
async fn test_route_advertised_when_peer_becomes_established() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    // FakePeer connects and completes OPEN handshake (reaches OpenConfirm)
    let mut fake_peer = FakePeer::connect(None, &server).await;
    fake_peer
        .handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90)
        .await;

    // Announce route while peer is still in OpenConfirm (not Established)
    announce_route(
        &mut server,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Complete handshake to reach Established (send KEEPALIVE)
    fake_peer.handshake_keepalive().await;

    // Read UPDATE message - route should be automatically sent when peer became Established
    let update = fake_peer.read_update().await;
    let nlri = update.nlri_list();
    assert_eq!(nlri.len(), 1, "Expected one route announcement");
    assert_eq!(
        nlri[0].to_string(),
        "10.0.0.0/24",
        "Expected 10.0.0.0/24 to be announced"
    );
}
