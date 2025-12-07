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

#[tokio::test]
async fn test_peer_down() {
    let hold_timer_secs = 3;
    let (server1, mut server2) = setup_two_peered_servers(Some(hold_timer_secs)).await;

    // Server2 announces a route to Server1 via gRPC
    server2
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            None,
            false,
        )
        .await
        .expect("Failed to announce route");

    // Get the actual peer address (with OS-allocated port)
    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    // Poll for route to appear in Server1's RIB
    // eBGP: NEXT_HOP rewritten to sender's local address
    poll_route_propagation(&[(
        &server1,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65002])],
                &server2.address,
                peer_addr.clone(),
                Origin::Igp,
                Some(100),
                None,
                false,
                vec![],
            )],
        }],
    )])
    .await;

    // Kill Server2 to simulate peer going down (drops runtime, killing ALL tasks)
    server2.kill();

    // Poll for peer state change (configured peers kept in Idle, not removed)
    // server1 connected to server2, so from server1's view, server2 is configured (dynamic=false)
    poll_until(
        || async {
            verify_peers(&server1, vec![server2.to_peer(BgpState::Idle, false)]).await
        },
        "Timeout waiting for peer down detection",
    )
    .await;

    // Poll for route withdrawal
    poll_route_withdrawal(&[&server1]).await;
}

#[tokio::test]
async fn test_peer_down_four_node_mesh() {
    let hold_timer_secs = 3;
    let (mut server1, server2, server3, mut server4) =
        setup_four_meshed_servers(Some(hold_timer_secs)).await;

    // Server1 announces a route
    server1
        .client
        .add_route(
            "10.1.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            None,
            false,
        )
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route to propagate to all peers
    // eBGP: NEXT_HOP rewritten to router IDs
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])],
                    &server1.address, // eBGP: NEXT_HOP rewritten to sender's local address
                    server1.address.clone(),
                    Origin::Igp,
                    Some(100),
                    None,
                    false,
                    vec![],
                )],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])],
                    &server1.address, // eBGP: NEXT_HOP rewritten to sender's local address
                    server1.address.clone(),
                    Origin::Igp,
                    Some(100),
                    None,
                    false,
                    vec![],
                )],
            }],
        ),
        (
            &server4,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])],
                    &server1.address, // eBGP: NEXT_HOP rewritten to sender's local address
                    server1.address.clone(),
                    Origin::Igp,
                    Some(100),
                    None,
                    false,
                    vec![],
                )],
            }],
        ),
    ])
    .await;

    // Kill Server4 to simulate peer going down
    server4.kill();

    // Poll for all servers to detect Server4 is down (configured peers stay in Idle)
    // mesh_servers: lower index connects to higher index
    poll_until(
        || async {
            verify_peers(
                &server1,
                vec![
                    server2.to_peer(BgpState::Established, false),
                    server3.to_peer(BgpState::Established, false),
                    server4.to_peer(BgpState::Idle, false),
                ],
            )
            .await
                && verify_peers(
                    &server2,
                    vec![
                        server1.to_peer(BgpState::Established, true),
                        server3.to_peer(BgpState::Established, false),
                        server4.to_peer(BgpState::Idle, false),
                    ],
                )
                .await
                && verify_peers(
                    &server3,
                    vec![
                        server1.to_peer(BgpState::Established, true),
                        server2.to_peer(BgpState::Established, true),
                        server4.to_peer(BgpState::Idle, false),
                    ],
                )
                .await
        },
        "Timeout waiting for Server4 peer down detection",
    )
    .await;

    // Verify Server2 and Server3 still have the route (learned from Server1, not Server4)
    // eBGP: NEXT_HOP rewritten to router IDs
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])],
                    &server1.address, // eBGP: NEXT_HOP rewritten to sender's local address
                    server1.address.clone(),
                    Origin::Igp,
                    Some(100),
                    None,
                    false,
                    vec![],
                )],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])],
                    &server1.address, // eBGP: NEXT_HOP rewritten to sender's local address
                    server1.address.clone(),
                    Origin::Igp,
                    Some(100),
                    None,
                    false,
                    vec![],
                )],
            }],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_remove_peer() {
    let hold_timer_secs = 3;
    let (mut server1, mut server2) = setup_two_peered_servers(Some(hold_timer_secs)).await;

    // Server2 announces a route to Server1 via gRPC
    server2
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            None,
            false,
        )
        .await
        .expect("Failed to announce route");

    // Get the actual peer address (with OS-allocated port)
    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    // Poll for route to appear in Server1's RIB
    // eBGP: NEXT_HOP rewritten to sender's local address
    poll_route_propagation(&[(
        &server1,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65002])],
                &server2.address,
                peer_addr.clone(),
                Origin::Igp,
                Some(100),
                None,
                false,
                vec![],
            )],
        }],
    )])
    .await;

    // Remove peer via API call instead of killing the server
    server1
        .client
        .remove_peer(peer_addr.clone())
        .await
        .expect("Failed to remove peer");

    // Poll for route withdrawal - route should be withdrawn when peer is removed
    poll_route_withdrawal(&[&server1]).await;

    // Verify Server1 has no peers in Established state anymore
    assert!(verify_peers(&server1, vec![]).await);
}

#[tokio::test]
async fn test_remove_peer_withdraw_routes() {
    let hold_timer_secs = 3;
    let (mut server1, mut server2) = setup_two_peered_servers(Some(hold_timer_secs)).await;

    // Server2 announces a route
    server2
        .client
        .add_route(
            "10.2.0.0/24".to_string(),
            "192.168.2.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            None,
            false,
        )
        .await
        .expect("Failed to announce route from server 2");

    // Get the actual peer address
    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    // Poll for route to appear in Server1's RIB
    // eBGP: NEXT_HOP rewritten to router ID
    poll_route_propagation(&[(
        &server1,
        vec![Route {
            prefix: "10.2.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65002])],
                &server2.address, // eBGP: NEXT_HOP rewritten to sender's local address
                peer_addr.clone(),
                Origin::Igp,
                Some(100),
                None,
                false,
                vec![],
            )],
        }],
    )])
    .await;

    // Remove Server2's peer from Server1 via API call
    server1
        .client
        .remove_peer(peer_addr.clone())
        .await
        .expect("Failed to remove peer");

    // Poll for route withdrawal from Server1 - Server1 should withdraw the route learned from Server2
    poll_route_withdrawal(&[&server1]).await;

    // Verify Server1 no longer has Server2 as a peer
    assert!(verify_peers(&server1, vec![]).await);
}

#[tokio::test]
async fn test_remove_peer_four_node_mesh() {
    let hold_timer_secs = 3;
    let (mut server1, server2, server3, mut server4) =
        setup_four_meshed_servers(Some(hold_timer_secs)).await;

    // Server4 announces a route
    server4
        .client
        .add_route(
            "10.4.0.0/24".to_string(),
            "192.168.4.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            None,
            false,
        )
        .await
        .expect("Failed to announce route from server 4");

    // Poll for route to propagate to all peers
    // eBGP: NEXT_HOP rewritten to router IDs
    poll_route_propagation(&[
        (
            &server1,
            vec![Route {
                prefix: "10.4.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65004])],
                    &server4.address, // eBGP: NEXT_HOP rewritten to sender's local address
                    server4.address.clone(),
                    Origin::Igp,
                    Some(100),
                    None,
                    false,
                    vec![],
                )],
            }],
        ),
        (
            &server2,
            vec![Route {
                prefix: "10.4.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65004])],
                    &server4.address, // eBGP: NEXT_HOP rewritten to sender's local address
                    server4.address.clone(),
                    Origin::Igp,
                    Some(100),
                    None,
                    false,
                    vec![],
                )],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.4.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65004])],
                    &server4.address, // eBGP: NEXT_HOP rewritten to sender's local address
                    server4.address.clone(),
                    Origin::Igp,
                    Some(100),
                    None,
                    false,
                    vec![],
                )],
            }],
        ),
    ])
    .await;

    // Remove Server4's peer from Server1 via API call
    server1
        .client
        .remove_peer(server4.address.clone())
        .await
        .expect("Failed to remove peer");

    // Verify all servers still have the route
    // Server1 now learns via server2 (deterministically chosen due to lower peer IP)
    // Server2 and Server3 still learn directly from Server4
    // eBGP: NEXT_HOP rewritten to router IDs
    // Use longer timeout for re-convergence after peer removal
    poll_route_propagation_with_timeout(
        &[
            (
                &server1,
                vec![Route {
                    prefix: "10.4.0.0/24".to_string(),
                    paths: vec![build_path(
                        vec![as_sequence(vec![65002, 65004])],
                        &server2.address, // eBGP: NEXT_HOP rewritten to sender's local address
                        server2.address.clone(),
                        Origin::Igp,
                        Some(100),
                        None,
                        false,
                        vec![],
                    )], // Via server2 (127.0.0.2 < 127.0.0.3)
                }],
            ),
            (
                &server2,
                vec![Route {
                    prefix: "10.4.0.0/24".to_string(),
                    paths: vec![build_path(
                        vec![as_sequence(vec![65004])],
                        &server4.address, // eBGP: NEXT_HOP rewritten to sender's local address
                        server4.address.clone(),
                        Origin::Igp,
                        Some(100),
                        None,
                        false,
                        vec![],
                    )],
                }],
            ),
            (
                &server3,
                vec![Route {
                    prefix: "10.4.0.0/24".to_string(),
                    paths: vec![build_path(
                        vec![as_sequence(vec![65004])],
                        &server4.address, // eBGP: NEXT_HOP rewritten to sender's local address
                        server4.address.clone(),
                        Origin::Igp,
                        Some(100),
                        None,
                        false,
                        vec![],
                    )],
                }],
            ),
        ],
        200,
    )
    .await;

    // Verify Server1 no longer has Server4 as a peer
    // mesh_servers: lower index connects to higher index
    assert!(
        verify_peers(
            &server1,
            vec![
                server2.to_peer(BgpState::Established, false),
                server3.to_peer(BgpState::Established, false),
            ],
        )
        .await
    );
}

#[tokio::test]
async fn test_peer_up() {
    let hold_timer_secs = 3;
    let (server1, server2) = setup_two_peered_servers(Some(hold_timer_secs)).await;

    // Poll until OPEN exchanged and at least one keepalive cycle completed
    let expected = ExpectedStats {
        open_sent: Some(1),
        open_received: Some(1),
        min_keepalive_sent: Some(2),
        min_keepalive_received: Some(2),
        ..Default::default()
    };
    poll_peer_stats(&server1, &server2.address, expected).await;
    poll_peer_stats(&server2, &server1.address, expected).await;

    // Verify both peers are still in Established state
    // chain_servers: server1 connected to server2
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established, false)],).await);
    assert!(verify_peers(&server2, vec![server1.to_peer(BgpState::Established, true)],).await);
}

#[tokio::test]
async fn test_peer_up_four_node_mesh() {
    let hold_timer_secs = 3;
    let (server1, server2, server3, server4) =
        setup_four_meshed_servers(Some(hold_timer_secs)).await;

    // Poll until multiple keepalive cycles completed (proves connection stays up)
    let expected = ExpectedStats {
        min_keepalive_sent: Some(2),
        min_keepalive_received: Some(2),
        ..Default::default()
    };
    poll_peer_stats(&server1, &server2.address, expected).await;
    poll_peer_stats(&server1, &server3.address, expected).await;
    poll_peer_stats(&server1, &server4.address, expected).await;
    poll_peer_stats(&server2, &server1.address, expected).await;
    poll_peer_stats(&server2, &server3.address, expected).await;
    poll_peer_stats(&server2, &server4.address, expected).await;
    poll_peer_stats(&server3, &server1.address, expected).await;
    poll_peer_stats(&server3, &server2.address, expected).await;
    poll_peer_stats(&server3, &server4.address, expected).await;
    poll_peer_stats(&server4, &server1.address, expected).await;
    poll_peer_stats(&server4, &server2.address, expected).await;
    poll_peer_stats(&server4, &server3.address, expected).await;

    // Verify all peers are still in Established state
    // mesh_servers: lower index connects to higher index
    assert!(
        verify_peers(
            &server1,
            vec![
                server2.to_peer(BgpState::Established, false),
                server3.to_peer(BgpState::Established, false),
                server4.to_peer(BgpState::Established, false),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![
                server1.to_peer(BgpState::Established, true),
                server3.to_peer(BgpState::Established, false),
                server4.to_peer(BgpState::Established, false),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server3,
            vec![
                server1.to_peer(BgpState::Established, true),
                server2.to_peer(BgpState::Established, true),
                server4.to_peer(BgpState::Established, false),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server4,
            vec![
                server1.to_peer(BgpState::Established, true),
                server2.to_peer(BgpState::Established, true),
                server3.to_peer(BgpState::Established, true),
            ],
        )
        .await
    );
}

#[tokio::test]
async fn test_peer_crash_and_recover() {
    let hold_timer_secs = 3;
    let crash_count = 5;
    let (server1, mut server2) = setup_two_peered_servers(Some(hold_timer_secs)).await;

    let server2_port = server1.bgp_port; // Server1's port that Server2 connects to
    let server2_asn = server2.asn;
    let server2_router_id = server2.client.router_id;
    let server2_bind_ip = server2.address.clone();

    // Crash and recover the peer multiple times
    for i in 0..crash_count {
        // Kill Server2 (simulates crash)
        server2.kill();

        // Restart Server2 with same configuration
        server2 = start_test_server(
            server2_asn,
            server2_router_id,
            Some(hold_timer_secs),
            &server2_bind_ip,
        )
        .await;

        // Server2 reconnects to Server1
        server2
            .client
            .add_peer(format!("127.0.0.1:{}", server2_port), None)
            .await
            .expect("Failed to re-add peer after crash");

        // Poll until re-established before next crash cycle
        // server2 connects to server1: from server1's view server2 is dynamic, vice versa
        poll_until(
            || async {
                verify_peers(&server1, vec![server2.to_peer(BgpState::Established, true)]).await
                    && verify_peers(&server2, vec![server1.to_peer(BgpState::Established, false)])
                        .await
            },
            &format!(
                "Timeout waiting for peers to re-establish after crash {}",
                i + 1
            ),
        )
        .await;
    }
}

#[tokio::test]
async fn test_dynamic_peer_removed_on_disconnect() {
    use std::net::Ipv4Addr;

    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(90), "127.0.0.1").await;

    // FakePeer connects to the server - this is a dynamic/incoming peer
    let fake_peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 90, &server).await;

    // Verify peer is established (fake_peer connects to server, so dynamic=true)
    poll_until(
        || async {
            verify_peers(&server, vec![fake_peer.to_peer(BgpState::Established, true)]).await
        },
        "Timeout waiting for FakePeer to establish",
    )
    .await;

    // Drop FakePeer to disconnect - dynamic peer should be removed entirely
    drop(fake_peer);

    // Verify peer is removed (not in Idle, but completely gone)
    poll_until(
        || async { verify_peers(&server, vec![]).await },
        "Timeout waiting for dynamic peer removal",
    )
    .await;
}
