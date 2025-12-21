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

use bgpgg::bgp::msg_notification::{BgpError, CeaseSubcode};
use bgpgg::config::Config;
use bgpgg::grpc::proto::{AdminState, BgpState, Origin, Peer, Route, SessionConfig};
use std::net::Ipv4Addr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

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
    // server1 connected to server2, so from server1's view, server2 is configured
    poll_until(
        || async { verify_peers(&server1, vec![server2.to_peer(BgpState::Idle, true)]).await },
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
    // From connector's view: configured=true; from acceptor's view: configured=false
    poll_until(
        || async {
            verify_peers(
                &server1,
                vec![
                    server2.to_peer(BgpState::Established, true),
                    server3.to_peer(BgpState::Established, true),
                    server4.to_peer(BgpState::Idle, true),
                ],
            )
            .await
                && verify_peers(
                    &server2,
                    vec![
                        server1.to_peer(BgpState::Established, false),
                        server3.to_peer(BgpState::Established, true),
                        server4.to_peer(BgpState::Idle, true),
                    ],
                )
                .await
                && verify_peers(
                    &server3,
                    vec![
                        server1.to_peer(BgpState::Established, false),
                        server2.to_peer(BgpState::Established, false),
                        server4.to_peer(BgpState::Idle, true),
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
    // From connector's view: configured=true
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
    // From connector's view: configured=true; from acceptor's view: configured=false
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
async fn test_peer_crash_and_recover() {
    let hold_timer_secs = 3;

    // Server2 is stable (passive, won't crash) - its port never changes
    // Server1 is active, will crash and recover
    let mut server2 = start_test_server(Config::new(
        65002,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        hold_timer_secs as u64,
        true,
    ))
    .await;

    let mut server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        hold_timer_secs as u64,
        true,
    ))
    .await;

    // Server2: passive peer - waits for connections, idle_hold_time_secs=0 for immediate Active
    server2
        .client
        .add_peer(
            format!("127.0.0.1:{}", server1.bgp_port),
            Some(SessionConfig {
                passive_mode: Some(true),
                idle_hold_time_secs: Some(0),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Server1: active peer - initiates connection to server2
    server1
        .client
        .add_peer(
            format!("127.0.0.2:{}", server2.bgp_port),
            Some(SessionConfig {
                idle_hold_time_secs: Some(0),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Wait for initial establishment
    poll_until(
        || async {
            verify_peers(&server1, vec![server2.to_peer(BgpState::Established, true)]).await
                && verify_peers(&server2, vec![server1.to_peer(BgpState::Established, true)]).await
        },
        "Timeout waiting for initial peer establishment",
    )
    .await;

    // Crash server1 (the active side)
    server1.kill();

    // Wait for server2's passive peer to be in Active (ready to accept connections)
    poll_until(
        || async {
            let peers = server2.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Active as i32
        },
        "Timeout waiting for server2 peer to reach Active",
    )
    .await;

    // Restart server1 - it gets a new port, but that's fine since it initiates
    let mut server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        hold_timer_secs as u64,
        true,
    ))
    .await;

    // Server1 adds peer pointing to server2 (whose port hasn't changed)
    server1
        .client
        .add_peer(
            format!("127.0.0.2:{}", server2.bgp_port),
            Some(SessionConfig {
                idle_hold_time_secs: Some(0),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Wait for re-establishment
    poll_until(
        || async {
            verify_peers(&server1, vec![server2.to_peer(BgpState::Established, true)]).await
                && verify_peers(&server2, vec![server1.to_peer(BgpState::Established, true)]).await
        },
        "Timeout waiting for peers to re-establish after crash",
    )
    .await;
}

#[tokio::test]
async fn test_auto_reconnect() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        3,
        true,
    ))
    .await;
    let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Use idle_hold_time_secs=0 for fast test (no delay before reconnect)
    server
        .client
        .add_peer(
            format!("127.0.0.2:{}", port),
            Some(SessionConfig {
                idle_hold_time_secs: Some(0),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Accept first connection (server initiated connection to configured peer)
    let mut peer = FakePeer::accept(&listener, 65002).await;
    peer.accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90).await;
    peer.handshake_keepalive().await;
    poll_until(
        || async { verify_peers(&server, vec![peer.to_peer(BgpState::Established, true)]).await },
        "Timeout waiting for Established",
    )
    .await;

    // Disconnect
    peer.stream.shutdown().await.ok();

    poll_until(
        || async {
            verify_peers(
                &server,
                vec![Peer {
                    address: peer.address.clone(),
                    asn: 65002, // Preserved from previous session
                    state: BgpState::OpenSent as i32,
                    admin_state: AdminState::Up.into(),
                    configured: true,
                }],
            )
            .await
        },
        "Timeout waiting for reconnect attempt",
    )
    .await;

    // Accept reconnection
    let mut peer = FakePeer::accept(&listener, 65002).await;
    peer.accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90).await;
    peer.handshake_keepalive().await;
    poll_until(
        || async { verify_peers(&server, vec![peer.to_peer(BgpState::Established, true)]).await },
        "Timeout waiting for auto-reconnect",
    )
    .await;
}

/// Test that idle_hold_time delays reconnection attempts
#[tokio::test]
async fn test_idle_hold_time_delay() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        3,
        true,
    ))
    .await;
    let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let idle_hold_secs = 2u64;

    // Add peer with idle_hold_time
    server
        .client
        .add_peer(
            format!("127.0.0.2:{}", port),
            Some(SessionConfig {
                idle_hold_time_secs: Some(idle_hold_secs),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Accept first connection and establish (server initiated connection to configured peer)
    let mut peer = FakePeer::accept(&listener, 65002).await;
    peer.accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90).await;
    peer.handshake_keepalive().await;
    poll_until(
        || async { verify_peers(&server, vec![peer.to_peer(BgpState::Established, true)]).await },
        "Timeout waiting for Established",
    )
    .await;

    // Disconnect
    peer.stream.shutdown().await.ok();

    // First wait for state to become Idle (server processed disconnect)
    poll_until(
        || async {
            let peers = server.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Idle as i32
        },
        "Timeout waiting for Idle",
    )
    .await;

    // Now record time and wait for reconnect
    let disconnect_time = std::time::Instant::now();
    poll_until(
        || async {
            let peers = server.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state != BgpState::Idle as i32
        },
        "Timeout waiting for reconnect attempt",
    )
    .await;

    // Verify that at least idle_hold_time elapsed before reconnect
    let elapsed = disconnect_time.elapsed();
    assert!(
        elapsed.as_secs() >= idle_hold_secs,
        "Reconnect happened too early: {:?} < {}s",
        elapsed,
        idle_hold_secs
    );
}

/// Test that allow_automatic_start=false prevents auto-reconnect
#[tokio::test]
async fn test_allow_automatic_start_false() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        3,
        true,
    ))
    .await;
    let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Add peer with automatic restart disabled (idle_hold_time_secs=None)
    server
        .client
        .add_peer(
            format!("127.0.0.2:{}", port),
            Some(SessionConfig {
                idle_hold_time_secs: None, // Disable automatic restart
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Accept connection and establish (server initiated connection to configured peer)
    let mut peer = FakePeer::accept(&listener, 65002).await;
    peer.accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90).await;
    peer.handshake_keepalive().await;
    poll_until(
        || async { verify_peers(&server, vec![peer.to_peer(BgpState::Established, true)]).await },
        "Timeout waiting for Established",
    )
    .await;

    // Disconnect
    peer.stream.shutdown().await.ok();

    // Wait for peer to go Idle (ASN preserved from previous session)
    poll_until(
        || async {
            verify_peers(
                &server,
                vec![Peer {
                    address: peer.address.clone(),
                    asn: peer.asn as u32,
                    state: BgpState::Idle as i32,
                    admin_state: AdminState::Up.into(),
                    configured: true,
                }],
            )
            .await
        },
        "Timeout waiting for Idle state",
    )
    .await;

    // Verify peer stays in Idle (no auto-reconnect) for 3 seconds
    poll_while(
        || async {
            let peers = server.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Idle as i32
        },
        std::time::Duration::from_secs(3),
        "Peer should stay in Idle with allow_automatic_start=false",
    )
    .await;
}

/// Test that manually stopped peer doesn't auto-reconnect even with idle_hold_time configured
#[tokio::test]
async fn test_manually_stopped_no_auto_reconnect() {
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
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
        true,
    ))
    .await;

    // Add peer with fast auto-reconnect
    server1
        .client
        .add_peer(
            format!("{}:{}", server2.address, server2.bgp_port),
            Some(SessionConfig {
                idle_hold_time_secs: Some(0),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Wait for Established
    poll_until(
        || async {
            let peers = server1.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Established as i32
        },
        "Timeout waiting for Established",
    )
    .await;

    // Disable the peer
    server1
        .client
        .disable_peer(server2.address.clone())
        .await
        .unwrap();

    // Wait for Idle with admin_state Down
    poll_until(
        || async {
            let peers = server1.client.get_peers().await.unwrap();
            peers.len() == 1
                && peers[0].state == BgpState::Idle as i32
                && peers[0].admin_state == AdminState::Down as i32
        },
        "Timeout waiting for Idle/Down",
    )
    .await;

    // Verify peer stays in Idle (no auto-reconnect despite idle_hold_time=0)
    poll_while(
        || async {
            let peers = server1.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Idle as i32
        },
        std::time::Duration::from_secs(2),
        "Manually stopped peer should not auto-reconnect",
    )
    .await;
}

#[tokio::test]
async fn test_unconfigured_peer_removed_on_disconnect() {
    use std::net::Ipv4Addr;

    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    // FakePeer connects to the server - this is an unconfigured peer
    let mut fake_peer = FakePeer::connect(None, &server).await;
    fake_peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90).await;
    fake_peer.handshake_keepalive().await;

    // Verify peer is established (fake_peer connects without AddPeer, so configured=false)
    poll_until(
        || async {
            verify_peers(
                &server,
                vec![fake_peer.to_peer(BgpState::Established, false)],
            )
            .await
        },
        "Timeout waiting for FakePeer to establish",
    )
    .await;

    // Drop FakePeer to disconnect - unconfigured peer should be removed entirely
    drop(fake_peer);

    // Verify peer is removed (not in Idle, but completely gone)
    poll_until(
        || async { verify_peers(&server, vec![]).await },
        "Timeout waiting for unconfigured peer removal",
    )
    .await;
}

#[tokio::test]
async fn test_damp_peer_oscillations() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        3,
        true,
    ))
    .await;
    let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // idle_hold_time=1s, damping=true. After 2 downs: 1s * 2^2 = 4s
    server
        .client
        .add_peer(
            format!("127.0.0.2:{}", port),
            Some(SessionConfig {
                idle_hold_time_secs: Some(1),
                damp_peer_oscillations: Some(true),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // 2 rapid connect/disconnect cycles to build up consecutive_down_count
    for _ in 0..2 {
        let mut peer = FakePeer::accept(&listener, 65002).await;
    peer.accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90).await;
    peer.handshake_keepalive().await;
        poll_until(
            || async {
                verify_peers(&server, vec![peer.to_peer(BgpState::Established, true)]).await
            },
            "Timeout waiting for Established",
        )
        .await;
        peer.stream.shutdown().await.ok();
    }

    // Wait for peer to reach Idle after second disconnect
    poll_until(
        || async {
            let peers = server.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Idle as i32
        },
        "Timeout waiting for Idle after disconnect",
    )
    .await;

    // After 2 downs: idle_hold = 1s * 2^2 = 4s
    // Verify peer stays in Idle for 2s (proving backoff > base 1s)
    poll_while(
        || async {
            let peers = server.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Idle as i32
        },
        std::time::Duration::from_secs(2),
        "Damping should delay reconnect beyond 2s",
    )
    .await;
}

/// Test that unconfigured peers are rejected when accept_unconfigured_peers=false
/// RFC 4486: SHOULD send CEASE/ConnectionRejected
#[tokio::test]
async fn test_reject_unconfigured_peer() {
    // Server with accept_unconfigured_peers=false, 127.0.0.2 is configured
    let mut config = Config::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 90, false);
    config.peers.push(bgpgg::config::PeerConfig {
        address: "127.0.0.2:179".to_string(),
        passive_mode: true,
        ..Default::default()
    });
    let server = start_test_server(config).await;

    // Configured peer from 127.0.0.2 should be accepted
    let mut configured_peer = FakePeer::connect(Some("127.0.0.2"), &server).await;
    configured_peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90).await;
    configured_peer.handshake_keepalive().await;
    poll_until(
        || async {
            verify_peers(
                &server,
                vec![configured_peer.to_peer(BgpState::Established, true)],
            )
            .await
        },
        "configured peer should be established",
    )
    .await;

    // Unconfigured peer from 127.0.0.3 should be rejected
    let mut unconfigured_peer = FakePeer::connect(Some("127.0.0.3"), &server).await;
    let notif = unconfigured_peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::Cease(CeaseSubcode::ConnectionRejected),
    );

    // Server should still have only the configured peer
    let peers = server.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address, "127.0.0.2");
}

/// Test PassiveTcpEstablishment - server waits for remote to connect (RFC 4271 8.1.1)
#[tokio::test]
async fn test_passive_mode() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    // Add peer with passive_mode=true
    server
        .client
        .add_peer(
            "127.0.0.2:179".to_string(),
            Some(SessionConfig {
                passive_mode: Some(true),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Verify server does NOT initiate connection (stays in Active waiting for incoming)
    poll_while(
        || async {
            let peers = server.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Active as i32
        },
        std::time::Duration::from_secs(2),
        "Passive peer should stay in Active",
    )
    .await;

    // Remote peer connects - should be accepted and establish
    let mut fake_peer = FakePeer::connect(Some("127.0.0.2"), &server).await;
    fake_peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90).await;
    fake_peer.handshake_keepalive().await;

    poll_until(
        || async {
            verify_peers(
                &server,
                vec![fake_peer.to_peer(BgpState::Established, true)],
            )
            .await
        },
        "Passive peer should establish when remote connects",
    )
    .await;
}

#[tokio::test]
async fn test_delay_open() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        false,
    ))
    .await;

    let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let delay_secs: u64 = 3;

    let start = std::time::Instant::now();

    server
        .client
        .add_peer(
            format!("127.0.0.2:{}", port),
            Some(SessionConfig {
                delay_open_time_secs: Some(delay_secs),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Accept connection - FakePeer won't send OPEN, so server's DelayOpenTimer runs
    let mut _peer = FakePeer::accept(&listener, 65002).await;
    _peer.accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90).await;
    _peer.handshake_keepalive().await;

    // Wait for server to send OPEN
    poll_until(
        || async {
            let Ok((_, stats)) = server.client.get_peer("127.0.0.2".to_string()).await else {
                return false;
            };
            stats.map_or(false, |s| s.open_sent > 0)
        },
        "Timeout waiting for OPEN",
    )
    .await;

    assert!(
        start.elapsed().as_secs() >= delay_secs,
        "OPEN sent before delay_open_time elapsed"
    );
}
