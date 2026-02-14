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

//! Tests for peer lifecycle: up, down, crash, recovery, and reconnection

mod utils;
pub use utils::*;

use bgpgg::bgp::msg_notification::{BgpError, OpenMessageError};
use bgpgg::config::Config;
use bgpgg::grpc::proto::{
    AdminState, Afi, BgpState, GracefulRestartConfig, Origin, Peer, ResetType, Route, Safi,
    SessionConfig,
};
use std::net::Ipv4Addr;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn test_peer_down() {
    let hold_timer_secs = 3;
    let gr_restart_time_secs = 3; // 3-second GR timer for testing

    // Set up servers
    let [server1, mut server2] = [
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            hold_timer_secs as u64,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            hold_timer_secs as u64,
        ))
        .await,
    ];

    // Server2 configures server1 as a passive peer with short GR timer
    // This ensures server2 advertises the short restart time
    let config2 = bgpgg::grpc::proto::SessionConfig {
        graceful_restart: Some(bgpgg::grpc::proto::GracefulRestartConfig {
            enabled: Some(true),
            restart_time_secs: Some(gr_restart_time_secs),
        }),
        passive_mode: Some(true),
        ..Default::default()
    };
    let mut config2 = config2;
    config2.port = Some(server1.bgp_port as u32);
    server2
        .client
        .add_peer(server1.address.to_string(), Some(config2))
        .await
        .unwrap();

    // Server1 connects to server2 with short GR timer
    let mut config1 = session_config_with_gr_timer(gr_restart_time_secs);
    config1.port = Some(server2.bgp_port as u32);
    server1
        .client
        .add_peer(server2.address.to_string(), Some(config1))
        .await
        .unwrap();

    // Wait for peering to establish
    poll_peers(&server1, vec![server2.to_peer(BgpState::Established)]).await;

    // Server2 announces a route to Server1
    let server2_addr = server2.address.to_string();
    announce_and_verify_route(
        &server2,
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

    // Kill Server2 to simulate peer going down
    server2.kill();

    // Poll for peer state change to Idle
    poll_peers(&server1, vec![server2.to_peer(BgpState::Idle)]).await;

    // With 3-second GR timer, routes withdrawn after 3 seconds
    poll_until_with_timeout(
        || async {
            let Ok(routes) = server1.client.get_routes().await else {
                return false;
            };
            routes.is_empty()
        },
        "Timeout waiting for route withdrawal after GR timer expires",
        50, // 5 seconds = 3s GR timer + 2s buffer
    )
    .await;
}

#[tokio::test]
async fn test_peer_down_four_node_mesh() {
    let (server1, server2, server3, mut server4) = setup_four_meshed_servers(PeerConfig {
        hold_timer_secs: Some(3),
        ..Default::default()
    })
    .await;

    // Server1 announces a route to all peers
    let server1_addr = server1.address.to_string();
    announce_and_verify_route(
        &server1,
        &[&server2, &server3, &server4],
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

    // Kill Server4 to simulate peer going down
    server4.kill();

    // Poll for all servers to detect Server4 is down (configured peers stay in Idle)
    // Active-active peering: all sides call add_peer, so configured=true for all
    poll_until(
        || async {
            verify_peers(
                &server1,
                vec![
                    server2.to_peer(BgpState::Established),
                    server3.to_peer(BgpState::Established),
                    server4.to_peer(BgpState::Idle),
                ],
            )
            .await
                && verify_peers(
                    &server2,
                    vec![
                        server1.to_peer(BgpState::Established),
                        server3.to_peer(BgpState::Established),
                        server4.to_peer(BgpState::Idle),
                    ],
                )
                .await
                && verify_peers(
                    &server3,
                    vec![
                        server1.to_peer(BgpState::Established),
                        server2.to_peer(BgpState::Established),
                        server4.to_peer(BgpState::Idle),
                    ],
                )
                .await
        },
        "Timeout waiting for Server4 peer down detection",
    )
    .await;

    // Verify Server2 and Server3 still have the route (learned from Server1, not Server4)
    // eBGP: NEXT_HOP rewritten to router IDs
    poll_rib(&[
        (
            &server2,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(PathParams {
                    as_path: vec![as_sequence(vec![65001])],
                    next_hop: server1.address.to_string(), // eBGP: NEXT_HOP rewritten to sender's local address
                    peer_address: server1.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                })],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![build_path(PathParams {
                    as_path: vec![as_sequence(vec![65001])],
                    next_hop: server1.address.to_string(), // eBGP: NEXT_HOP rewritten to sender's local address
                    peer_address: server1.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                })],
            }],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_peer_up() {
    let (server1, server2) = setup_two_peered_servers(PeerConfig {
        hold_timer_secs: Some(3),
        ..Default::default()
    })
    .await;

    // Poll until OPEN exchanged and at least one keepalive cycle completed
    let expected = ExpectedStats {
        open_sent: Some(1),
        open_received: Some(1),
        min_keepalive_sent: Some(2),
        min_keepalive_received: Some(2),
        ..Default::default()
    };
    poll_peer_stats(&server1, &server2.address.to_string(), expected).await;
    poll_peer_stats(&server2, &server1.address.to_string(), expected).await;

    // Verify both peers are still in Established state
    // Active-active peering: both sides call add_peer, so configured=true on both
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established)],).await);
    assert!(verify_peers(&server2, vec![server1.to_peer(BgpState::Established)],).await);
}

#[tokio::test]
async fn test_peer_up_four_node_mesh() {
    let (server1, server2, server3, server4) = setup_four_meshed_servers(PeerConfig {
        hold_timer_secs: Some(3),
        ..Default::default()
    })
    .await;

    // Poll until multiple keepalive cycles completed (proves connection stays up)
    let expected = ExpectedStats {
        min_keepalive_sent: Some(2),
        min_keepalive_received: Some(2),
        ..Default::default()
    };
    poll_peer_stats(&server1, &server2.address.to_string(), expected).await;
    poll_peer_stats(&server1, &server3.address.to_string(), expected).await;
    poll_peer_stats(&server1, &server4.address.to_string(), expected).await;
    poll_peer_stats(&server2, &server1.address.to_string(), expected).await;
    poll_peer_stats(&server2, &server3.address.to_string(), expected).await;
    poll_peer_stats(&server2, &server4.address.to_string(), expected).await;
    poll_peer_stats(&server3, &server1.address.to_string(), expected).await;
    poll_peer_stats(&server3, &server2.address.to_string(), expected).await;
    poll_peer_stats(&server3, &server4.address.to_string(), expected).await;
    poll_peer_stats(&server4, &server1.address.to_string(), expected).await;
    poll_peer_stats(&server4, &server2.address.to_string(), expected).await;
    poll_peer_stats(&server4, &server3.address.to_string(), expected).await;

    // Verify all peers are still in Established state
    // Active-active peering: all sides call add_peer, so configured=true for all
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
async fn test_peer_crash_and_recover() {
    let hold_timer_secs = 3;

    // Server2 is stable (passive, won't crash) - its port never changes
    // Server1 is active, will crash and recover
    let server2 = start_test_server(Config::new(
        65002,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        hold_timer_secs as u64,
    ))
    .await;

    let mut server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        hold_timer_secs as u64,
    ))
    .await;

    // Server2: passive peer - waits for connections, idle_hold_time_secs=0 for immediate Active
    server2
        .client
        .add_peer(
            "127.0.0.1".to_string(),
            Some(SessionConfig {
                port: Some(server1.bgp_port as u32),
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
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                port: Some(server2.bgp_port as u32),
                idle_hold_time_secs: Some(0),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Wait for initial establishment
    poll_until(
        || async {
            verify_peers(&server1, vec![server2.to_peer(BgpState::Established)]).await
                && verify_peers(&server2, vec![server1.to_peer(BgpState::Established)]).await
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
    let server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        hold_timer_secs as u64,
    ))
    .await;

    // Server1 adds peer pointing to server2 (whose port hasn't changed)
    server1
        .client
        .add_peer(
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                port: Some(server2.bgp_port as u32),
                idle_hold_time_secs: Some(0),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Wait for re-establishment
    poll_until(
        || async {
            verify_peers(&server1, vec![server2.to_peer(BgpState::Established)]).await
                && verify_peers(&server2, vec![server1.to_peer(BgpState::Established)]).await
        },
        "Timeout waiting for peers to re-establish after crash",
    )
    .await;
}

#[tokio::test]
async fn test_auto_reconnect() {
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        3,
    ))
    .await;
    let mut peer = FakePeer::new("127.0.0.2:0", 65002).await;
    let port = peer.port();

    // Use idle_hold_time_secs=0 for fast test (no delay before reconnect)
    server
        .client
        .add_peer(
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                port: Some(port as u32),
                idle_hold_time_secs: Some(0),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Accept first connection (server initiated connection to configured peer)
    peer.accept().await;
    peer.accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90)
        .await;
    peer.handshake_keepalive().await;
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;

    // Disconnect
    peer.stream.as_mut().unwrap().shutdown().await.ok();

    poll_peers(
        &server,
        vec![Peer {
            address: peer.address.to_string(),
            asn: 0, // Cleared on disconnect, re-learned on next OPEN
            state: BgpState::OpenSent as i32,
            admin_state: AdminState::Up.into(),
            import_policies: vec![],
            export_policies: vec![],
        }],
    )
    .await;

    // Accept reconnection
    peer.accept().await;
    peer.accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90)
        .await;
    peer.handshake_keepalive().await;
    poll_until(
        || async { verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await },
        "Timeout waiting for auto-reconnect",
    )
    .await;
}

/// Test that idle_hold_time delays reconnection attempts
#[tokio::test]
async fn test_idle_hold_time_delay() {
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        3,
    ))
    .await;
    let mut peer = FakePeer::new("127.0.0.2:0", 65002).await;
    let port = peer.port();

    let idle_hold_secs = 2u64;

    // Add peer with idle_hold_time
    server
        .client
        .add_peer(
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                port: Some(port as u32),
                idle_hold_time_secs: Some(idle_hold_secs),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Accept first connection and establish (server initiated connection to configured peer)
    peer.accept().await;
    peer.accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90)
        .await;
    peer.handshake_keepalive().await;
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;

    // Disconnect
    peer.stream.as_mut().unwrap().shutdown().await.ok();

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
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        3,
    ))
    .await;
    let mut peer = FakePeer::new("127.0.0.2:0", 65002).await;
    let port = peer.port();

    // Add peer with automatic restart disabled (idle_hold_time_secs=None)
    server
        .client
        .add_peer(
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                port: Some(port as u32),
                idle_hold_time_secs: None, // Disable automatic restart
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Accept connection and establish (server initiated connection to configured peer)
    peer.accept().await;
    peer.accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90)
        .await;
    peer.handshake_keepalive().await;
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;

    // Disconnect
    peer.stream.as_mut().unwrap().shutdown().await.ok();

    // Wait for peer to go Idle, verify it stays there (no auto-reconnect)
    poll_until_stable(
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
async fn test_damp_peer_oscillations() {
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        3,
    ))
    .await;
    let mut peer = FakePeer::new("127.0.0.2:0", 65002).await;
    let port = peer.port();

    // idle_hold_time=1s, damping=true. After 2 downs: 1s * 2^2 = 4s
    server
        .client
        .add_peer(
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                port: Some(port as u32),
                idle_hold_time_secs: Some(1),
                damp_peer_oscillations: Some(true),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // 2 rapid connect/disconnect cycles to build up consecutive_down_count
    for _ in 0..2 {
        peer.accept().await;
        peer.accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90)
            .await;
        peer.handshake_keepalive().await;
        poll_until(
            || async { verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await },
            "Timeout waiting for Established",
        )
        .await;
        peer.stream.as_mut().unwrap().shutdown().await.ok();
    }

    // After 2 downs: idle_hold = 1s * 2^2 = 4s
    // Wait for Idle then verify it stays in Idle for 2s (proving backoff > base 1s)
    poll_until_stable(
        || async {
            let peers = server.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Idle as i32
        },
        std::time::Duration::from_secs(2),
        "Damping should keep peer in Idle",
    )
    .await;
}

/// Test PassiveTcpEstablishment - server waits for remote to connect (RFC 4271 8.1.1)
#[tokio::test]
async fn test_passive_mode() {
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // Add peer with passive_mode=true
    // idle_hold_time_secs enables allow_automatic_start which triggers AutomaticStartPassive
    server
        .client
        .add_peer(
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                passive_mode: Some(true),
                idle_hold_time_secs: Some(0),
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
    fake_peer
        .handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90)
        .await;
    fake_peer.handshake_keepalive().await;

    poll_until(
        || async { verify_peers(&server, vec![fake_peer.to_peer(BgpState::Established)]).await },
        "Passive peer should establish when remote connects",
    )
    .await;
}

#[tokio::test]
async fn test_delay_open() {
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    let mut _peer = FakePeer::new("127.0.0.2:0", 65002).await;
    let port = _peer.port();
    let delay_secs: u64 = 3;

    let start = std::time::Instant::now();

    server
        .client
        .add_peer(
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                port: Some(port as u32),
                delay_open_time_secs: Some(delay_secs),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Accept connection - FakePeer won't send OPEN, so server's DelayOpenTimer runs
    _peer.accept().await;
    _peer
        .accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90)
        .await;
    _peer.handshake_keepalive().await;

    // Wait for server to send OPEN
    poll_until(
        || async {
            let Ok((_, stats)) = server.client.get_peer("127.0.0.2".to_string()).await else {
                return false;
            };
            stats.is_some_and(|s| s.open_sent > 0)
        },
        "Timeout waiting for OPEN",
    )
    .await;

    assert!(
        start.elapsed().as_secs() >= delay_secs,
        "OPEN sent before delay_open_time elapsed"
    );
}

/// Test MRAI (RFC 4271 9.2.1.1) per-peer rate limiting
#[tokio::test]
async fn test_mrai_rate_limiting() {
    let test_cases = vec![
        (0u64, 3), // MRAI=0: all UPDATEs sent immediately
        (2u64, 3), // MRAI=2s: first sent, rest queued
    ];

    for (mrai_secs, num_routes) in test_cases {
        // Set MRAI on the peer config - controls how fast server1 can send updates to server2
        let (server1, server2) = setup_two_peered_servers(PeerConfig {
            min_route_advertisement_interval_secs: Some(mrai_secs),
            ..Default::default()
        })
        .await;

        let start_time = std::time::Instant::now();

        // Rapidly announce multiple routes
        for i in 0..num_routes {
            announce_route(
                &server1,
                RouteParams {
                    prefix: format!("10.{}.0.0/24", i),
                    next_hop: "192.168.1.1".to_string(),
                    ..Default::default()
                },
            )
            .await;
        }

        // Poll until all routes propagate
        poll_rib(&[(
            &server2,
            (0..num_routes)
                .map(|i| Route {
                    prefix: format!("10.{}.0.0/24", i),
                    paths: vec![build_path(PathParams {
                        as_path: vec![as_sequence(vec![65001])],
                        next_hop: server1.address.to_string(),
                        peer_address: server1.address.to_string(),
                        origin: Some(Origin::Igp),
                        local_pref: Some(100),
                        ..Default::default()
                    })],
                })
                .collect(),
        )])
        .await;

        let elapsed = start_time.elapsed();

        // Verify MRAI timing constraint
        if mrai_secs > 0 {
            assert!(
                elapsed.as_secs() >= mrai_secs,
                "MRAI={}: routes propagated too early ({:?} < {}s)",
                mrai_secs,
                elapsed,
                mrai_secs
            );
        }

        // Verify all UPDATEs sent
        poll_peer_stats(
            &server1,
            &server2.address.to_string(),
            ExpectedStats {
                update_sent: Some(num_routes),
                ..Default::default()
            },
        )
        .await;
    }
}

#[tokio::test]
async fn test_ipv6_peering() {
    let hold_timer_secs = 3;

    let server1 = start_test_server(Config::new(
        65001,
        "[::1]:0",
        Ipv4Addr::new(1, 1, 1, 1),
        hold_timer_secs as u64,
    ))
    .await;

    let server2 = start_test_server(Config::new(
        65002,
        "[::1]:0",
        Ipv4Addr::new(2, 2, 2, 2),
        hold_timer_secs as u64,
    ))
    .await;

    // Peer over IPv6 (both sides add peer, retry handles initial rejection)
    server1
        .client
        .add_peer(
            "::1".to_string(),
            Some(SessionConfig {
                port: Some(server2.bgp_port as u32),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    server2
        .client
        .add_peer(
            "::1".to_string(),
            Some(SessionConfig {
                port: Some(server1.bgp_port as u32),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Wait for peering to establish
    poll_until(
        || async {
            verify_peers(&server1, vec![server2.to_peer(BgpState::Established)]).await
                && verify_peers(&server2, vec![server1.to_peer(BgpState::Established)]).await
        },
        "Timeout waiting for IPv6 transport peering to establish",
    )
    .await;

    // Verify keepalive exchange works
    let expected = ExpectedStats {
        open_sent: Some(1),
        open_received: Some(1),
        min_keepalive_sent: Some(2),
        min_keepalive_received: Some(2),
        ..Default::default()
    };
    poll_peer_stats(&server1, "::1", expected).await;
    poll_peer_stats(&server2, "::1", expected).await;
}

// Table-driven test for soft reset combinations
#[tokio::test]
async fn test_reset_peer_soft() {
    struct TestCase {
        name: &'static str,
        reset_type: ResetType,
        afi: Option<Afi>,
        safi: Option<Safi>,
        // For SoftIn: server calling reset_peer, peer to verify updates on
        // For SoftOut: server calling reset_peer (also peer to verify updates on)
        reset_caller_is_server2: bool,
    }

    let test_cases = vec![
        TestCase {
            name: "soft_in_ipv4_unicast_explicit",
            reset_type: ResetType::SoftIn,
            afi: Some(Afi::Ipv4),
            safi: Some(Safi::Unicast),
            reset_caller_is_server2: true,
        },
        TestCase {
            name: "soft_in_all_negotiated",
            reset_type: ResetType::SoftIn,
            afi: None,
            safi: None,
            reset_caller_is_server2: true,
        },
        TestCase {
            name: "soft_out_ipv4_unicast_explicit",
            reset_type: ResetType::SoftOut,
            afi: Some(Afi::Ipv4),
            safi: Some(Safi::Unicast),
            reset_caller_is_server2: false,
        },
        TestCase {
            name: "soft_out_all_negotiated",
            reset_type: ResetType::SoftOut,
            afi: None,
            safi: None,
            reset_caller_is_server2: false,
        },
        TestCase {
            name: "soft_both_ipv4_unicast",
            reset_type: ResetType::Soft,
            afi: Some(Afi::Ipv4),
            safi: Some(Safi::Unicast),
            reset_caller_is_server2: false,
        },
        TestCase {
            name: "soft_both_all_negotiated",
            reset_type: ResetType::Soft,
            afi: None,
            safi: None,
            reset_caller_is_server2: false,
        },
    ];

    for tc in test_cases {
        println!("Running test case: {}", tc.name);
        let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

        // Server1 announces a route to server2
        announce_route(
            &server1,
            RouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.168.1.1".to_string(),
                ..Default::default()
            },
        )
        .await;

        // Wait for route to propagate
        poll_rib(&[(
            &server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(PathParams {
                    as_path: vec![as_sequence(vec![65001])],
                    next_hop: server1.address.to_string(),
                    peer_address: server1.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                })],
            }],
        )])
        .await;

        // Get initial stats
        let (_, s1_initial_stats) = server1
            .client
            .get_peer(server2.address.to_string())
            .await
            .unwrap();
        let s1_initial_update_sent = s1_initial_stats.unwrap().update_sent;

        let (_, s2_initial_stats) = server2
            .client
            .get_peer(server1.address.to_string())
            .await
            .unwrap();
        let s2_initial_update_received = s2_initial_stats.unwrap().update_received;

        // Execute reset based on test case
        if tc.reset_caller_is_server2 {
            // SoftIn: Server2 requests routes from server1
            server2
                .client
                .reset_peer(server1.address.to_string(), tc.reset_type, tc.afi, tc.safi)
                .await
                .unwrap();
        } else {
            // SoftOut or Soft: Server1 resends routes to server2
            server1
                .client
                .reset_peer(server2.address.to_string(), tc.reset_type, tc.afi, tc.safi)
                .await
                .unwrap();
        }

        // Verify server1 re-sent the route to server2
        poll_peer_stats(
            &server1,
            &server2.address.to_string(),
            ExpectedStats {
                min_update_sent: Some(s1_initial_update_sent + 1),
                ..Default::default()
            },
        )
        .await;

        // Verify server2 received the re-sent/re-advertised route from server1
        poll_peer_stats(
            &server2,
            &server1.address.to_string(),
            ExpectedStats {
                min_update_received: Some(s2_initial_update_received + 1),
                ..Default::default()
            },
        )
        .await;
    }
}

#[tokio::test]
async fn test_hard_reset_established() {
    // Use setup with short idle_hold_time for faster reconnect
    // Disable GR so routes are withdrawn (not marked stale) on disconnect
    let (server1, server2) = setup_two_peered_servers(PeerConfig {
        idle_hold_time_secs: Some(1),
        graceful_restart: Some(GracefulRestartConfig {
            enabled: Some(false),
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;

    // Server1 announces a route to server2
    announce_route(
        &server1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Wait for route to propagate
    poll_rib(&[(
        &server2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                as_path: vec![as_sequence(vec![65001])],
                next_hop: server1.address.to_string(),
                peer_address: server1.address.to_string(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            })],
        }],
    )])
    .await;

    // Execute hard reset on server1's peer (server2)
    server1
        .client
        .reset_peer(server2.address.to_string(), ResetType::Hard, None, None)
        .await
        .unwrap();

    // Verify route was withdrawn from server2 (hard reset sends NOTIFICATION)
    poll_route_withdrawal(&[&server2]).await;

    // Verify configured peers reconnect on both sides
    // Both sides have each other configured, so both stay as configured=true after reconnect
    poll_peers(&server1, vec![server2.to_peer(BgpState::Established)]).await;
    poll_peers(&server2, vec![server1.to_peer(BgpState::Established)]).await;

    // Verify route is automatically re-advertised after reconnection
    poll_rib(&[(
        &server2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                as_path: vec![as_sequence(vec![65001])],
                next_hop: server1.address.to_string(),
                peer_address: server1.address.to_string(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            })],
        }],
    )])
    .await;
}

#[tokio::test]
async fn test_hard_reset_non_established_error() {
    use bgpgg::config::Config;

    let server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        "127.0.0.1".parse().unwrap(),
        30,
    ))
    .await;

    // Add a peer that will never establish (no listening server, passive mode)
    server1
        .client
        .add_peer(
            "127.0.0.1".to_string(),
            Some(SessionConfig {
                passive_mode: Some(true),
                port: Some(9999),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Wait for peer to be added (will be in Idle state in passive mode)
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Try hard reset - should fail because not in Established state
    // Note: reset_peer expects IP address, not IP:PORT
    let result = server1
        .client
        .reset_peer("127.0.0.1".to_string(), ResetType::Hard, None, None)
        .await;

    assert!(
        result.is_err(),
        "Hard reset should fail on non-Established peer"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not in Established state") || err_msg.contains("Established"),
        "Error message should mention Established state requirement: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_hard_reset_peer_not_found() {
    use bgpgg::config::Config;

    let server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        "127.0.0.1".parse().unwrap(),
        30,
    ))
    .await;

    // Try hard reset on non-existent peer
    // Note: reset_peer expects IP address, not IP:PORT
    let result = server1
        .client
        .reset_peer("192.168.99.99".to_string(), ResetType::Hard, None, None)
        .await;

    assert!(
        result.is_err(),
        "Hard reset should fail on non-existent peer"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not found"),
        "Error message should mention peer not found: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_graceful_restart() {
    struct TestCase {
        name: &'static str,
        gr_enabled: bool,
        expect_routes_retained: bool,
    }

    let test_cases = vec![
        TestCase {
            name: "configured peer with GR",
            gr_enabled: true,
            expect_routes_retained: true,
        },
        TestCase {
            name: "configured peer without GR",
            gr_enabled: false,
            expect_routes_retained: false,
        },
    ];

    for tc in test_cases {
        let gr_restart_time_secs = 3;

        // Create two servers with short hold timer for faster disconnect detection
        let mut server1 = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            3, // Short hold timer for fast disconnect detection
        ))
        .await;

        let mut server2 = start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            3, // Short hold timer for fast disconnect detection
        ))
        .await;

        // Configure server2 as a passive peer
        let s2_session_config = if tc.gr_enabled {
            Some(SessionConfig {
                graceful_restart: Some(bgpgg::grpc::proto::GracefulRestartConfig {
                    enabled: Some(true),
                    restart_time_secs: Some(gr_restart_time_secs),
                }),
                passive_mode: Some(true),
                ..Default::default()
            })
        } else {
            Some(SessionConfig {
                passive_mode: Some(true),
                ..Default::default()
            })
        };

        let mut s2_cfg = s2_session_config.unwrap_or_default();
        s2_cfg.port = Some(server1.bgp_port as u32);
        server2
            .client
            .add_peer(server1.address.to_string(), Some(s2_cfg))
            .await
            .unwrap();

        let s1_session_config = if tc.gr_enabled {
            session_config_with_gr_timer(gr_restart_time_secs)
        } else {
            // Disable GR
            SessionConfig {
                graceful_restart: Some(bgpgg::grpc::proto::GracefulRestartConfig {
                    enabled: Some(false),
                    restart_time_secs: None,
                }),
                ..Default::default()
            }
        };

        let mut s1_cfg = s1_session_config;
        s1_cfg.port = Some(server2.bgp_port as u32);
        server1
            .client
            .add_peer(server2.address.to_string(), Some(s1_cfg))
            .await
            .unwrap();

        poll_peers(&server1, vec![server2.to_peer(BgpState::Established)]).await;

        // Announce route from server1 and verify it propagates to server2
        let s1_addr = server1.address.to_string();
        announce_and_verify_route(
            &server1,
            &[&server2],
            RouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.168.1.1".to_string(),
                ..Default::default()
            },
            PathParams {
                as_path: vec![as_sequence(vec![65001])],
                next_hop: s1_addr.clone(),
                peer_address: s1_addr,
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            },
        )
        .await;

        // Kill server1
        server1.kill();

        if tc.expect_routes_retained {
            // For GR: peer goes to Idle but stays in HashMap
            poll_peers(&server2, vec![server1.to_peer(BgpState::Idle)]).await;

            // Routes should be retained during GR timer
            poll_while(
                || async {
                    let Ok(routes) = server2.client.get_routes().await else {
                        return false;
                    };
                    routes.len() == 1
                },
                std::time::Duration::from_secs(1),
                &format!("{}: routes should be retained during GR timer", tc.name),
            )
            .await;

            // After GR timer, routes withdrawn
            poll_until_with_timeout(
                || async {
                    let Ok(routes) = server2.client.get_routes().await else {
                        return false;
                    };
                    routes.is_empty()
                },
                &format!(
                    "{}: timeout waiting for route withdrawal after GR timer",
                    tc.name
                ),
                50, // 5s = 3s GR timer + 2s buffer
            )
            .await;

            // Peer should still exist in Idle state (configured peers stay)
            poll_peers(&server2, vec![server1.to_peer(BgpState::Idle)]).await;
        } else {
            // No GR: Wait for peer to detect disconnect and routes to be withdrawn
            // Configured peer goes to Idle
            poll_peers_with_timeout(&server2, vec![server1.to_peer(BgpState::Idle)], 40).await;

            // Routes should be withdrawn immediately
            poll_route_withdrawal(&[&server2]).await;
        }

        server2.kill();
    }
}

/// Test BGP Graceful Restart reconnect scenario (RFC 4724)
///
/// Flow:
/// 1. Server peers with FakePeer (GR enabled, 5s timer, idle_hold=0 for fast reconnect)
/// 2. FakePeer announces route 10.0.0.0/24
/// 3. FakePeer drops TCP (simulates restart)
/// 4. Server retains route during GR timer, goes Idle, then reconnects
/// 5. FakePeer re-handshakes with R=1 (restart in progress)
/// 6. Route still retained after reconnect
#[tokio::test]
async fn test_graceful_restart_reconnect() {
    let gr_restart_time_secs = 5u32;

    // Create FakePeer listener (ephemeral port)
    let mut peer = FakePeer::new("127.0.0.1:0", 65002).await;
    let peer_port = peer.port();

    // Start server
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90, // Hold timer (longer than GR timer)
    ))
    .await;

    // Add peer with GR enabled and idle_hold_time=0 for immediate reconnect
    server
        .client
        .add_peer(
            "127.0.0.1".to_string(),
            Some(SessionConfig {
                port: Some(peer_port as u32),
                graceful_restart: Some(bgpgg::grpc::proto::GracefulRestartConfig {
                    enabled: Some(true),
                    restart_time_secs: Some(gr_restart_time_secs),
                }),
                idle_hold_time_secs: Some(0), // Reconnect immediately after TCP drop
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Accept server's connection
    peer.accept().await;

    // Read server's OPEN
    peer.read_open().await;

    // Send OPEN with GR + Multiprotocol capabilities (no R flag - normal operation)
    // Multiprotocol capability is needed for EOR to be sent after reconnect
    peer.send_open_with_gr(
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
        90,
        gr_restart_time_secs as u16,
        false,
    )
    .await;
    peer.asn = 65002;

    // Exchange KEEPALIVEs -> Established
    peer.send_keepalive().await;
    peer.read_keepalive().await;

    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;

    // Server injects route locally (source=Local) so the source-peer filter
    // won't block it when re-sending to the restarting peer.
    announce_route(
        &server,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // FakePeer receives the locally-injected route
    let initial_update = peer.read_update().await;
    assert_eq!(
        initial_update.nlri_prefixes().len(),
        1,
        "Peer should receive locally-injected route"
    );

    // Drop TCP without NOTIFICATION -> triggers GR
    drop(peer.stream.take());

    // With idle_hold=0, peer reconnects immediately - just verify it's no longer Established
    poll_until(
        || async {
            server.client.get_peers().await.ok().is_some_and(|peers| {
                peers.len() == 1 && peers[0].state != BgpState::Established as i32
            })
        },
        "peer should disconnect",
    )
    .await;

    // Route retained during GR timer (verify briefly - peer reconnects fast with idle_hold=0)
    let routes = server.client.get_routes().await.unwrap();
    assert!(
        routes.len() == 1 && routes[0].prefix == "10.0.0.0/24",
        "route should be retained during GR"
    );

    // Accept the reconnected connection (server already initiated TCP)
    peer.accept().await;

    // Read server's OPEN
    peer.read_open().await;

    // Send OPEN with GR + Multiprotocol capabilities and R flag (restart in progress)
    peer.send_open_with_gr(
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
        90,
        gr_restart_time_secs as u16,
        true,
    )
    .await;

    // Exchange KEEPALIVEs -> Established
    peer.send_keepalive().await;
    peer.read_keepalive().await;

    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;

    // RFC 4724 Section 4.2: Receiving Speaker sends full table to Restarting Speaker
    let route_update = peer.read_update().await;
    assert_eq!(
        route_update.nlri_prefixes().len(),
        1,
        "Server should send retained route to restarting peer"
    );
    assert_eq!(
        route_update.nlri_prefixes()[0].to_string(),
        "10.0.0.0/24",
        "Server should send 10.0.0.0/24 route"
    );

    // Server should send End-of-RIB marker after initial update
    use tokio::time::{timeout, Duration};
    let eor_result = timeout(Duration::from_secs(2), peer.read_update()).await;
    assert!(
        eor_result.is_ok(),
        "Server should send End-of-RIB marker after route update"
    );
    assert!(
        eor_result.unwrap().is_eor(),
        "Expected End-of-RIB marker (empty UPDATE)"
    );

    // Route still retained after reconnect
    poll_until(
        || async {
            server
                .client
                .get_routes()
                .await
                .ok()
                .is_some_and(|r| r.len() == 1 && r[0].prefix == "10.0.0.0/24")
        },
        "route should still be in RIB after reconnect",
    )
    .await;
}

/// RFC 4724 Section 4.2: When peer reconnects with F=0 (forwarding state not preserved),
/// the Receiving Speaker MUST immediately remove all stale routes.
///
/// Flow:
/// 1. Server peers with FakePeer (GR enabled with F=1)
/// 2. FakePeer announces route 10.0.0.0/24
/// 3. FakePeer drops TCP (routes marked stale)
/// 4. FakePeer reconnects with F=0 (forwarding state lost)
/// 5. Stale routes should be immediately cleared (no waiting for EOR)
#[tokio::test]
async fn test_graceful_restart_fbit_zero_clears_stale() {
    let gr_restart_time_secs = 30u32; // Long timer - we should NOT wait for it

    // Create FakePeer listener
    let mut peer = FakePeer::new("127.0.0.1:0", 65002).await;
    let peer_port = peer.port();

    // Start server
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // Add peer with GR enabled
    server
        .client
        .add_peer(
            "127.0.0.1".to_string(),
            Some(SessionConfig {
                port: Some(peer_port as u32),
                graceful_restart: Some(bgpgg::grpc::proto::GracefulRestartConfig {
                    enabled: Some(true),
                    restart_time_secs: Some(gr_restart_time_secs),
                }),
                idle_hold_time_secs: Some(0), // Reconnect immediately
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Accept server's connection
    peer.accept().await;
    peer.read_open().await;

    // Send OPEN with GR (F=1 - forwarding preserved)
    peer.send_open_with_gr_fbit(
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
        90,
        gr_restart_time_secs as u16,
        false, // R=0 (not restarting)
        true,  // F=1 (forwarding preserved)
    )
    .await;
    peer.asn = 65002;

    // Exchange KEEPALIVEs -> Established
    peer.send_keepalive().await;
    peer.read_keepalive().await;
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;

    // FakePeer announces route 10.0.0.0/24
    let update = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_2byte(vec![65002]),
            &attr_next_hop(Ipv4Addr::new(192, 168, 1, 1)),
        ],
        &[24, 10, 0, 0], // 10.0.0.0/24
        None,
    );
    peer.send_raw(&update).await;

    // Verify route in RIB
    poll_until(
        || async {
            server
                .client
                .get_routes()
                .await
                .ok()
                .is_some_and(|r| r.len() == 1 && r[0].prefix == "10.0.0.0/24")
        },
        "route should be in RIB",
    )
    .await;

    // Drop TCP without NOTIFICATION -> triggers GR, routes marked stale
    drop(peer.stream.take());
    // Wait for disconnect (don't assert specific state - with idle_hold_time=0, Idle is transient)
    poll_until(
        || async {
            server.client.get_peers().await.ok().is_some_and(|peers| {
                peers
                    .iter()
                    .any(|p| p.state != BgpState::Established as i32)
            })
        },
        "peer should disconnect",
    )
    .await;

    // Route still retained (GR timer hasn't expired)
    let routes = server.client.get_routes().await.unwrap();
    assert_eq!(routes.len(), 1, "route should be retained during GR");

    // Server reconnects
    peer.accept().await;
    peer.read_open().await;

    // Send OPEN with GR but F=0 (forwarding state LOST)
    peer.send_open_with_gr_fbit(
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
        90,
        gr_restart_time_secs as u16,
        true,  // R=1 (restarting)
        false, // F=0 (forwarding NOT preserved)
    )
    .await;

    // Exchange KEEPALIVEs -> Established
    peer.send_keepalive().await;
    peer.read_keepalive().await;
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;

    // RFC 4724: With F=0, stale routes should be immediately cleared
    // We should NOT need to wait for EOR - routes should already be gone
    poll_until(
        || async {
            server
                .client
                .get_routes()
                .await
                .ok()
                .is_some_and(|r| r.is_empty())
        },
        "stale routes should be immediately cleared when F=0",
    )
    .await;
}

/// RFC 4724: GR reconnection - when outgoing is Established with GR and new incoming
/// connection arrives, close old session and accept new (BIRD style).
#[tokio::test]
async fn test_gr_reconnection_accepts_new_connection() {
    // FakePeer listens - server will connect outgoing
    let mut peer = FakePeer::new("127.0.0.2:0", 65002).await;
    let peer_port = peer.port();

    // Start server with GR enabled
    let mut config = Config::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 90);
    config.peers.push(bgpgg::config::PeerConfig {
        address: "127.0.0.2".to_string(),
        port: peer_port,
        graceful_restart: bgpgg::config::GracefulRestartConfig {
            enabled: true,
            restart_time: 120,
        },
        ..Default::default()
    });
    let server = start_test_server(config).await;

    // Accept server's outgoing connection
    peer.accept().await;
    peer.read_open().await;

    // Send OPEN with GR capability
    peer.send_open_with_gr(65002, Ipv4Addr::new(2, 2, 2, 2), 90, 120, false)
        .await;
    peer.asn = 65002;
    peer.send_keepalive().await;
    peer.read_keepalive().await;

    // Verify Established
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;

    // Now FakePeer "restarts" - connects to server as new incoming connection
    // This simulates peer restart where old TCP is stale but server doesn't know yet
    let mut reconnecting_peer = FakePeer::connect(Some("127.0.0.2"), &server).await;

    // Server should accept the new connection (trigger GR, close old)
    // Read server's OPEN on new connection
    let open = reconnecting_peer.read_open().await;
    assert_eq!(open.asn as u32, 65001);

    // Complete handshake on new connection
    reconnecting_peer
        .send_open_with_gr(65002, Ipv4Addr::new(2, 2, 2, 2), 90, 120, true) // R=1 (restarting)
        .await;
    reconnecting_peer.asn = 65002;
    reconnecting_peer.send_keepalive().await;
    reconnecting_peer.read_keepalive().await;

    // Verify peer reaches Established on new connection
    poll_peers(
        &server,
        vec![reconnecting_peer.to_peer(BgpState::Established)],
    )
    .await;
}

/// When outgoing is Established without GR capability, new incoming connection
/// should be rejected to protect the existing session.
#[tokio::test]
async fn test_reject_incoming_when_established_no_gr() {
    // FakePeer listens - server will connect outgoing
    let mut peer = FakePeer::new("127.0.0.2:0", 65002).await;
    let peer_port = peer.port();

    // Start server with GR disabled
    let mut config = Config::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 90);
    config.peers.push(bgpgg::config::PeerConfig {
        address: "127.0.0.2".to_string(),
        port: peer_port,
        graceful_restart: bgpgg::config::GracefulRestartConfig {
            enabled: false,
            restart_time: 0,
        },
        ..Default::default()
    });
    let server = start_test_server(config).await;

    // Accept server's outgoing connection
    peer.accept().await;
    peer.read_open().await;

    // Send OPEN WITHOUT GR capability
    peer.send_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90).await;
    peer.asn = 65002;
    peer.send_keepalive().await;
    peer.read_keepalive().await;

    // Verify Established
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;

    // Now FakePeer tries to connect as new incoming connection
    let reconnecting_peer = FakePeer::connect(Some("127.0.0.2"), &server).await;

    // Server should reject - notification sent async, may or may not arrive
    use tokio::io::AsyncReadExt;
    let mut stream = reconnecting_peer.stream.unwrap();
    let mut buf = [0u8; 1024];
    let result =
        tokio::time::timeout(std::time::Duration::from_millis(500), stream.read(&mut buf)).await;

    // Should get EOF (connection closed), NOTIFICATION, or timeout
    match result {
        Ok(Ok(0)) => {} // EOF - connection closed
        Ok(Ok(n)) if n >= 19 => {
            // Got NOTIFICATION - verify it's ConnectionRejected
            assert_eq!(buf[19], 6, "Expected CEASE error code");
            assert_eq!(buf[20], 5, "Expected ConnectionRejected subcode");
        }
        Ok(Ok(_)) => panic!("Unexpected short read"),
        Ok(Err(_)) => {} // Read error - connection rejected
        Err(_) => {}     // Timeout - acceptable
    }

    // Original session should still be Established
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;
}

/// RFC 6793: Test peering establishment between peers with large ASNs
#[tokio::test]
async fn test_large_asn_peering() {
    let [s1, s2] = &mut create_asn_chain([4200000001, 4200000002], None).await;

    verify_peers(s1, vec![s2.to_peer(BgpState::Established)]).await;
    verify_peers(s2, vec![s1.to_peer(BgpState::Established)]).await;
}

/// RFC 6793 Section 4.2.1: Peering between NEW and OLD speakers
/// is only possible if NEW speaker has a two-octet AS number.
///
/// Test verifies that when local ASN > 65535, the session is rejected
/// if peer doesn't support 4-byte ASN capability (detected during OPEN exchange).
#[tokio::test]
async fn test_large_asn_requires_4byte_capability() {
    // Create server with large ASN (> 65535)
    let large_asn = 4200000001;
    let server = start_test_server(Config::new(
        large_asn,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
    ))
    .await;

    // Add peer as passive so we can connect to it
    server
        .client
        .add_peer(
            "127.0.0.1".to_string(),
            Some(SessionConfig {
                passive_mode: Some(true),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // OLD speaker connects (FakePeer will send OPEN without capability 65)
    let mut peer = FakePeer::connect(None, &server).await;

    // Read the server's OPEN message
    // Server will send AS_TRANS (23456) in wire format but also capability 65 with real ASN
    let msg = peer.read_open().await;
    // The parsed OPEN contains the real ASN from capability 65
    assert_eq!(msg.asn, large_asn);

    // OLD speaker sends OPEN without capability 65 (no optional parameters)
    // This simulates an OLD BGP speaker that doesn't understand 4-byte ASNs
    let old_speaker_open = build_raw_open(
        65002,                                // OLD speaker ASN
        300,                                  // hold_time
        u32::from(Ipv4Addr::new(2, 2, 2, 2)), // router_id
        RawOpenOptions::default(),            // No capabilities for OLD speaker
    );
    peer.send_raw(&old_speaker_open).await;

    // Server should reject the session and send NOTIFICATION
    // RFC 6793: Cannot peer with OLD speaker when local ASN > 65535
    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::OpenMessageError(OpenMessageError::UnsupportedOptionalParameter),
        "Server should reject OLD speaker when local ASN > 65535"
    );
}
