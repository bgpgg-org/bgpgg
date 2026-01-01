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

//! Tests for BGP CEASE notifications and connection collision detection per RFC 4271 Sections 6.7, 6.8

mod common;
pub use common::*;

use bgpgg::bgp::msg_notification::{BgpError, CeaseSubcode};
use bgpgg::config::{Config, PeerConfig};
use bgpgg::grpc::proto::{
    AdminState, BgpState, MaxPrefixAction, MaxPrefixSetting, Origin as ProtoOrigin, Peer,
    SessionConfig,
};
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_max_prefix_limit() {
    // (name, action, allow_automatic_stop, expect_disconnect)
    let test_cases = vec![
        // Terminate with allow_automatic_stop=true: disconnects
        ("terminate", MaxPrefixAction::Terminate as i32, None, true),
        // Discard: stays connected
        ("discard", MaxPrefixAction::Discard as i32, None, false),
        // Terminate with allow_automatic_stop=false: stays connected
        (
            "terminate_no_auto_stop",
            MaxPrefixAction::Terminate as i32,
            Some(false),
            false,
        ),
    ];

    for (name, action, allow_automatic_stop, expect_disconnect) in test_cases {
        // Server1: will inject routes
        let mut server1 = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
            true,
        ))
        .await;

        // Server2: will receive routes with max_prefix limit
        let mut server2 = start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            300,
            true,
        ))
        .await;

        // Server2 connects to Server1 with max_prefix limit of 2
        server2
            .client
            .add_peer(
                format!("127.0.0.1:{}", server1.bgp_port),
                Some(SessionConfig {
                    max_prefix: Some(MaxPrefixSetting { limit: 2, action }),
                    allow_automatic_stop,
                    ..Default::default()
                }),
            )
            .await
            .expect("Failed to add peer");

        // Wait for peering to establish
        poll_until(
            || async {
                verify_peers(&server2, vec![server1.to_peer(BgpState::Established, true)]).await
            },
            "Timeout waiting for peering",
        )
        .await;

        // Server1 adds 3 routes (exceeds limit of 2)
        for i in 0..3 {
            server1
                .client
                .add_route(
                    format!("10.{}.0.0/24", i),
                    "1.1.1.1".to_string(),
                    ProtoOrigin::Igp,
                    vec![],
                    None,
                    None,
                    false,
                    vec![],
                )
                .await
                .expect("Failed to add route");
        }

        if expect_disconnect {
            // Terminate: session should be closed (CEASE sent), configured peer stays in Idle
            // AdminState is set to PrefixLimitReached which maps to admin_down=true
            poll_until(
                || async {
                    verify_peers(
                        &server2,
                        vec![Peer {
                            address: server1.address.clone(),
                            asn: server1.asn as u32,
                            state: BgpState::Idle.into(),
                            admin_state: AdminState::PrefixLimitExceeded.into(),
                            configured: true,
                        }],
                    )
                    .await
                },
                &format!("Test case {}: timeout waiting for peer to go Idle", name),
            )
            .await;
        } else {
            // Discard: peer stays connected, routes are limited
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            assert!(
                verify_peers(&server2, vec![server1.to_peer(BgpState::Established, true)]).await,
                "Test case {}: peer should remain established",
                name
            );

            // Verify no CEASE notification was sent
            poll_peer_stats(
                &server2,
                &server1.address,
                ExpectedStats {
                    notification_sent: Some(0),
                    ..Default::default()
                },
            )
            .await;

            let routes = server2
                .client
                .get_routes()
                .await
                .expect("Failed to get routes");
            assert!(
                routes.len() <= 2,
                "Test case {}: should have at most 2 routes, got {}",
                name,
                routes.len()
            );
        }
    }
}

#[tokio::test]
async fn test_remove_peer_sends_cease_notification() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

    poll_until(
        || async { verify_peers(&server, vec![peer.to_peer(BgpState::Established, false)]).await },
        "Timeout waiting for peer to establish",
    )
    .await;

    server
        .client
        .remove_peer(peer.address.clone())
        .await
        .expect("Failed to remove peer");

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::Cease(CeaseSubcode::PeerDeconfigured)
    );
}

#[tokio::test]
async fn test_disable_peer_sends_admin_shutdown() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

    poll_until(
        || async { verify_peers(&server, vec![peer.to_peer(BgpState::Established, false)]).await },
        "Timeout waiting for peer to establish",
    )
    .await;

    server
        .client
        .disable_peer(peer.address.clone())
        .await
        .expect("Failed to disable peer");

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::Cease(CeaseSubcode::AdministrativeShutdown)
    );
}

/// RFC 4271 Section 6.8: Connection Collision Detection
/// local < remote -> close existing, accept new
#[tokio::test]
async fn test_collision_local_lower_bgp_id() {
    // Server BGP ID 1.1.1.1 (lower than peer's 2.2.2.2)
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;

    // Peer 1: connect and reach OpenConfirm
    let mut peer1 = FakePeer::connect(Some("127.0.0.3"), &server).await;
    peer1
        .handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;

    poll_until(
        || async { verify_peers(&server, vec![peer1.to_peer(BgpState::OpenConfirm, false)]).await },
        "Timeout waiting for peer1 to reach OpenConfirm",
    )
    .await;

    // Peer 2: collision - since local < remote, existing (peer1) closed, new (peer2) wins
    let mut peer2 = FakePeer::connect(Some("127.0.0.3"), &server).await;
    peer2
        .handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;

    // Verify peer1 received NOTIFICATION with ConnectionCollisionResolution
    let notif = peer1.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::Cease(CeaseSubcode::ConnectionCollisionResolution),
        "peer1 should receive ConnectionCollisionResolution"
    );

    // Complete handshake on peer2 (the winner)
    peer2.send_keepalive().await;

    // Verify peer2 is Established (same address as peer1 since same IP)
    poll_until(
        || async { verify_peers(&server, vec![peer2.to_peer(BgpState::Established, false)]).await },
        "Timeout waiting for peer2 to reach Established",
    )
    .await;
}

/// RFC 4271 Section 6.8: Connection Collision Detection in OpenConfirm state
#[tokio::test]
async fn test_collision_openconfirm() {
    let test_cases = vec![
        // (server_bgp_id, peer_bgp_id, existing_kept)
        (Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(1, 1, 1, 1), true), // local >= remote -> keep existing
        (Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(3, 3, 3, 3), false), // local < remote -> accept new
    ];

    for (server_bgp_id, peer_bgp_id, existing_kept) in test_cases {
        let server =
            start_test_server(Config::new(65001, "127.0.0.1:0", server_bgp_id, 300, true)).await;

        // Peer 1: connect and reach OpenConfirm
        let mut peer1 = FakePeer::connect(Some("127.0.0.3"), &server).await;
        peer1.handshake_open(65002, peer_bgp_id, 300).await;

        poll_until(
            || async {
                verify_peers(&server, vec![peer1.to_peer(BgpState::OpenConfirm, false)]).await
            },
            "Timeout waiting for peer1 to reach OpenConfirm",
        )
        .await;

        // Peer 2: collision from same IP
        let mut peer2 = FakePeer::connect(Some("127.0.0.3"), &server).await;

        if existing_kept {
            // local >= remote -> existing kept, new rejected
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            assert!(
                verify_peers(&server, vec![peer1.to_peer(BgpState::OpenConfirm, false)]).await,
                "peer1 should still be in OpenConfirm"
            );
        } else {
            // local < remote -> existing closed, new accepted
            // peer1 receives NOTIFICATION
            let notif = peer1.read_notification().await;
            assert_eq!(
                notif.error(),
                &BgpError::Cease(CeaseSubcode::ConnectionCollisionResolution)
            );

            // Complete handshake on peer2
            peer2.read_open().await;
            peer2.send_open(65002, peer_bgp_id, 300).await;
            peer2.read_keepalive().await;
            peer2.send_keepalive().await;

            // Verify peer2 reaches Established
            poll_until(
                || async {
                    let peers = server.client.get_peers().await.unwrap();
                    peers.len() == 1 && peers[0].state == BgpState::Established as i32
                },
                "Timeout waiting for peer2 to reach Established",
            )
            .await;
        }
    }
}

/// RFC 4271 8.1.1 Option 5: CollisionDetectEstablishedState
/// By default (false), collision detection is ignored in Established state.
#[tokio::test]
async fn test_collision_ignored_in_established() {
    // server1 and server2 peer and reach Established
    let (server1, server2) = setup_two_peered_servers(None).await;

    // server3 on same IP as server2 tries to connect to server1 - triggers collision
    let mut config3 = Config::new(65003, "127.0.0.2:0", Ipv4Addr::new(3, 3, 3, 3), 90, true);
    config3.peers.push(PeerConfig {
        address: format!("{}:{}", server1.address, server1.bgp_port),
        ..Default::default()
    });
    let _server3 = start_test_server(config3).await;

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Original peer should still be Established (collision ignored by default)
    // server1 connected to server2 (configured from server1's view)
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established, true)],).await);
}

/// RFC 4271 6.8: Deferred collision detection for outgoing connections
/// When server has outgoing in OpenSent (no BGP ID), incoming is deferred until OPEN received.
#[tokio::test]
async fn test_collision_deferred() {
    let test_cases = vec![
        // (server_bgp_id, peer_bgp_id, outgoing_wins)
        (Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(1, 1, 1, 1), true), // outgoing wins
        (Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(3, 3, 3, 3), false), // incoming wins
    ];

    for (server_bgp_id, peer_bgp_id, outgoing_wins) in test_cases {
        // Peer listens at 127.0.0.3, server will connect to it
        let mut peer = FakePeer::new("127.0.0.3:0", 65002).await;
        let listener_addr = format!("127.0.0.3:{}", peer.port());

        let mut config = Config::new(65001, "127.0.0.1:0", server_bgp_id, 300, true);
        config.peers.push(PeerConfig {
            address: listener_addr.to_string(),
            ..Default::default()
        });
        let server = start_test_server(config).await;

        // Accept server's outbound connection (server sends OPEN, but we don't read it yet)
        peer.accept().await;

        // Server is in OpenSent (sent OPEN, waiting for response)
        poll_until(
            || async {
                let peers = server.client.get_peers().await.unwrap();
                peers.len() == 1 && peers[0].state == BgpState::OpenSent as i32
            },
            "Timeout waiting for OpenSent",
        )
        .await;

        // Same peer initiates connection to server - triggers deferred collision (no BGP ID yet)
        let mut incoming_stream = peer.connect_to(&server).await;

        // Now exchange OPENs on first connection - server learns BGP ID and resolves collision
        peer.read_open().await;
        peer.send_open(65002, peer_bgp_id, 300).await;

        if outgoing_wins {
            // Complete handshake on outgoing connection
            peer.send_keepalive().await;
            peer.read_keepalive().await;

            // Outgoing wins, collision dropped, session reaches Established
            poll_until(
                || async {
                    let peers = server.client.get_peers().await.unwrap();
                    peers.len() == 1 && peers[0].state == BgpState::Established as i32
                },
                "Timeout waiting for Established (outgoing wins)",
            )
            .await;

            drop(incoming_stream);
        } else {
            // Incoming wins - server closes outgoing (peer gets NOTIFICATION), switches to incoming
            // Complete handshake on incoming connection
            // Wrap incoming_stream in FakePeer to use helper methods
            let mut incoming_peer = FakePeer {
                stream: Some(incoming_stream),
                address: "127.0.0.3".to_string(),
                asn: 65002,
                listener: None,
            };

            incoming_peer.read_open().await;
            incoming_peer.send_open(65002, peer_bgp_id, 300).await;
            incoming_peer.read_keepalive().await;
            incoming_peer.send_keepalive().await;

            incoming_stream = incoming_peer.stream.take().unwrap();

            // Incoming wins, session reaches Established
            poll_until(
                || async {
                    let peers = server.client.get_peers().await.unwrap();
                    peers.len() == 1 && peers[0].state == BgpState::Established as i32
                },
                "Timeout waiting for Established (incoming wins)",
            )
            .await;

            drop(incoming_stream);
        }
    }
}
