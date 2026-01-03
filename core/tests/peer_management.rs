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

//! Tests for peer management: add, remove, configure, passive mode, delay open, manual stop, MRAI

mod utils;
pub use utils::*;

use bgpgg::bgp::msg_notification::{BgpError, CeaseSubcode};
use bgpgg::config::Config;
use bgpgg::grpc::proto::{AdminState, BgpState, Origin, Route, SessionConfig};
use std::net::Ipv4Addr;

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
            vec![],
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
                &server2.address.to_string(),
                peer_addr.clone(),
                Origin::Igp,
                Some(100),
                None,
                false,
                vec![],
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
            vec![],
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
                &server2.address.to_string(), // eBGP: NEXT_HOP rewritten to sender's local address
                peer_addr.clone(),
                Origin::Igp,
                Some(100),
                None,
                false,
                vec![],
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
            vec![],
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
                    &server4.address.to_string(), // eBGP: NEXT_HOP rewritten to sender's local address
                    server4.address.to_string(),
                    Origin::Igp,
                    Some(100),
                    None,
                    false,
                    vec![],
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
                    &server4.address.to_string(), // eBGP: NEXT_HOP rewritten to sender's local address
                    server4.address.to_string(),
                    Origin::Igp,
                    Some(100),
                    None,
                    false,
                    vec![],
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
                    &server4.address.to_string(), // eBGP: NEXT_HOP rewritten to sender's local address
                    server4.address.to_string(),
                    Origin::Igp,
                    Some(100),
                    None,
                    false,
                    vec![],
                    vec![],
                )],
            }],
        ),
    ])
    .await;

    // Remove Server4's peer from Server1 via API call
    server1
        .client
        .remove_peer(server4.address.to_string())
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
                        &server2.address.to_string(), // eBGP: NEXT_HOP rewritten to sender's local address
                        server2.address.to_string(),
                        Origin::Igp,
                        Some(100),
                        None,
                        false,
                        vec![],
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
                        &server4.address.to_string(), // eBGP: NEXT_HOP rewritten to sender's local address
                        server4.address.to_string(),
                        Origin::Igp,
                        Some(100),
                        None,
                        false,
                        vec![],
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
                        &server4.address.to_string(), // eBGP: NEXT_HOP rewritten to sender's local address
                        server4.address.to_string(),
                        Origin::Igp,
                        Some(100),
                        None,
                        false,
                        vec![],
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
        .disable_peer(server2.address.to_string())
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
    configured_peer
        .handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90)
        .await;
    configured_peer.handshake_keepalive().await;
    poll_peers(
        &server,
        vec![configured_peer.to_peer(BgpState::Established, true)],
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

/// Test ManualStop transitions to Idle from any state (RFC 4271 8.2.2)
#[tokio::test]
async fn test_manual_stop() {
    let test_cases = vec![
        (BgpState::Connect, Some(60)),
        (BgpState::OpenSent, None),
        (BgpState::OpenConfirm, None),
        (BgpState::Established, None),
    ];

    for (starting_state, delay_open_time_secs) in test_cases {
        let mut server = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
            true,
        ))
        .await;

        let mut fake_peer = FakePeer::new("127.0.0.2:0", 65002).await;
        let port = fake_peer.port();

        server
            .client
            .add_peer(
                format!("127.0.0.2:{}", port),
                delay_open_time_secs.map(|secs| SessionConfig {
                    delay_open_time_secs: Some(secs),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();

        fake_peer.accept().await;

        // Move peer to the target state
        match starting_state {
            BgpState::Connect => {
                // DelayOpen keeps server in Connect
            }
            BgpState::OpenSent => {
                // Server sends OPEN and enters OpenSent
            }
            BgpState::OpenConfirm => {
                fake_peer
                    .accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
                    .await;
            }
            BgpState::Established => {
                fake_peer
                    .accept_handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
                    .await;
                fake_peer.handshake_keepalive().await;
            }
            _ => continue,
        }

        // Wait for peer to reach starting state
        poll_until(
            || async {
                let peers = server.client.get_peers().await.unwrap_or_default();
                peers.len() == 1 && peers[0].state == starting_state as i32
            },
            &format!("Timeout waiting for {:?}", starting_state),
        )
        .await;

        // Send ManualStop
        server
            .client
            .disable_peer(fake_peer.address.to_string())
            .await
            .expect("Failed to disable peer");

        // Verify transition to Idle
        poll_until(
            || async {
                let peers = server.client.get_peers().await.unwrap_or_default();
                peers.len() == 1
                    && peers[0].state == BgpState::Idle as i32
                    && peers[0].admin_state == AdminState::Down as i32
            },
            &format!("ManualStop from {:?} -> Idle", starting_state),
        )
        .await;
    }
}
