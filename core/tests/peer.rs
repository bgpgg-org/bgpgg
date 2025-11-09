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

use bgpgg::grpc::proto::{BgpState, Origin, Path, Peer, Route};

#[tokio::test]
async fn test_peer_down() {
    let hold_timer_secs = 3;
    let (server1, mut server2) = setup_two_peered_servers(Some(hold_timer_secs)).await;

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

    // Kill Server2 to simulate peer going down (drops runtime, killing ALL tasks)
    server2.kill();

    // Give some time for Server1 to detect the disconnection
    // With a 3-second hold time, the peer should be detected as down
    // when the next keepalive fails (keepalive is sent every hold_time/3 = 1 second)
    tokio::time::sleep(tokio::time::Duration::from_secs(
        (hold_timer_secs + 2).into(),
    ))
    .await;

    // Poll for route withdrawal - route should be withdrawn when peer goes down
    poll_route_withdrawal(&[&server1]).await;

    // Verify Server1 has no peers in Established state anymore
    assert!(verify_peers(&server1, vec![]).await);
}

#[tokio::test]
async fn test_peer_down_four_node_mesh() {
    let hold_timer_secs = 3;
    let (mut server1, server2, server3, mut server4) =
        setup_four_meshed_servers(Some(hold_timer_secs)).await;

    // Server1 announces a route
    server1
        .client
        .announce_route("10.1.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route to propagate to all peers
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

    // Kill Server4 to simulate peer going down
    server4.kill();

    // Give time for other servers to detect Server4 is down
    tokio::time::sleep(tokio::time::Duration::from_secs(
        (hold_timer_secs + 2).into(),
    ))
    .await;

    // Verify Server2 and Server3 still have the route (learned from Server1, not Server4)
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

    // Verify all servers have correct peers after Server4 goes down
    // Peers are now identified by IP address only (no port)
    assert!(
        verify_peers(
            &server1,
            vec![
                Peer {
                    address: server2.address.clone(),
                    asn: server2.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server3.address.clone(),
                    asn: server3.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![
                Peer {
                    address: server1.address.clone(),
                    asn: server1.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server3.address.clone(),
                    asn: server3.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server3,
            vec![
                Peer {
                    address: server1.address.clone(),
                    asn: server1.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server2.address.clone(),
                    asn: server2.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
}

#[tokio::test]
async fn test_remove_peer() {
    let hold_timer_secs = 3;
    let (mut server1, mut server2) = setup_two_peered_servers(Some(hold_timer_secs)).await;

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
        .announce_route("10.2.0.0/24".to_string(), "192.168.2.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 2");

    // Get the actual peer address
    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    // Poll for route to appear in Server1's RIB
    poll_route_propagation(&[(
        &server1,
        vec![Route {
            prefix: "10.2.0.0/24".to_string(),
            paths: vec![Path {
                origin: Origin::Igp.into(),
                as_path: vec![65002],
                next_hop: "192.168.2.1".to_string(),
                peer_address: peer_addr.clone(),
                local_pref: Some(100),
                med: None,
            }],
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
        .announce_route("10.4.0.0/24".to_string(), "192.168.4.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 4");

    // Poll for route to propagate to all peers
    poll_route_propagation(&[
        (
            &server1,
            vec![Route {
                prefix: "10.4.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65004],
                    next_hop: "192.168.4.1".to_string(),
                    peer_address: server4.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
        (
            &server2,
            vec![Route {
                prefix: "10.4.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65004],
                    next_hop: "192.168.4.1".to_string(),
                    peer_address: server4.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.4.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65004],
                    next_hop: "192.168.4.1".to_string(),
                    peer_address: server4.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
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
    poll_route_propagation(&[
        (
            &server1,
            vec![Route {
                prefix: "10.4.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65002, 65004], // Via server2 (127.0.0.2 < 127.0.0.3)
                    next_hop: "192.168.4.1".to_string(),
                    peer_address: server2.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
        (
            &server2,
            vec![Route {
                prefix: "10.4.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65004],
                    next_hop: "192.168.4.1".to_string(),
                    peer_address: server4.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.4.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65004],
                    next_hop: "192.168.4.1".to_string(),
                    peer_address: server4.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
    ])
    .await;

    // Verify Server1 no longer has Server4 as a peer
    assert!(
        verify_peers(
            &server1,
            vec![
                Peer {
                    address: server2.address.clone(),
                    asn: server2.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server3.address.clone(),
                    asn: server3.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
}

#[tokio::test]
async fn test_peer_up() {
    let hold_timer_secs = 3;
    let (server1, server2) = setup_two_peered_servers(Some(hold_timer_secs)).await;

    // Wait for 3x hold timer to ensure multiple keepalives are exchanged and the connection stays up
    tokio::time::sleep(tokio::time::Duration::from_secs(hold_timer_secs as u64 * 3)).await;

    // Verify both peers are still in Established state
    assert!(
        verify_peers(
            &server1,
            vec![Peer {
                address: server2.address.clone(),
                asn: server2.asn as u32,
                state: BgpState::Established.into(),
            }],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![Peer {
                address: server1.address.clone(),
                asn: server1.asn as u32,
                state: BgpState::Established.into(),
            }],
        )
        .await
    );
}

#[tokio::test]
async fn test_peer_up_four_node_mesh() {
    let hold_timer_secs = 3;
    let (server1, server2, server3, server4) =
        setup_four_meshed_servers(Some(hold_timer_secs)).await;

    // Wait for 3x hold timer to ensure multiple keepalives are exchanged and the connections stay up
    tokio::time::sleep(tokio::time::Duration::from_secs(hold_timer_secs as u64 * 3)).await;

    // Verify all peers are still in Established state
    assert!(
        verify_peers(
            &server1,
            vec![
                Peer {
                    address: server2.address.clone(),
                    asn: server2.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server3.address.clone(),
                    asn: server3.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server4.address.clone(),
                    asn: server4.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![
                Peer {
                    address: server1.address.clone(),
                    asn: server1.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server3.address.clone(),
                    asn: server3.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server4.address.clone(),
                    asn: server4.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server3,
            vec![
                Peer {
                    address: server1.address.clone(),
                    asn: server1.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server2.address.clone(),
                    asn: server2.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server4.address.clone(),
                    asn: server4.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server4,
            vec![
                Peer {
                    address: server1.address.clone(),
                    asn: server1.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server2.address.clone(),
                    asn: server2.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server3.address.clone(),
                    asn: server3.asn as u32,
                    state: BgpState::Established.into(),
                },
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
    for _ in 0..crash_count {
        // Kill Server2 (simulates crash)
        server2.kill();

        // Wait a bit before restarting
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

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
            .add_peer(format!("127.0.0.1:{}", server2_port))
            .await
            .expect("Failed to re-add peer after crash");

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Wait for peers to re-establish after the final crash and recovery
    poll_until(
        || async {
            verify_peers(
                &server1,
                vec![Peer {
                    address: server2.address.clone(),
                    asn: server2.asn as u32,
                    state: BgpState::Established.into(),
                }],
            )
            .await
                && verify_peers(
                    &server2,
                    vec![Peer {
                        address: server1.address.clone(),
                        asn: server1.asn as u32,
                        state: BgpState::Established.into(),
                    }],
                )
                .await
        },
        "Timeout waiting for peers to re-establish after crash and recovery",
    )
    .await;
}
