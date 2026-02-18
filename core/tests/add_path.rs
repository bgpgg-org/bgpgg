// Copyright 2026 bgpgg Authors
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
use bgpgg::grpc::proto::{BgpState, Origin, Route, SessionConfig};
use std::net::Ipv4Addr;

/// ADD-PATH config: send all paths + receive path IDs
fn addpath_config() -> SessionConfig {
    SessionConfig {
        add_path_send: Some(1),
        add_path_receive: Some(true),
        ..Default::default()
    }
}

/// Sets up the common ADD-PATH test topology:
/// S1(65001) -> S2(65002) <- S3(65003), S2 -> S4(65004) with ADD-PATH, S2 -> S5(65005) normal
///
/// Returns (s1, s2, s3, s4, s5) with all sessions Established.
async fn setup_addpath_topology() -> (TestServer, TestServer, TestServer, TestServer, TestServer) {
    let server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;
    let server2 = start_test_server(Config::new(
        65002,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
    ))
    .await;
    let server3 = start_test_server(Config::new(
        65003,
        "127.0.0.3:0",
        Ipv4Addr::new(3, 3, 3, 3),
        90,
    ))
    .await;
    let server4 = start_test_server(Config::new(
        65004,
        "127.0.0.4:0",
        Ipv4Addr::new(4, 4, 4, 4),
        90,
    ))
    .await;
    let server5 = start_test_server(Config::new(
        65005,
        "127.0.0.5:0",
        Ipv4Addr::new(5, 5, 5, 5),
        90,
    ))
    .await;

    // S1 <-> S2 (normal eBGP)
    server1.add_peer(&server2).await;
    server2.add_peer(&server1).await;

    // S3 <-> S2 (normal eBGP)
    server3.add_peer(&server2).await;
    server2.add_peer(&server3).await;

    // S2 <-> S4 with ADD-PATH (both sides need ADD-PATH config for negotiation)
    server2
        .add_peer_with_config(&server4, addpath_config())
        .await;
    server4
        .add_peer_with_config(&server2, addpath_config())
        .await;

    // S2 <-> S5 normal eBGP
    server2.add_peer(&server5).await;
    server5.add_peer(&server2).await;

    // Wait for all sessions to reach Established
    for (server, expected_count) in [
        (&server1, 1),
        (&server2, 4),
        (&server3, 1),
        (&server4, 1),
        (&server5, 1),
    ] {
        poll_until(
            || async {
                let Ok(peers) = server.client.get_peers().await else {
                    return false;
                };
                peers
                    .iter()
                    .filter(|peer| peer.state == BgpState::Established as i32)
                    .count()
                    == expected_count
            },
            &format!(
                "Timeout waiting for {} Established peers on AS{}",
                expected_count, server.asn
            ),
        )
        .await;
    }

    (server1, server2, server3, server4, server5)
}

/// S1 and S3 announce same prefix to S2. S4 (ADD-PATH) should see 2 paths,
/// S5 (normal) should see only 1 (best path).
#[tokio::test]
async fn test_addpath_multiple_paths() {
    let (server1, server2, server3, server4, server5) = setup_addpath_topology().await;
    let server2_addr = server2.address.to_string();

    // S1 announces 10.0.0.0/24
    announce_route(
        &server1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // S3 announces 10.0.0.0/24
    announce_route(
        &server3,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.3.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // S4 (ADD-PATH) should see 2 paths with distinct path_ids.
    // Both have next_hop=S2 (eBGP next_hop rewrite), distinguished by AS path.
    poll_rib_addpath(&[(
        &server4,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65002, 65001])],
                    next_hop: server2_addr.clone(),
                    peer_address: server2_addr.clone(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65002, 65003])],
                    next_hop: server2_addr.clone(),
                    peer_address: server2_addr.clone(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
            ],
        }],
    )])
    .await;

    // S5 (normal) should see only 1 path (best — S1's path wins by lower BGP ID 1.1.1.1)
    poll_rib(&[(
        &server5,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                as_path: vec![as_sequence(vec![65002, 65001])],
                next_hop: server2_addr.clone(),
                peer_address: server2_addr,
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            })],
        }],
    )])
    .await;
}

/// Both announce, then S1 withdraws. S4 (ADD-PATH) should drop to 1 path,
/// S5 (normal) should still have 1 path.
#[tokio::test]
async fn test_addpath_withdraw() {
    let (server1, server2, server3, server4, server5) = setup_addpath_topology().await;
    let server2_addr = server2.address.to_string();

    // Both announce 10.0.0.0/24
    announce_route(
        &server1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;
    announce_route(
        &server3,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.3.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Wait for S4 to have 2 paths
    poll_rib_addpath(&[(
        &server4,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65002, 65001])],
                    next_hop: server2_addr.clone(),
                    peer_address: server2_addr.clone(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65002, 65003])],
                    next_hop: server2_addr.clone(),
                    peer_address: server2_addr.clone(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
            ],
        }],
    )])
    .await;

    // S1 withdraws
    server1
        .client
        .remove_route("10.0.0.0/24".to_string())
        .await
        .unwrap();

    // S4 (ADD-PATH) should drop to 1 path (S3's)
    poll_rib_addpath(&[(
        &server4,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                as_path: vec![as_sequence(vec![65002, 65003])],
                next_hop: server2_addr.clone(),
                peer_address: server2_addr.clone(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            })],
        }],
    )])
    .await;

    // S5 (normal) should have S3's path (now the only and best)
    poll_rib(&[(
        &server5,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                as_path: vec![as_sequence(vec![65002, 65003])],
                next_hop: server2_addr.clone(),
                peer_address: server2_addr,
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            })],
        }],
    )])
    .await;
}

/// Both announce, then S2 removes peer S1. S4 (ADD-PATH) should drop to 1 path (S3's).
#[tokio::test]
async fn test_addpath_peer_disconnect() {
    let (server1, server2, server3, server4, _) = setup_addpath_topology().await;
    let server2_addr = server2.address.to_string();

    // Both announce 10.0.0.0/24
    announce_route(
        &server1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;
    announce_route(
        &server3,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.3.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Wait for S4 to have 2 paths
    poll_rib_addpath(&[(
        &server4,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65002, 65001])],
                    next_hop: server2_addr.clone(),
                    peer_address: server2_addr.clone(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65002, 65003])],
                    next_hop: server2_addr.clone(),
                    peer_address: server2_addr.clone(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
            ],
        }],
    )])
    .await;

    // S2 removes peer S1 — triggers bulk path removal
    server2.remove_peer(&server1).await;

    // S4 should drop to 1 path (S3's)
    poll_rib_addpath(&[(
        &server4,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                as_path: vec![as_sequence(vec![65002, 65003])],
                next_hop: server2_addr.clone(),
                peer_address: server2_addr,
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            })],
        }],
    )])
    .await;
}

/// Route reflector with ADD-PATH: RR reflects both client paths to each client.
/// BUG: ORIGINATOR_ID loop rejection doesn't scope to path_id, withdraws valid paths too.
/// See addpath.md "Known Bug: ADD-PATH + Route Reflector Loop Rejection".
#[tokio::test]
#[ignore]
async fn test_addpath_route_reflector() {
    // All iBGP (same ASN 65001)
    let route_reflector = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;
    let client1 = start_test_server(Config::new(
        65001,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
    ))
    .await;
    let client2 = start_test_server(Config::new(
        65001,
        "127.0.0.3:0",
        Ipv4Addr::new(3, 3, 3, 3),
        90,
    ))
    .await;

    // RR peers with clients using rr_client + ADD-PATH
    let rr_addpath_config = SessionConfig {
        rr_client: Some(true),
        add_path_send: Some(1),
        add_path_receive: Some(true),
        ..Default::default()
    };

    route_reflector
        .add_peer_with_config(&client1, rr_addpath_config)
        .await;
    route_reflector
        .add_peer_with_config(&client2, rr_addpath_config)
        .await;

    // Clients peer with RR using ADD-PATH (no rr_client from client side)
    client1
        .add_peer_with_config(&route_reflector, addpath_config())
        .await;
    client2
        .add_peer_with_config(&route_reflector, addpath_config())
        .await;

    // Wait for Established
    poll_until(
        || async {
            let Ok(peers) = route_reflector.client.get_peers().await else {
                return false;
            };
            peers
                .iter()
                .filter(|peer| peer.state == BgpState::Established as i32)
                .count()
                == 2
        },
        "Timeout waiting for RR peers to reach Established",
    )
    .await;

    let rr_addr = route_reflector.address.to_string();

    // Client1 announces 10.0.0.0/24
    announce_route(
        &client1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Client2 announces 10.0.0.0/24
    announce_route(
        &client2,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.2.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Client1 should see Client2's path reflected by RR (iBGP: next_hop preserved)
    poll_rib_addpath(&[(
        &client1,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                next_hop: "192.168.2.1".to_string(),
                peer_address: rr_addr.clone(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            })],
        }],
    )])
    .await;

    // Client2 should see Client1's path reflected by RR
    poll_rib_addpath(&[(
        &client2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                next_hop: "192.168.1.1".to_string(),
                peer_address: rr_addr,
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            })],
        }],
    )])
    .await;
}
