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
use bgpgg::grpc::proto::{AddPathSendMode, BgpState, Origin, Route, SessionConfig};
use std::net::Ipv4Addr;

/// ADD-PATH config: send all paths + receive path IDs
fn addpath_config() -> SessionConfig {
    SessionConfig {
        add_path_send: Some(AddPathSendMode::AddPathSendAll.into()),
        add_path_receive: Some(true),
        ..Default::default()
    }
}

/// Sets up the common ADD-PATH test topology:
///
///   S1(65001) ---\
///                 +---> S3(65003) ---[ADD-PATH send]---> S4(65004)
///   S2(65002) ---/    (ADD-PATH recv)      |
///                                          +----[normal]---> S5(65005)
///
/// S1 and S2 originate routes. S3 collects and forwards to S4 (ADD-PATH) and S5 (normal).
/// Returns (s1, s2, s3, s4, s5) with all sessions Established.
async fn setup_addpath_topology() -> (TestServer, TestServer, TestServer, TestServer, TestServer) {
    let server1 = start_test_server(test_config(65001, 1)).await;
    let server2 = start_test_server(test_config(65002, 2)).await;
    let server3 = start_test_server(test_config(65003, 3)).await;
    let server4 = start_test_server(test_config(65004, 4)).await;
    let server5 = start_test_server(test_config(65005, 5)).await;

    peer_servers(&server1, &server3).await;
    peer_servers(&server2, &server3).await;
    peer_servers_with_config(&server3, &server4, addpath_config()).await;
    peer_servers(&server3, &server5).await;

    (server1, server2, server3, server4, server5)
}

/// S1 and S2 announce 10.0.0.0/24, validates:
/// - S3 loc-rib has both paths (one from each originator)
/// - S4 (ADD-PATH) receives both paths with distinct path_ids
/// - S5 (normal) receives only the best path (S1 wins by lower BGP ID)
async fn send_and_validate_addpath_routes(
    server1: &TestServer,
    server2: &TestServer,
    server3: &TestServer,
    server4: &TestServer,
    server5: &TestServer,
) {
    let server3_addr = server3.address.to_string();
    for (server, next_hop) in [(server1, "192.168.1.1"), (server2, "192.168.2.1")] {
        announce_route(
            server,
            RouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: next_hop.to_string(),
                ..Default::default()
            },
        )
        .await;
    }

    // S3 loc-rib: both paths from S1 and S2
    poll_rib(&[(
        server3,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65001])],
                    next_hop: server1.address.to_string(),
                    peer_address: server1.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65002])],
                    next_hop: server2.address.to_string(),
                    peer_address: server2.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
            ],
        }],
    )])
    .await;

    // S4 (ADD-PATH): both paths with distinct path_ids, next_hop=S3 (eBGP rewrite)
    poll_rib_addpath(&[(
        server4,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65003, 65001])],
                    next_hop: server3_addr.clone(),
                    peer_address: server3_addr.clone(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65003, 65002])],
                    next_hop: server3_addr.clone(),
                    peer_address: server3_addr.clone(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
            ],
        }],
    )])
    .await;

    // S5 (normal): only best path (S1 wins by lower BGP ID 1.1.1.1)
    poll_rib(&[(
        server5,
        expected_single_path(&server3_addr, vec![65003, 65001]),
    )])
    .await;
}

/// Expected rib: single path for 10.0.0.0/24 via S3 with given AS path.
fn expected_single_path(server3_addr: &str, as_path: Vec<u32>) -> Vec<Route> {
    vec![Route {
        prefix: "10.0.0.0/24".to_string(),
        paths: vec![build_path(PathParams {
            as_path: vec![as_sequence(as_path)],
            next_hop: server3_addr.to_string(),
            peer_address: server3_addr.to_string(),
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            ..Default::default()
        })],
    }]
}

/// S1 and S2 announce same prefix to S3. Validates ADD-PATH (S4 gets both paths)
/// vs normal (S5 gets only best).
#[tokio::test]
async fn test_addpath_multiple_paths() {
    let (server1, server2, server3, server4, server5) = setup_addpath_topology().await;
    send_and_validate_addpath_routes(&server1, &server2, &server3, &server4, &server5).await;
}

/// Both announce, then S1 withdraws. S4 (ADD-PATH) should drop to 1 path,
/// S5 (normal) should still have 1 path.
#[tokio::test]
async fn test_addpath_withdraw() {
    let (server1, server2, server3, server4, server5) = setup_addpath_topology().await;
    let server3_addr = server3.address.to_string();

    send_and_validate_addpath_routes(&server1, &server2, &server3, &server4, &server5).await;

    server1
        .client
        .remove_route("10.0.0.0/24".to_string())
        .await
        .unwrap();

    // S4 (ADD-PATH) should drop to 1 path (S2's)
    poll_rib_addpath(&[(
        &server4,
        expected_single_path(&server3_addr, vec![65003, 65002]),
    )])
    .await;

    // S5 (normal) should have S2's path (now the only and best)
    poll_rib(&[(
        &server5,
        expected_single_path(&server3_addr, vec![65003, 65002]),
    )])
    .await;
}

/// Both announce, then S3 removes peer S1. S4 (ADD-PATH) should drop to 1 path (S2's).
#[tokio::test]
async fn test_addpath_peer_disconnect() {
    let (server1, server2, server3, server4, server5) = setup_addpath_topology().await;
    let server3_addr = server3.address.to_string();

    send_and_validate_addpath_routes(&server1, &server2, &server3, &server4, &server5).await;

    server3.remove_peer(&server1).await;

    // S4 should drop to 1 path (S2's)
    poll_rib_addpath(&[(
        &server4,
        expected_single_path(&server3_addr, vec![65003, 65002]),
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
        add_path_send: Some(AddPathSendMode::AddPathSendAll.into()),
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
