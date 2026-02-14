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

use bgpgg::bgp::msg_update::{attr_flags, attr_type_code};
use bgpgg::config::Config;
use bgpgg::grpc::proto::{AddPathSendMode, BgpState, Origin, Route, SessionConfig};
use std::net::Ipv4Addr;
use std::time::Duration;

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

/// Sets up an iBGP route reflector with ADD-PATH and two clients:
///
///   Client1(BGP ID 2.2.2.2) --+
///                              +--> RR(BGP ID 1.1.1.1)
///   Client2(BGP ID 3.3.3.3) --+
///
/// All ASN 65001, rr_client + ADD-PATH on all peerings.
/// Returns (rr, client1, client2) with all sessions Established.
async fn setup_rr_addpath_topology() -> (TestServer, TestServer, TestServer) {
    let rr = start_test_server(Config::new(
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

    let rr_config = SessionConfig {
        rr_client: Some(true),
        add_path_send: Some(AddPathSendMode::AddPathSendAll.into()),
        add_path_receive: Some(true),
        ..Default::default()
    };
    rr.add_peer_with_config(&client1, rr_config).await;
    rr.add_peer_with_config(&client2, rr_config).await;
    client1.add_peer_with_config(&rr, addpath_config()).await;
    client2.add_peer_with_config(&rr, addpath_config()).await;

    poll_until(
        || async {
            rr.client.get_peers().await.is_ok_and(|peers| {
                peers
                    .iter()
                    .filter(|p| p.state == BgpState::Established as i32)
                    .count()
                    == 2
            })
        },
        "Timeout waiting for RR peers to reach Established",
    )
    .await;

    (rr, client1, client2)
}

/// Create a server + FakePeer with ADD-PATH iBGP session in Established state.
/// FakePeer listens, server connects out. Both are ASN 65001.
///
///   Server --[iBGP + ADD-PATH recv]--> FakePeer
async fn setup_fakepeer_addpath(
    server_bgp_id: Ipv4Addr,
    fake_bgp_id: Ipv4Addr,
) -> (TestServer, FakePeer) {
    let server = start_test_server(Config::new(65001, "127.0.0.1:0", server_bgp_id, 90)).await;
    let mut fake = FakePeer::new("127.0.0.2:0", 65001).await;
    server
        .client
        .add_peer(
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                port: Some(fake.port() as u32),
                add_path_receive: Some(true),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    fake.accept_and_handshake(
        65001,
        fake_bgp_id,
        Some(vec![
            build_multiprotocol_capability_ipv4_unicast(),
            build_addpath_capability_ipv4_unicast(),
        ]),
    )
    .await;

    poll_until(
        || async {
            server.client.get_peers().await.is_ok_and(|peers| {
                peers
                    .iter()
                    .any(|p| p.state == BgpState::Established as i32)
            })
        },
        "Timeout waiting for Established",
    )
    .await;

    (server, fake)
}

/// Build ADD-PATH NLRI bytes: 4-byte path_id + prefix_len + prefix_bytes
fn addpath_nlri(path_id: u32, prefix_bytes: &[u8]) -> Vec<u8> {
    let mut nlri = path_id.to_be_bytes().to_vec();
    nlri.extend_from_slice(prefix_bytes);
    nlri
}

/// Build ORIGINATOR_ID attribute
fn attr_originator_id(ip: Ipv4Addr) -> Vec<u8> {
    build_attr_bytes(
        attr_flags::OPTIONAL,
        attr_type_code::ORIGINATOR_ID,
        4,
        &ip.octets(),
    )
}

/// Build LOCAL_PREF attribute
fn attr_local_pref(value: u32) -> Vec<u8> {
    build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::LOCAL_PREF,
        4,
        &value.to_be_bytes(),
    )
}

/// Sender-side: RR must not reflect a client's own path back to that client.
/// Checks RR's adj-rib-out toward Client1.
#[tokio::test]
async fn test_addpath_rr_no_reflect_to_originator() {
    let (rr, client1, client2) = setup_rr_addpath_topology().await;
    let client1_addr = client1.address.to_string();

    for (server, next_hop) in [(&client1, "192.168.1.1"), (&client2, "192.168.2.1")] {
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

    // Should only have Client2's path, not Client1's own reflected back
    poll_until_stable(
        || async {
            rr.client
                .get_adj_rib_out(&client1_addr)
                .await
                .is_ok_and(|routes| {
                    routes.iter().any(|r| {
                        r.prefix == "10.0.0.0/24"
                            && r.paths.len() == 1
                            && r.paths[0].next_hop == "192.168.2.1"
                    })
                })
        },
        Duration::from_secs(2),
        "RR adj-rib-out toward Client1 should have exactly 1 path (Client2's, next_hop 192.168.2.1)",
    )
    .await;
}

/// Per-path withdrawal must not remove other paths from the same ADD-PATH peer.
/// FakePeer sends two paths (path_id=1, path_id=2), then withdraws path_id=1.
/// path_id=2 must survive.
///
/// Also tests implicit replacement: re-announcing the same path_id with different
/// attributes must replace in-place (1 path, not 2).
#[tokio::test]
async fn test_addpath_per_path_withdrawal() {
    let (server, mut fake) = setup_fakepeer_addpath(
        Ipv4Addr::new(1, 1, 1, 1), // server BGP ID
        Ipv4Addr::new(2, 2, 2, 2), // fake BGP ID
    )
    .await;

    // Path 1: next_hop=192.168.1.1
    let update1 = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 1, 1)),
            &attr_local_pref(100),
        ],
        &addpath_nlri(1, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update1).await;

    // Path 2: next_hop=192.168.2.1
    let update2 = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 2, 1)),
            &attr_local_pref(100),
        ],
        &addpath_nlri(2, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update2).await;

    let fake_addr = "127.0.0.2".to_string();
    let ibgp_path = |next_hop: &str| {
        build_path(PathParams {
            next_hop: next_hop.to_string(),
            peer_address: fake_addr.clone(),
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            ..Default::default()
        })
    };

    // Both paths in loc-rib
    poll_rib_addpath(&[(
        &server,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![ibgp_path("192.168.1.1"), ibgp_path("192.168.2.1")],
        }],
    )])
    .await;

    // Withdraw path_id=1 only
    let withdraw = build_raw_update(&addpath_nlri(1, &[24, 10, 0, 0]), &[], &[], None);
    fake.send_raw(&withdraw).await;

    // path_id=2 (next_hop=192.168.2.1) must survive
    poll_until_stable(
        || async {
            let expected = vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![ibgp_path("192.168.2.1")],
            }];
            server
                .client
                .get_routes()
                .await
                .is_ok_and(|routes| routes_match(&routes, &expected, ExpectPathId::Distinct))
        },
        Duration::from_secs(2),
        "path_id=2 was removed by withdrawal of path_id=1",
    )
    .await;

    // Implicit replacement: re-announce path_id=2 with different next_hop.
    // Must replace in-place (still 1 path), not append (would be 2 paths).
    let update_replace = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 3, 1)),
            &attr_local_pref(100),
        ],
        &addpath_nlri(2, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update_replace).await;

    poll_until_stable(
        || async {
            let expected = vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![ibgp_path("192.168.3.1")],
            }];
            server
                .client
                .get_routes()
                .await
                .is_ok_and(|routes| routes_match(&routes, &expected, ExpectPathId::Distinct))
        },
        Duration::from_secs(2),
        "path_id=2 was not replaced in-place (wrong path count or attrs)",
    )
    .await;
}

/// Receiver-side: ORIGINATOR_ID loop rejection must not withdraw other paths from same peer.
/// FakePeer sends valid path (path_id=1), then looped path (path_id=2). Valid must survive.
#[tokio::test]
async fn test_originator_id_rejection_preserves_other_paths() {
    let (server, mut fake) = setup_fakepeer_addpath(
        Ipv4Addr::new(2, 2, 2, 2), // server BGP ID
        Ipv4Addr::new(3, 3, 3, 3), // fake BGP ID
    )
    .await;

    // Valid path: ORIGINATOR_ID=3.3.3.3 (not ours)
    let update_valid = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 2, 1)),
            &attr_local_pref(100),
            &attr_originator_id(Ipv4Addr::new(3, 3, 3, 3)),
        ],
        &addpath_nlri(1, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update_valid).await;

    poll_until_stable(
        || async {
            server
                .client
                .get_routes()
                .await
                .is_ok_and(|routes| routes.iter().any(|r| r.prefix == "10.0.0.0/24"))
        },
        Duration::from_secs(1),
        "Timeout waiting for valid path to stabilize",
    )
    .await;

    // Looped path: ORIGINATOR_ID=2.2.2.2 (matches server's BGP ID)
    let update_looped = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 1, 1)),
            &attr_local_pref(100),
            &attr_originator_id(Ipv4Addr::new(2, 2, 2, 2)),
        ],
        &addpath_nlri(2, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update_looped).await;

    // Valid path must survive the looped path's rejection
    poll_while(
        || async {
            server
                .client
                .get_routes()
                .await
                .is_ok_and(|routes| routes.iter().any(|r| r.prefix == "10.0.0.0/24"))
        },
        Duration::from_secs(2),
        "Valid path was removed by ORIGINATOR_ID loop rejection of another path",
    )
    .await;
}
