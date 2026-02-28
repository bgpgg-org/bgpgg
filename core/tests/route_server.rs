// Copyright 2026 bgpgg Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Route Server tests (RFC 7947)

mod utils;
pub use utils::*;

use bgpgg::bgp::ext_community::*;
use bgpgg::bgp::msg_update::{attr_flags, attr_type_code};
use bgpgg::bgp::msg_update_types::LargeCommunity as BgpLargeCommunity;
use bgpgg::grpc::proto::{
    self as proto,
    extended_community::{Community, TwoOctetAsSpecific},
    AddPathSendMode, BgpState, ExtendedCommunity, Origin, Route, SessionConfig, UnknownAttribute,
};
use std::net::Ipv4Addr;

/// Helper to configure a server as a route server (eBGP)
async fn setup_route_server(rs: &TestServer, clients: Vec<&TestServer>) {
    for client in &clients {
        // Configure client as rs-client on the route server
        let rs_client_cfg = SessionConfig {
            rs_client: Some(true),
            asn: Some(client.asn),
            ..Default::default()
        };
        rs.add_peer_with_config(client, rs_client_cfg).await;

        // Configure route server on the client (disable first AS check)
        let client_cfg = SessionConfig {
            enforce_first_as: Some(false),
            ..Default::default()
        };
        client.add_peer_with_config(rs, client_cfg).await;
    }

    // Wait for all peers to establish
    let expected: Vec<_> = clients
        .iter()
        .map(|c| c.to_peer(BgpState::Established))
        .collect();
    poll_until(
        || async { verify_peers(rs, expected.clone()).await },
        "Waiting for route server peerings to establish",
    )
    .await;

    for client in clients {
        poll_until(
            || async { verify_peers(client, vec![rs.to_peer(BgpState::Established)]).await },
            "Waiting for client to establish with RS",
        )
        .await;
    }
}

/// RFC 7947 Section 2.2.2.1: Route servers preserve AS_PATH, NEXT_HOP, MED without modification.
/// Topology: Client1(AS65001) -- RS(AS65000) -- Client2(AS65002)
/// Client1 announces route with specific attributes, RS forwards transparently to Client2.
#[tokio::test]
async fn test_rs_basic_transparency() {
    let client1 = start_test_server(test_config(65001, 1)).await;
    let rs = start_test_server(test_config(65000, 2)).await;
    let client2 = start_test_server(test_config(65002, 3)).await;

    setup_route_server(&rs, vec![&client1, &client2]).await;

    // Client1 announces route with AS_PATH [65099], MED 42
    announce_route(
        &client1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client1.address.to_string(),
            as_path: vec![as_sequence(vec![65099])],
            med: Some(42),
            ..Default::default()
        },
    )
    .await;

    // Client2 should receive the route with route server transparency:
    // - AS_PATH: preserved without RS ASN prepending [65001, 65099]
    // - MED: preserved (42, proves transparency)
    // - LOCAL_PREF: set to 100 by client2's import policy (eBGP strips it)
    poll_route_exists(
        &client2,
        Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                next_hop: client1.address.to_string(),
                peer_address: rs.address.to_string(),
                as_path: vec![as_sequence(vec![65001, 65099])],
                med: Some(42), // Preserved - validates transparency
                origin: Some(Origin::Igp),
                local_pref: Some(100), // Default policy (not on wire for eBGP)
                ..Default::default()
            })],
        },
    )
    .await;
}

/// RFC 7947 Section 2.2.2.1: Route servers preserve ALL communities (standard, extended, large).
/// Unlike normal eBGP which filters non-transitive extended communities, route servers preserve everything.
#[tokio::test]
async fn test_rs_community_preservation() {
    let client1 = start_test_server(test_config(65001, 1)).await;
    let rs = start_test_server(test_config(65000, 2)).await;
    let client2 = start_test_server(test_config(65002, 3)).await;

    setup_route_server(&rs, vec![&client1, &client2]).await;

    // Announce route with standard, extended, and large communities
    announce_route(
        &client1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client1.address.to_string(),
            communities: vec![65001 << 16 | 100, 65001 << 16 | 200],
            extended_communities: vec![0x0002FDE900000064u64], // rt:65001:100
            large_communities: vec![BgpLargeCommunity::new(65001, 1, 100)],
            ..Default::default()
        },
    )
    .await;

    // Client2 should receive all communities unchanged
    poll_route_exists(
        &client2,
        Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                next_hop: client1.address.to_string(),
                peer_address: rs.address.to_string(),
                as_path: vec![as_sequence(vec![65001])], // Client1 prepends its ASN
                communities: vec![65001 << 16 | 100, 65001 << 16 | 200],
                extended_communities: vec![ExtendedCommunity {
                    community: Some(Community::TwoOctetAs(TwoOctetAsSpecific {
                        is_transitive: true,
                        sub_type: SUBTYPE_ROUTE_TARGET as u32,
                        asn: 65001,
                        local_admin: 100,
                    })),
                }],
                large_communities: vec![proto::LargeCommunity {
                    global_admin: 65001,
                    local_data_1: 1,
                    local_data_2: 100,
                }],
                local_pref: Some(100), // Set by client2's import policy
                ..Default::default()
            })],
        },
    )
    .await;
}

/// RFC 7947 Section 2.3.2.1: Route servers with ADD-PATH send all paths to clients.
/// This prevents path hiding and allows clients to make their own filtering decisions.
#[tokio::test]
async fn test_rs_addpath_no_path_hiding() {
    let client1 = start_test_server(test_config(65001, 1)).await;
    let client2 = start_test_server(test_config(65002, 2)).await;
    let rs = start_test_server(test_config(65000, 3)).await;
    let client3 = start_test_server(test_config(65003, 4)).await;

    let client_addpath_cfg = SessionConfig {
        enforce_first_as: Some(false),
        add_path_send: Some(AddPathSendMode::AddPathSendAll.into()),
        add_path_receive: Some(true),
        ..Default::default()
    };

    for client in &[&client1, &client2, &client3] {
        // Configure RS with ADD-PATH send enabled for this client
        let rs_addpath_cfg = SessionConfig {
            rs_client: Some(true),
            asn: Some(client.asn),
            add_path_send: Some(AddPathSendMode::AddPathSendAll.into()),
            // RFC 7947 §2.3.2.2.2: RS enforces send-only ADD-PATH mode
            ..Default::default()
        };
        rs.add_peer_with_config(client, rs_addpath_cfg).await;
        client.add_peer_with_config(&rs, client_addpath_cfg).await;
    }

    poll_until(
        || async {
            verify_peers(
                &rs,
                vec![
                    client1.to_peer(BgpState::Established),
                    client2.to_peer(BgpState::Established),
                    client3.to_peer(BgpState::Established),
                ],
            )
            .await
        },
        "Waiting for RS peerings to establish",
    )
    .await;

    poll_until(
        || async { verify_peers(&client1, vec![rs.to_peer(BgpState::Established)]).await },
        "Waiting for client1 to establish",
    )
    .await;

    poll_until(
        || async { verify_peers(&client2, vec![rs.to_peer(BgpState::Established)]).await },
        "Waiting for client2 to establish",
    )
    .await;

    poll_until(
        || async { verify_peers(&client3, vec![rs.to_peer(BgpState::Established)]).await },
        "Waiting for client3 to establish",
    )
    .await;

    // Client1 announces 10.0.0.0/24
    announce_route(
        &client1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client1.address.to_string(),
            ..Default::default()
        },
    )
    .await;

    // Client2 announces same prefix
    announce_route(
        &client2,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client2.address.to_string(),
            ..Default::default()
        },
    )
    .await;

    // Client3 should receive BOTH paths (no path hiding!)
    poll_rib(&[(
        &client3,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![
                build_path(PathParams {
                    next_hop: client1.address.to_string(),
                    peer_address: rs.address.to_string(),
                    as_path: vec![as_sequence(vec![65001])],
                    local_pref: Some(100),
                    ..Default::default()
                }),
                build_path(PathParams {
                    next_hop: client2.address.to_string(),
                    peer_address: rs.address.to_string(),
                    as_path: vec![as_sequence(vec![65002])],
                    local_pref: Some(100),
                    ..Default::default()
                }),
            ],
        }],
    )])
    .await;
}

/// RFC 7947 Section 2.2.2.3: eBGP route servers strip LOCAL_PREF per RFC 4271.
#[tokio::test]
async fn test_rs_local_pref_handling() {
    let client1 = start_test_server(test_config(65001, 1)).await;
    let rs = start_test_server(test_config(65000, 2)).await;
    let client2 = start_test_server(test_config(65002, 3)).await;

    setup_route_server(&rs, vec![&client1, &client2]).await;

    announce_route(
        &client1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client1.address.to_string(),
            local_pref: Some(200),
            ..Default::default()
        },
    )
    .await;

    // eBGP RS: LOCAL_PREF is stripped on wire (RFC 4271), then set by import policy
    poll_route_exists(
        &client2,
        Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                next_hop: client1.address.to_string(),
                peer_address: rs.address.to_string(),
                as_path: vec![as_sequence(vec![65001])],
                local_pref: Some(100), // Default policy (not on wire)
                ..Default::default()
            })],
        },
    )
    .await;
}

/// RFC 7947 Section 2.2.2.4: Route servers do NOT add ORIGINATOR_ID or CLUSTER_LIST.
/// These are RR-specific attributes (RFC 4456) and should not appear when using route server mode.
#[tokio::test]
async fn test_rs_no_rr_attributes() {
    let client1 = start_test_server(test_config(65001, 1)).await;
    let rs = start_test_server(test_config(65000, 2)).await;
    let client2 = start_test_server(test_config(65002, 3)).await;

    setup_route_server(&rs, vec![&client1, &client2]).await;

    announce_route(
        &client1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client1.address.to_string(),
            ..Default::default()
        },
    )
    .await;

    // Client2 should receive route WITHOUT ORIGINATOR_ID or CLUSTER_LIST
    poll_route_exists(
        &client2,
        Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                next_hop: client1.address.to_string(),
                peer_address: rs.address.to_string(),
                as_path: vec![as_sequence(vec![65001])],
                originator_id: None,   // RS does not add this
                cluster_list: vec![],  // RS does not add this
                local_pref: Some(100), // Default policy
                ..Default::default()
            })],
        },
    )
    .await;
}

/// Validation: Peer cannot be both rr-client and rs-client simultaneously.
#[tokio::test]
async fn test_rs_rr_mutual_exclusion() {
    let server = start_test_server(test_config(65000, 1)).await;
    let client = start_test_server(test_config(65000, 2)).await;

    // Try to configure peer as both RR client and RS client (should fail)
    let config = SessionConfig {
        rr_client: Some(true),
        rs_client: Some(true),
        ..Default::default()
    };

    let result = server
        .client
        .add_peer(client.address.to_string(), Some(config))
        .await;
    assert!(
        result.is_err(),
        "Should reject peer with both rr_client and rs_client enabled"
    );
}

/// RFC 7947 Section 2.3.2: when RS-side export policy blocks the best path for a client,
/// route iteration tries the next path rather than sending nothing.
///
/// Topology: Client1(65001) ──┐
///           Client2(65002) ──┤── RS(65000) ── Client3(65003)
#[tokio::test]
async fn test_rs_route_iteration_no_path_hiding() {
    let client1 = start_test_server(test_config(65001, 1)).await;
    let client2 = start_test_server(test_config(65002, 2)).await;
    let rs = start_test_server(test_config(65000, 3)).await;
    let client3 = start_test_server(test_config(65003, 4)).await;

    setup_route_server(&rs, vec![&client1, &client2, &client3]).await;

    apply_export_neighbor_reject_policy(
        &rs,
        &client3.address.to_string(),
        "reject-client1",
        &client1.address.to_string(),
    )
    .await;

    // Client1 (IGP origin) is preferred over Client2 (Incomplete origin); policy blocks it for Client3.
    announce_route(
        &client1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client1.address.to_string(),
            ..Default::default()
        },
    )
    .await;

    announce_route(
        &client2,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client2.address.to_string(),
            origin: Some(Origin::Incomplete),
            ..Default::default()
        },
    )
    .await;

    // Client3 receives Client2's path via route iteration.
    poll_route_exists(
        &client3,
        Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                next_hop: client2.address.to_string(),
                peer_address: rs.address.to_string(),
                as_path: vec![as_sequence(vec![65002])],
                origin: Some(Origin::Incomplete),
                local_pref: Some(100),
                ..Default::default()
            })],
        },
    )
    .await;
}

/// RFC 7947 Section 2.2: Route server attribute transparency.
///
/// Client1(AS65001) -- RS(AS65000) -- Client2(AS65002)
///
/// For each case: Client1 announces a route with specific attributes, Client2
/// must receive them unmodified. AS_PATH and NEXT_HOP transparency (2.2.1,
/// 2.2.2.1) are verified by every case via the common base expected path.
#[tokio::test]
async fn test_rs_section_2_2_attribute_transparency() {
    struct Case {
        route_modifier: fn(RouteParams) -> RouteParams,
        expected_modifier: fn(PathParams) -> PathParams,
    }

    let test_cases: Vec<Case> = vec![
        // 2.2.1 + 2.2.2.1: NEXT_HOP and AS_PATH pass through without RS modification.
        // Verified implicitly by every case; explicit here for documentation.
        Case {
            route_modifier: |r| r,
            expected_modifier: |p| p,
        },
        // 2.2.3: MED propagated unchanged
        Case {
            route_modifier: |r| RouteParams { med: Some(42), ..r },
            expected_modifier: |p| PathParams { med: Some(42), ..p },
        },
        // 2.2.4: Standard communities (RFC 1997) preserved
        Case {
            route_modifier: |r| RouteParams {
                communities: vec![65001 << 16 | 100],
                ..r
            },
            expected_modifier: |p| PathParams {
                communities: vec![65001 << 16 | 100],
                ..p
            },
        },
        // 2.2.4: Non-transitive extended communities (RFC 4360) preserved.
        // Normal eBGP strips these; RS must keep them.
        Case {
            route_modifier: |r| RouteParams {
                extended_communities: vec![0x4002_0001_0000_0064u64],
                ..r
            },
            expected_modifier: |p| PathParams {
                extended_communities: vec![ExtendedCommunity {
                    community: Some(Community::TwoOctetAs(TwoOctetAsSpecific {
                        is_transitive: false,
                        sub_type: SUBTYPE_ROUTE_TARGET as u32,
                        asn: 1,
                        local_admin: 100,
                    })),
                }],
                ..p
            },
        },
        // 2.2.4: Large communities (RFC 8092) preserved
        Case {
            route_modifier: |r| RouteParams {
                large_communities: vec![BgpLargeCommunity::new(65001, 1, 100)],
                ..r
            },
            expected_modifier: |p| PathParams {
                large_communities: vec![proto::LargeCommunity {
                    global_admin: 65001,
                    local_data_1: 1,
                    local_data_2: 100,
                }],
                ..p
            },
        },
    ];

    for case in test_cases {
        let client1 = start_test_server(test_config(65001, 1)).await;
        let rs = start_test_server(test_config(65000, 2)).await;
        let client2 = start_test_server(test_config(65002, 3)).await;

        setup_route_server(&rs, vec![&client1, &client2]).await;

        let base_route = RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client1.address.to_string(),
            ..Default::default()
        };
        announce_route(&client1, (case.route_modifier)(base_route)).await;

        let base_expected = PathParams {
            as_path: vec![as_sequence(vec![client1.asn])], // RS must not prepend its ASN
            next_hop: client1.address.to_string(),         // RS must not modify next hop
            peer_address: rs.address.to_string(),
            local_pref: Some(100),
            origin: Some(Origin::Igp),
            ..Default::default()
        };
        poll_route_exists(
            &client2,
            Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path((case.expected_modifier)(base_expected))],
            },
        )
        .await;
    }
}

/// RFC 7947 Section 2.2: RS preserves unknown optional attributes (transitive and
/// non-transitive). Normal eBGP drops non-transitive unknown attrs; RS must not.
///
/// Uses FakePeer to inject raw unknown attributes that have no gRPC representation.
///
/// FakePeer(AS65001, 127.0.0.5) -- RS(AS65000) -- Client2(AS65002)
#[tokio::test]
async fn test_rs_unknown_attr_transparency() {
    const FAKE_PEER_IP: &str = "127.0.0.5";
    const FAKE_PEER_ASN: u32 = 65001;

    let rs = start_test_server(test_config(65000, 2)).await;
    let client2 = start_test_server(test_config(65002, 3)).await;

    setup_route_server(&rs, vec![&client2]).await;

    // 127.0.0.5 avoids conflict with client2 (127.0.0.3)
    rs.client
        .add_peer(
            FAKE_PEER_IP.to_string(),
            Some(SessionConfig {
                rs_client: Some(true),
                passive_mode: Some(true),
                asn: Some(FAKE_PEER_ASN),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    let mut fake = FakePeer::connect(Some(FAKE_PEER_IP), &rs).await;
    fake.handshake_open(FAKE_PEER_ASN, Ipv4Addr::new(1, 1, 1, 1), 180)
        .await;
    fake.handshake_keepalive().await;

    // AS_PATH: AS_SEQUENCE(2), count=1, AS=65001 (2-byte: 0xFDE9)
    let origin_attr = build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 1, &[0x00]);
    let as_path_attr = build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::AS_PATH,
        4,
        &[0x02, 0x01, 0xFD, 0xE9],
    );
    let next_hop_attr = build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::NEXT_HOP,
        4,
        &[127, 0, 0, 5],
    );
    let transitive_unknown = build_attr_bytes(
        attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
        200,
        4,
        &[0xde, 0xad, 0xbe, 0xef],
    );
    let non_transitive_unknown = build_attr_bytes(attr_flags::OPTIONAL, 201, 2, &[0xca, 0xfe]);

    fake.send_raw(&build_raw_update(
        &[],
        &[
            &origin_attr,
            &as_path_attr,
            &next_hop_attr,
            &transitive_unknown,
            &non_transitive_unknown,
        ],
        &[24, 10, 0, 0],
        None,
    ))
    .await;

    poll_route_exists(
        &client2,
        Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                as_path: vec![as_sequence(vec![FAKE_PEER_ASN])],
                next_hop: FAKE_PEER_IP.to_string(),
                peer_address: rs.address.to_string(),
                local_pref: Some(100),
                origin: Some(Origin::Igp),
                unknown_attributes: vec![
                    UnknownAttribute {
                        attr_type: 200,
                        // Transitive unknown attrs get PARTIAL bit set when forwarded (RFC 4271)
                        flags: (attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::PARTIAL)
                            as u32,
                        value: vec![0xde, 0xad, 0xbe, 0xef],
                    },
                    UnknownAttribute {
                        attr_type: 201,
                        flags: attr_flags::OPTIONAL as u32,
                        value: vec![0xca, 0xfe],
                    },
                ],
                ..Default::default()
            })],
        },
    )
    .await;
}
