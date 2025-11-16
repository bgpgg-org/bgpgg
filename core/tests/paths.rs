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

//! Tests for RFC 4271 Section 5: Path Attributes
//!
//! This module tests path attribute handling:
//!
//! ORIGIN preservation:
//! - ORIGIN attribute (IGP, EGP, INCOMPLETE) MUST NOT be changed by intermediate speakers
//!
//! AS_PATH manipulation:
//! - Originating routes: empty AS_PATH to iBGP peers, [local_AS] to eBGP peers
//! - eBGP: prepend local AS to AS_PATH when advertising to external peers
//! - iBGP: do NOT modify AS_PATH when advertising to internal peers
//!
//! NEXT_HOP handling:
//! - iBGP: Locally-originated routes with unspecified NEXT_HOP (0.0.0.0) are rewritten to router ID

mod common;
pub use common::*;

use bgpgg::grpc::proto::{AsPathSegment, Origin, Route};

#[tokio::test]
async fn test_origin_preservation() {
    // RFC 4271 Section 5.1.1: ORIGIN attribute
    // "Its value SHOULD NOT be changed by any other speaker."
    //
    // Topology: S1(AS65001) -> S2(AS65002) -> S3(AS65003)
    //                          eBGP           eBGP
    let [server1, server2, server3] = &mut chain_servers([
        start_test_server(
            65001,
            std::net::Ipv4Addr::new(1, 1, 1, 1),
            None,
            "127.0.0.1",
        )
        .await,
        start_test_server(
            65002,
            std::net::Ipv4Addr::new(2, 2, 2, 2),
            None,
            "127.0.0.2",
        )
        .await,
        start_test_server(
            65003,
            std::net::Ipv4Addr::new(3, 3, 3, 3),
            None,
            "127.0.0.3",
        )
        .await,
    ])
    .await;

    // S1 originates routes with different ORIGIN values
    let test_routes = [
        ("10.1.0.0/24", "192.168.1.1", Origin::Igp),
        ("10.2.0.0/24", "192.168.2.1", Origin::Egp),
        ("10.3.0.0/24", "192.168.3.1", Origin::Incomplete),
    ];

    for (prefix, next_hop, origin) in test_routes {
        server1
            .client
            .add_route(
                prefix.to_string(),
                next_hop.to_string(),
                origin.into(),
                vec![],
            )
            .await
            .expect("Failed to announce route");
    }

    // Helper to build expected routes with different AS_PATH, next_hop, and peer_address
    let build_expected_routes =
        |as_path: Vec<AsPathSegment>, next_hop: &str, peer_address: String| {
            test_routes
                .iter()
                .map(|(prefix, _, origin)| Route {
                    prefix: prefix.to_string(),
                    paths: vec![build_path(
                        as_path.clone(),
                        next_hop,
                        peer_address.clone(),
                        *origin,
                    )],
                })
                .collect()
        };

    // Verify ORIGIN is preserved at each hop
    // eBGP rewrites NEXT_HOP to router ID of the sending speaker
    poll_route_propagation(&[
        (
            &server2,
            build_expected_routes(
                vec![as_sequence(vec![65001])],
                "1.1.1.1",
                server1.address.clone(),
            ),
        ),
        (
            &server3,
            build_expected_routes(
                vec![as_sequence(vec![65002, 65001])],
                "2.2.2.2",
                server2.address.clone(),
            ),
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_as_path_prepending_ebgp_vs_ibgp() {
    // RFC 4271 Section 5.1.2: AS_PATH handling
    //
    // eBGP: When advertising to external peer, prepend local AS to AS_PATH
    // iBGP: When advertising to internal peer, AS_PATH MUST NOT be modified
    //
    // Topology: S1(AS65001) -> S2(AS65002) -> S3(AS65002) -> S4(AS65003)
    //                          eBGP           iBGP           eBGP
    let [server1, server2, server3, server4] = &mut chain_servers([
        start_test_server(
            65001,
            std::net::Ipv4Addr::new(1, 1, 1, 1),
            None,
            "127.0.0.1",
        )
        .await,
        start_test_server(
            65002,
            std::net::Ipv4Addr::new(2, 2, 2, 2),
            None,
            "127.0.0.2",
        )
        .await,
        start_test_server(
            65002,
            std::net::Ipv4Addr::new(3, 3, 3, 3),
            None,
            "127.0.0.3",
        )
        .await,
        start_test_server(
            65003,
            std::net::Ipv4Addr::new(4, 4, 4, 4),
            None,
            "127.0.0.4",
        )
        .await,
    ])
    .await;

    // S1 originates a route (starts with empty AS_PATH)
    server1
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            0,
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify AS_PATH and NEXT_HOP at each hop:
    //
    // S1 -> S2 (eBGP): S1 creates AS_PATH=[65001], NEXT_HOP=1.1.1.1
    // S2 -> S3 (iBGP): S2 preserves AS_PATH=[65001] (does NOT prepend), NEXT_HOP=1.1.1.1 (preserved)
    // S3 -> S4 (eBGP): S3 prepends AS_PATH=[65002, 65001], NEXT_HOP=3.3.3.3 (rewritten to S3's router ID)
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])], // eBGP: S1 created AS_SEQUENCE with its AS
                    "1.1.1.1",                      // eBGP: NEXT_HOP rewritten to S1's router ID
                    server1.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])], // iBGP: S2 did NOT modify AS_PATH
                    "1.1.1.1",                      // iBGP: NEXT_HOP preserved from S2
                    server2.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
        (
            &server4,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65002, 65001])], // eBGP: S3 prepended its AS
                    "3.3.3.3", // eBGP: NEXT_HOP rewritten to S3's router ID
                    server3.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_originating_speaker_as_path() {
    // RFC 4271 Section 5.1.2: When a BGP speaker originates a route:
    //
    // (a) To external peer: includes its own AS in AS_SEQUENCE (single segment, single AS)
    // (b) To internal peer: includes empty AS_PATH
    //
    // Topology: S1(AS65001) -> S2(AS65001) -> S3(AS65002)
    //                          iBGP           eBGP
    let [server1, server2, server3] = &mut chain_servers([
        start_test_server(
            65001,
            std::net::Ipv4Addr::new(1, 1, 1, 1),
            None,
            "127.0.0.1",
        )
        .await,
        start_test_server(
            65001,
            std::net::Ipv4Addr::new(2, 2, 2, 2),
            None,
            "127.0.0.2",
        )
        .await,
        start_test_server(
            65002,
            std::net::Ipv4Addr::new(3, 3, 3, 3),
            None,
            "127.0.0.3",
        )
        .await,
    ])
    .await;

    // S1 originates a route
    server1
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            0,
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify AS_PATH and NEXT_HOP at each hop:
    //
    // S1 -> S2 (iBGP): S1 sends empty AS_PATH (case b), NEXT_HOP=192.168.1.1 (preserved explicit value)
    // S2 -> S3 (eBGP): S2 creates AS_PATH=[65001] (prepends its AS), NEXT_HOP=2.2.2.2 (rewritten to S2's router ID)
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![],        // iBGP: originating speaker sends empty AS_PATH
                    "192.168.1.1", // iBGP: NEXT_HOP preserved (explicit value, not 0.0.0.0)
                    server1.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])], // eBGP: S2 prepended AS65001
                    "2.2.2.2",                      // eBGP: NEXT_HOP rewritten to S2's router ID
                    server2.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_ebgp_prepend_as_before_as_set() {
    // RFC 4271 Section 5.1.2: AS_PATH handling with AS_SET
    //
    // Topology: S1(AS65001) -> S2(AS65002)
    //                          eBGP
    //
    // S1 injects a route with AS_SET[65003, 65004] as the first segment.
    // S2 should receive it with AS_SEQUENCE[65001] prepended by S1.

    let [server1, server2] = &mut chain_servers([
        start_test_server(
            65001,
            std::net::Ipv4Addr::new(1, 1, 1, 1),
            None,
            "127.0.0.1",
        )
        .await,
        start_test_server(
            65002,
            std::net::Ipv4Addr::new(2, 2, 2, 2),
            None,
            "127.0.0.2",
        )
        .await,
    ])
    .await;

    // S1 adds a route with AS_SET as the first segment
    server1
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            0,
            vec![
                as_set(vec![65003, 65004]), // AS_SET as first segment
                as_sequence(vec![65005]),   // AS_SEQUENCE after
            ],
        )
        .await
        .expect("Failed to add route from server 1");

    // Verify S2 receives the route with AS_SEQUENCE[65001] prepended
    // Result: AS_SEQUENCE[65001], AS_SET[65003, 65004], AS_SEQUENCE[65005]
    // eBGP: NEXT_HOP rewritten to S1's router ID
    poll_route_propagation(&[(
        &server2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![
                    as_sequence(vec![65001]),   // Prepended by S1 (eBGP)
                    as_set(vec![65003, 65004]), // Original AS_SET
                    as_sequence(vec![65005]),   // Original AS_SEQUENCE
                ],
                "1.1.1.1", // eBGP: NEXT_HOP rewritten to S1's router ID
                server1.address.clone(),
                Origin::Igp,
            )],
        }],
    )])
    .await;
}

#[tokio::test]
async fn test_next_hop_locally_originated_to_ibgp() {
    // RFC 4271 Section 5.1.3: NEXT_HOP for locally-originated routes
    //
    // "When announcing a locally-originated route to an internal peer, the BGP speaker
    // SHOULD use the interface address of the router through which the announced network
    // is reachable for the speaker as the NEXT_HOP."
    //
    // Topology: S1(AS65001, router_id=1.1.1.1) -> S2(AS65001, router_id=2.2.2.2)
    //                                    iBGP
    //
    // When S1 originates a route with NEXT_HOP unspecified (0.0.0.0),
    // the BGP speaker SHOULD set it to S1's local address (1.1.1.1)
    // when sending to iBGP peer S2.
    //
    // Note: Per GoBGP implementation, NEXT_HOP is only auto-set when it's unspecified.
    // If explicitly set to a non-zero value, it's preserved.
    let [server1, server2] = &mut chain_servers([
        start_test_server(
            65001,
            std::net::Ipv4Addr::new(1, 1, 1, 1),
            None,
            "127.0.0.1",
        )
        .await,
        start_test_server(
            65001,
            std::net::Ipv4Addr::new(2, 2, 2, 2),
            None,
            "127.0.0.2",
        )
        .await,
    ])
    .await;

    // S1 originates a route with NEXT_HOP unspecified (0.0.0.0)
    server1
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "0.0.0.0".to_string(), // Unspecified NEXT_HOP
            0,
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // RFC expectation: S2 should receive the route with NEXT_HOP set to 1.1.1.1
    // (S1's local address for the peering session)
    poll_route_propagation(&[(
        &server2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![],    // iBGP: empty AS_PATH for locally-originated route
                "1.1.1.1", // NEXT_HOP should be set to S1's local address
                server1.address.clone(),
                Origin::Igp,
            )],
        }],
    )])
    .await;
}

#[tokio::test]
async fn test_next_hop_rewrite_to_ebgp() {
    // RFC 4271 Section 5.1.3: NEXT_HOP handling when advertising to eBGP
    //
    // "By default, the BGP speaker SHOULD use the IP address of the interface
    // that the speaker uses to establish the BGP connection to peer X in the
    // NEXT_HOP attribute."
    //
    // Topology: S1(AS65001) -> S2(AS65001) -> S3(AS65002)
    //                          iBGP           eBGP
    //
    // When S1 sends a route to S2 via iBGP, S2 preserves NEXT_HOP.
    // When S2 advertises to S3 via eBGP, S2 SHOULD rewrite NEXT_HOP to self.
    let [server1, server2, server3] = &mut chain_servers([
        start_test_server(
            65001,
            std::net::Ipv4Addr::new(1, 1, 1, 1),
            None,
            "127.0.0.1",
        )
        .await,
        start_test_server(
            65001,
            std::net::Ipv4Addr::new(2, 2, 2, 2),
            None,
            "127.0.0.2",
        )
        .await,
        start_test_server(
            65002,
            std::net::Ipv4Addr::new(3, 3, 3, 3),
            None,
            "127.0.0.3",
        )
        .await,
    ])
    .await;

    // S1 originates a route with explicit NEXT_HOP
    server1
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.100".to_string(), // Arbitrary NEXT_HOP
            0,
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify NEXT_HOP handling:
    // S1 -> S2 (iBGP): NEXT_HOP preserved as 192.168.1.100
    // S2 -> S3 (eBGP): NEXT_HOP rewritten to S2's local address (2.2.2.2)
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![],          // iBGP: empty AS_PATH
                    "192.168.1.100", // iBGP: NEXT_HOP preserved
                    server1.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])], // eBGP: AS prepended
                    "2.2.2.2",                      // eBGP: NEXT_HOP rewritten to S2's address
                    server2.address.clone(),
                    Origin::Igp,
                )],
            }],
        ),
    ])
    .await;
}
