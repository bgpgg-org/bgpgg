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
                origin,
                vec![],
                None,
                None,
                false,
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
                        Some(100),
                        None,
                        false,
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
            Origin::Igp,
            vec![],
            None,
            None,
            false,
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
                    Some(100),
                    None,
                    false,
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
                    Some(100),
                    None,
                    false,
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
                    Some(100),
                    None,
                    false,
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
            Origin::Igp,
            vec![],
            None,
            None,
            false,
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
                    Some(100),
                    None,
                    false,
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
                    Some(100),
                    None,
                    false,
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
            Origin::Igp,
            vec![
                as_set(vec![65003, 65004]), // AS_SET as first segment
                as_sequence(vec![65005]),   // AS_SEQUENCE after
            ],
            None,
            None,
            false,
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
                Some(100),
                None,
                false,
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
            Origin::Igp,
            vec![],
            None,
            None,
            false,
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
                Some(100),
                None,
                false,
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
            Origin::Igp,
            vec![],
            None,
            None,
            false,
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
                    Some(100),
                    None,
                    false,
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
                    Some(100),
                    None,
                    false,
                )],
            }],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_local_pref_send_to_ibgp() {
    // RFC 4271 Section 5.1.5: LOCAL_PREF handling
    //
    // "LOCAL_PREF is a well-known attribute that SHALL be included in all
    //  UPDATE messages that a given BGP speaker sends to other internal peers."
    //
    // Topology: S1(AS65000) -> S2(AS65001) -> S3(AS65001)
    //                          eBGP           iBGP
    //
    // Verify LOCAL_PREF is propagated through iBGP:
    // - S1 originates route (external AS)
    // - S2 receives via eBGP, DefaultLocalPref policy sets to 100
    // - S3 receives via iBGP with LOCAL_PREF=100 (proves it was in UPDATE)
    let [server1, server2, server3] = &mut chain_servers([
        start_test_server(
            65000,
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
            65001,
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
            Origin::Igp,
            vec![],
            None,
            None,
            false,
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify:
    // S2 (eBGP): receives route with LOCAL_PREF=100 (set by DefaultLocalPref policy)
    // S3 (iBGP): receives route with LOCAL_PREF=100 (proves LOCAL_PREF was in UPDATE from S2)
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65000])],
                    "1.1.1.1",
                    server1.address.clone(),
                    Origin::Igp,
                    Some(100), // LOCAL_PREF set by DefaultLocalPref policy
                    None,
                    false,
                )],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65000])], // iBGP preserves AS_PATH
                    "1.1.1.1",                      // iBGP preserves NEXT_HOP
                    server2.address.clone(),
                    Origin::Igp,
                    Some(100), // LOCAL_PREF preserved from S2's UPDATE (proves it was included)
                    None,
                    false,
                )],
            }],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_local_pref_not_sent_to_ebgp() {
    // RFC 4271 Section 5.1.5: LOCAL_PREF is only for iBGP
    //
    // "A BGP speaker SHALL calculate the degree of preference for each external
    //  route based on the locally-configured policy, and include the degree of
    //  preference when advertising a route to its internal peers."
    //
    // LOCAL_PREF is well-known discretionary, so it's NOT sent to eBGP peers.
    //
    // Topology: S1(AS65001) -> S2(AS65001) -> S3(AS65002)
    //                          iBGP           eBGP
    //
    // Verify LOCAL_PREF is not sent to eBGP peers:
    // - S1 originates route with LOCAL_PREF=200
    // - S2 receives via iBGP with LOCAL_PREF=200
    // - S3 receives via eBGP with LOCAL_PREF=100 (set by policy, NOT from S2)
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

    // S1 originates a route with LOCAL_PREF=200
    server1
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            Some(200), // Explicitly set LOCAL_PREF to 200
            None,
            false,
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify S2 first (iBGP): receives route with LOCAL_PREF=200 (preserved from S1)
    poll_route_propagation(&[(
        &server2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![],        // iBGP: empty AS_PATH
                "192.168.1.1", // iBGP: NEXT_HOP preserved
                server1.address.clone(),
                Origin::Igp,
                Some(200),
                None, // LOCAL_PREF=200 preserved via iBGP
                false,
            )],
        }],
    )])
    .await;

    // Verify S3 (eBGP): receives route with LOCAL_PREF=100 (set by DefaultLocalPref policy, NOT from S2)
    //                   This proves LOCAL_PREF was NOT sent in UPDATE from S2 to S3
    poll_route_propagation(&[(
        &server3,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65001])], // eBGP: AS prepended
                "2.2.2.2",                      // eBGP: NEXT_HOP rewritten
                server2.address.clone(),
                Origin::Igp,
                Some(100), // LOCAL_PREF=100 (set by policy, NOT 200 from S2!)
                None,
                false,
            )],
        }],
    )])
    .await;
}

#[tokio::test]
async fn test_med_propagation_over_ibgp() {
    // RFC 4271 Section 5.1.4: MULTI_EXIT_DISC handling
    //
    // "If received over EBGP, the MULTI_EXIT_DISC attribute MAY be propagated
    //  over IBGP to other BGP speakers within the same AS."
    //
    // Topology: S1(AS65000) -> S2(AS65001) -> S3(AS65001)
    //                          eBGP           iBGP
    //
    // Verify MED is propagated through iBGP:
    // - S1 originates route with MED=50 (external AS)
    // - S2 receives via eBGP with MED=50
    // - S3 receives via iBGP with MED=50 (proves it was propagated)
    let [server1, server2, server3] = &mut chain_servers([
        start_test_server(
            65000,
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
            65001,
            std::net::Ipv4Addr::new(3, 3, 3, 3),
            None,
            "127.0.0.3",
        )
        .await,
    ])
    .await;

    // S1 originates a route with MED=50
    server1
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            Some(50), // Set MED=50
            false,
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify:
    // S2 (eBGP): receives route with MED=50
    // S3 (iBGP): receives route with MED=50 (proves MED was propagated over iBGP)
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65000])],
                    "1.1.1.1",
                    server1.address.clone(),
                    Origin::Igp,
                    Some(100), // LOCAL_PREF set by DefaultLocalPref policy
                    Some(50),  // MED=50 received from S1
                    false,
                )],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65000])], // iBGP preserves AS_PATH
                    "1.1.1.1",                      // iBGP preserves NEXT_HOP
                    server2.address.clone(),
                    Origin::Igp,
                    Some(100), // LOCAL_PREF preserved from S2
                    Some(50),  // MED=50 propagated over iBGP (proves propagation)
                    false,
                )],
            }],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_med_not_propagated_to_other_as() {
    // RFC 4271 Section 5.1.4: MULTI_EXIT_DISC must not cross AS boundaries
    //
    // "The MULTI_EXIT_DISC attribute received from a neighboring AS MUST NOT
    //  be propagated to other neighboring ASes."
    //
    // Topology: S1(AS65000) -> S2(AS65001) -> S3(AS65002)
    //                          eBGP           eBGP
    //
    // Verify MED is NOT propagated to other neighboring ASes:
    // - S1 originates route with MED=50
    // - S2 receives via eBGP with MED=50
    // - S3 receives via eBGP with MED=None (MED was NOT propagated to different AS)
    let [server1, server2, server3] = &mut chain_servers([
        start_test_server(
            65000,
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

    // S1 originates a route with MED=50
    server1
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            Some(50), // Set MED=50
            false,
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify S2 first (eBGP): receives route with MED=50
    poll_route_propagation(&[(
        &server2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65000])],
                "1.1.1.1",
                server1.address.clone(),
                Origin::Igp,
                Some(100), // LOCAL_PREF set by policy
                Some(50),  // MED=50 received from S1
                false,
            )],
        }],
    )])
    .await;

    // Verify S3 (eBGP to different AS): receives route with MED=None
    // This proves MED was NOT propagated to other neighboring AS (AS65002)
    poll_route_propagation(&[(
        &server3,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65001, 65000])], // eBGP: S2 prepended AS65001
                "2.2.2.2",                             // eBGP: NEXT_HOP rewritten
                server2.address.clone(),
                Origin::Igp,
                Some(100), // LOCAL_PREF set by policy
                None,      // MED=None (NOT 50 from S1 - proves MED not propagated to other AS)
                false,
            )],
        }],
    )])
    .await;
}

#[tokio::test]
async fn test_atomic_aggregate_propagation() {
    // RFC 4271 Section 5.1.6: ATOMIC_AGGREGATE propagation
    //
    // "A BGP speaker that receives a route with the ATOMIC_AGGREGATE attribute
    //  SHOULD NOT remove the attribute when propagating the route to other speakers."
    //
    // Topology: S1(AS65001) -> S2(AS65002) -> S3(AS65002)
    //                          eBGP           iBGP
    //
    // Verify ATOMIC_AGGREGATE is propagated in both eBGP and iBGP:
    // - S1 originates route with ATOMIC_AGGREGATE=true
    // - S2 receives via eBGP with ATOMIC_AGGREGATE=true
    // - S3 receives via iBGP with ATOMIC_AGGREGATE=true (proves propagation)
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
            65002,
            std::net::Ipv4Addr::new(3, 3, 3, 3),
            None,
            "127.0.0.3",
        )
        .await,
    ])
    .await;

    // S1 originates a route with ATOMIC_AGGREGATE=true
    server1
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            None,
            true, // ATOMIC_AGGREGATE=true
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify S2 (eBGP): receives route with ATOMIC_AGGREGATE=true
    poll_route_propagation(&[(
        &server2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65001])], // eBGP: S1 prepended its AS
                "1.1.1.1",                      // eBGP: NEXT_HOP rewritten to S1's router ID
                server1.address.clone(),
                Origin::Igp,
                Some(100), // LOCAL_PREF set by DefaultLocalPref policy
                None,
                true, // ATOMIC_AGGREGATE=true (received from S1)
            )],
        }],
    )])
    .await;

    // Verify S3 (iBGP): receives route with ATOMIC_AGGREGATE=true
    // This proves ATOMIC_AGGREGATE was propagated over iBGP
    poll_route_propagation(&[(
        &server3,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65001])], // iBGP: AS_PATH preserved
                "1.1.1.1",                      // iBGP: NEXT_HOP preserved
                server2.address.clone(),
                Origin::Igp,
                Some(100), // LOCAL_PREF preserved from S2
                None,
                true, // ATOMIC_AGGREGATE=true (propagated from S1 -> S2 -> S3)
            )],
        }],
    )])
    .await;
}
