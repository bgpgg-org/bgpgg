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

use bgpgg::bgp::msg_update::{attr_flags, attr_type_code};
use bgpgg::bgp::msg_update_types::{community, well_known_communities};
use bgpgg::config::Config;
use bgpgg::grpc::proto::{AsPathSegment, BgpState, Origin, Route, UnknownAttribute};
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_origin_preservation() {
    // RFC 4271 Section 5.1.1: ORIGIN attribute
    // "Its value SHOULD NOT be changed by any other speaker."
    //
    // Topology: S1(AS65001) -> S2(AS65002) -> S3(AS65003)
    //                          eBGP           eBGP
    let [server1, server2, server3] = &mut chain_servers([
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65003,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            90,
            true,
        ))
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
                        Some(100),
                        None,
                        false,
                        vec![],
                        vec![],
                    )],
                })
                .collect()
        };

    // Verify ORIGIN is preserved at each hop
    // eBGP rewrites NEXT_HOP to local address of the sending speaker
    poll_route_propagation(&[
        (
            server2,
            build_expected_routes(
                vec![as_sequence(vec![65001])],
                &server1.address,
                server1.address.clone(),
            ),
        ),
        (
            server3,
            build_expected_routes(
                vec![as_sequence(vec![65002, 65001])],
                &server2.address,
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
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65003,
            "127.0.0.4:0",
            Ipv4Addr::new(4, 4, 4, 4),
            90,
            true,
        ))
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
            server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])], // eBGP: S1 created AS_SEQUENCE with its AS
                    &server1.address, // eBGP: NEXT_HOP rewritten to S1's local address
                    server1.address.clone(),
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
            server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])], // iBGP: S2 did NOT modify AS_PATH
                    &server1.address,               // iBGP: NEXT_HOP preserved from S2
                    server2.address.clone(),
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
            server4,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65002, 65001])], // eBGP: S3 prepended its AS
                    &server3.address, // eBGP: NEXT_HOP rewritten to S3's local address
                    server3.address.clone(),
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
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65001,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            90,
            true,
        ))
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
            server2,
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
                    vec![],
                    vec![],
                )],
            }],
        ),
        (
            server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])], // eBGP: S2 prepended AS65001
                    &server2.address, // eBGP: NEXT_HOP rewritten to S2's local address
                    server2.address.clone(),
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
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
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
            vec![],
        )
        .await
        .expect("Failed to add route from server 1");

    // Verify S2 receives the route with AS_SEQUENCE[65001] prepended
    // Result: AS_SEQUENCE[65001], AS_SET[65003, 65004], AS_SEQUENCE[65005]
    // eBGP: NEXT_HOP rewritten to S1's router ID
    poll_route_propagation(&[(
        server2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![
                    as_sequence(vec![65001]),   // Prepended by S1 (eBGP)
                    as_set(vec![65003, 65004]), // Original AS_SET
                    as_sequence(vec![65005]),   // Original AS_SEQUENCE
                ],
                &server1.address, // eBGP: NEXT_HOP rewritten to S1's local address
                server1.address.clone(),
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
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65001,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
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
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // RFC expectation: S2 should receive the route with NEXT_HOP set to S1's local address
    // (the interface address used for the peering session)
    poll_route_propagation(&[(
        server2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![],           // iBGP: empty AS_PATH for locally-originated route
                &server1.address, // NEXT_HOP should be set to S1's local address
                server1.address.clone(),
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
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65001,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            90,
            true,
        ))
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
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify NEXT_HOP handling:
    // S1 -> S2 (iBGP): NEXT_HOP preserved as 192.168.1.100
    // S2 -> S3 (eBGP): NEXT_HOP rewritten to S2's local address (2.2.2.2)
    poll_route_propagation(&[
        (
            server2,
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
                    vec![],
                    vec![],
                )],
            }],
        ),
        (
            server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])], // eBGP: AS prepended
                    &server2.address, // eBGP: NEXT_HOP rewritten to S2's local address
                    server2.address.clone(),
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
        start_test_server(Config::new(
            65000,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65001,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65001,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            90,
            true,
        ))
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
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify:
    // S2 (eBGP): receives route with LOCAL_PREF=100 (set by DefaultLocalPref policy)
    // S3 (iBGP): receives route with LOCAL_PREF=100 (proves LOCAL_PREF was in UPDATE from S2)
    poll_route_propagation(&[
        (
            server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65000])],
                    &server1.address,
                    server1.address.clone(),
                    Origin::Igp,
                    Some(100), // LOCAL_PREF set by DefaultLocalPref policy
                    None,
                    false,
                    vec![],
                    vec![],
                )],
            }],
        ),
        (
            server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65000])], // iBGP preserves AS_PATH
                    &server1.address,               // iBGP preserves NEXT_HOP
                    server2.address.clone(),
                    Origin::Igp,
                    Some(100), // LOCAL_PREF preserved from S2's UPDATE (proves it was included)
                    None,
                    false,
                    vec![],
                    vec![],
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
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65001,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            90,
            true,
        ))
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
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify S2 first (iBGP): receives route with LOCAL_PREF=200 (preserved from S1)
    poll_route_propagation(&[(
        server2,
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
                vec![],
                vec![],
            )],
        }],
    )])
    .await;

    // Verify S3 (eBGP): receives route with LOCAL_PREF=100 (set by DefaultLocalPref policy, NOT from S2)
    //                   This proves LOCAL_PREF was NOT sent in UPDATE from S2 to S3
    poll_route_propagation(&[(
        server3,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65001])], // eBGP: AS prepended
                &server2.address,               // eBGP: NEXT_HOP rewritten
                server2.address.clone(),
                Origin::Igp,
                Some(100), // LOCAL_PREF=100 (set by policy, NOT 200 from S2!)
                None,
                false,
                vec![],
                vec![],
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
        start_test_server(Config::new(
            65000,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65001,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65001,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            90,
            true,
        ))
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
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify:
    // S2 (eBGP): receives route with MED=50
    // S3 (iBGP): receives route with MED=50 (proves MED was propagated over iBGP)
    poll_route_propagation(&[
        (
            server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65000])],
                    &server1.address,
                    server1.address.clone(),
                    Origin::Igp,
                    Some(100), // LOCAL_PREF set by DefaultLocalPref policy
                    Some(50),  // MED=50 received from S1
                    false,
                    vec![],
                    vec![],
                )],
            }],
        ),
        (
            server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65000])], // iBGP preserves AS_PATH
                    &server1.address,               // iBGP preserves NEXT_HOP
                    server2.address.clone(),
                    Origin::Igp,
                    Some(100), // LOCAL_PREF preserved from S2
                    Some(50),  // MED=50 propagated over iBGP (proves propagation)
                    false,
                    vec![],
                    vec![],
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
        start_test_server(Config::new(
            65000,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65001,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            90,
            true,
        ))
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
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify S2 first (eBGP): receives route with MED=50
    poll_route_propagation(&[(
        server2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65000])],
                &server1.address,
                server1.address.clone(),
                Origin::Igp,
                Some(100), // LOCAL_PREF set by policy
                Some(50),  // MED=50 received from S1
                false,
                vec![],
                vec![],
            )],
        }],
    )])
    .await;

    // Verify S3 (eBGP to different AS): receives route with MED=None
    // This proves MED was NOT propagated to other neighboring AS (AS65002)
    poll_route_propagation(&[(
        server3,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65001, 65000])], // eBGP: S2 prepended AS65001
                &server2.address,                      // eBGP: NEXT_HOP rewritten
                server2.address.clone(),
                Origin::Igp,
                Some(100), // LOCAL_PREF set by policy
                None,      // MED=None (NOT 50 from S1 - proves MED not propagated to other AS)
                false,
                vec![],
                vec![],
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
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            90,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            90,
            true,
        ))
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
            vec![],
        )
        .await
        .expect("Failed to announce route from server 1");

    // Verify S2 (eBGP): receives route with ATOMIC_AGGREGATE=true
    poll_route_propagation(&[(
        server2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65001])], // eBGP: S1 prepended its AS
                &server1.address,               // eBGP: NEXT_HOP rewritten to S1's local address
                server1.address.clone(),
                Origin::Igp,
                Some(100), // LOCAL_PREF set by DefaultLocalPref policy
                None,
                true, // ATOMIC_AGGREGATE=true (received from S1)
                vec![],
                vec![],
            )],
        }],
    )])
    .await;

    // Verify S3 (iBGP): receives route with ATOMIC_AGGREGATE=true
    // This proves ATOMIC_AGGREGATE was propagated over iBGP
    poll_route_propagation(&[(
        server3,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65001])], // iBGP: AS_PATH preserved
                &server1.address,               // iBGP: NEXT_HOP preserved
                server2.address.clone(),
                Origin::Igp,
                Some(100), // LOCAL_PREF preserved from S2
                None,
                true, // ATOMIC_AGGREGATE=true (propagated from S1 -> S2 -> S3)
                vec![],
                vec![],
            )],
        }],
    )])
    .await;
}

#[tokio::test]
async fn test_unknown_optional_attribute_handling_transitive() {
    test_unknown_optional_attribute_handling(
        attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
        vec![UnknownAttribute {
            attr_type: 200,
            flags: (attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::PARTIAL) as u32,
            value: vec![0xde, 0xad, 0xbe, 0xef],
        }],
    )
    .await;
}

#[tokio::test]
async fn test_unknown_optional_attribute_handling_non_transitive() {
    test_unknown_optional_attribute_handling(attr_flags::OPTIONAL, vec![]).await;
}

async fn test_unknown_optional_attribute_handling(
    attr_flags: u8,
    expected_unknown_attrs: Vec<UnknownAttribute>,
) {
    // Topology: FakePeer(S1) -> S2(AS65002) -> S3(AS65003)
    //                            iBGP            eBGP
    let [server2, server3] = &mut chain_servers([
        start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            300,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65003,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            300,
            true,
        ))
        .await,
    ])
    .await;

    let mut server1 = FakePeer::connect(None, server2).await;
    server1
        .handshake_open(65002, std::net::Ipv4Addr::new(1, 1, 1, 1), 300)
        .await;
    server1.handshake_keepalive().await;

    let origin_attr = build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 1, &[0]);
    let as_path_attr = build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::AS_PATH, 0, &[]);
    let next_hop_attr = build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::NEXT_HOP,
        4,
        &[10, 0, 0, 1],
    );
    let unknown_attr = build_attr_bytes(attr_flags, 200, 4, &[0xde, 0xad, 0xbe, 0xef]);

    let nlri = vec![24, 192, 168, 1];
    let msg = build_raw_update(
        &[],
        &[&origin_attr, &as_path_attr, &next_hop_attr, &unknown_attr],
        &nlri,
        None,
    );

    server1.send_raw(&msg).await;

    poll_route_propagation(&[(
        server3,
        vec![Route {
            prefix: "192.168.1.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65002])],
                &server2.address,
                server2.address.clone(),
                Origin::Igp,
                Some(100),
                None,
                false,
                expected_unknown_attrs,
                vec![],
            )],
        }],
    )])
    .await;
}

#[tokio::test]
async fn test_med_comparison_restricted_to_same_as() {
    // RFC 4271 Section 9.1.2.2(c): MED is only comparable between routes
    // from the same neighboring AS.
    //
    // Topology:  S1(AS65001, MED=100) ---\
    //            S2(AS65001, MED=50)  ----+--- S4(AS65004)
    //            S3(AS65002, MED=10)  ---/
    //
    // S4 receives three routes for 10.0.0.0/24:
    // - From S1 (AS65001): MED=100
    // - From S2 (AS65001): MED=50  <- wins among AS65001 routes
    // - From S3 (AS65002): MED=10  <- lowest MED but different AS
    //
    // Expected winner: S2 (AS65001, MED=50)
    // - S1 vs S2: same AS, MED compared -> S2 wins (50 < 100)
    // - S2 vs S3: different AS, MED NOT compared -> falls to peer address -> S2 wins (127.0.0.2 < 127.0.0.3)
    let mut server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;
    let mut server2 = start_test_server(Config::new(
        65001,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
        true,
    ))
    .await;
    let mut server3 = start_test_server(Config::new(
        65002,
        "127.0.0.3:0",
        Ipv4Addr::new(3, 3, 3, 3),
        90,
        true,
    ))
    .await;
    let server4 = start_test_server(Config::new(
        65004,
        "127.0.0.4:0",
        Ipv4Addr::new(4, 4, 4, 4),
        90,
        true,
    ))
    .await;

    // Connect S1, S2, S3 to S4 (star topology)
    server1
        .client
        .add_peer(format!("{}:{}", server4.address, server4.bgp_port), None)
        .await
        .unwrap();
    server2
        .client
        .add_peer(format!("{}:{}", server4.address, server4.bgp_port), None)
        .await
        .unwrap();
    server3
        .client
        .add_peer(format!("{}:{}", server4.address, server4.bgp_port), None)
        .await
        .unwrap();

    // Wait for all peers to establish
    poll_until(
        || async {
            verify_peers(
                &server4,
                vec![
                    server1.to_peer(BgpState::Established, false),
                    server2.to_peer(BgpState::Established, false),
                    server3.to_peer(BgpState::Established, false),
                ],
            )
            .await
        },
        "Timeout waiting for peers to establish",
    )
    .await;

    // All announce same prefix with different MEDs
    server1
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            Some(100),
            false,
            vec![],
        )
        .await
        .unwrap();

    server2
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.2.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            Some(50),
            false,
            vec![],
        )
        .await
        .unwrap();

    server3
        .client
        .add_route(
            "10.0.0.0/24".to_string(),
            "192.168.3.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            Some(10),
            false,
            vec![],
        )
        .await
        .unwrap();

    // S4 should select S2's route (AS65001, MED=50)
    // This proves: MED compared within AS65001 (S2 beat S1)
    //              MED NOT compared across ASes (S2 beat S3 despite higher MED)
    poll_route_propagation(&[(
        &server4,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65001])],
                &server2.address,
                server2.address.clone(),
                Origin::Igp,
                Some(100),
                Some(50),
                false,
                vec![],
                vec![],
            )],
        }],
    )])
    .await;
}

#[tokio::test]
async fn test_normal_community_propagation() {
    let (mut server1, server2) = setup_two_peered_servers(None).await;

    let communities = vec![
        community::from_asn_value(65001, 100),
        community::from_asn_value(65001, 200),
        community::from_asn_value(65001, 300),
    ];

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
            communities.clone(),
        )
        .await
        .expect("Failed to add route");

    poll_route_propagation(&[(
        &server2,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(
                vec![as_sequence(vec![65001])],
                &server1.address,
                server1.address.clone(),
                Origin::Igp,
                Some(100),
                None,
                false,
                vec![],
                communities,
            )],
        }],
    )])
    .await;
}

#[tokio::test]
async fn test_well_known_communities() {
    let (mut server1, server2) = setup_two_peered_servers(None).await;

    // Add routes with well-known communities (should be filtered)
    server1
        .client
        .add_route(
            "10.1.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            None,
            false,
            vec![well_known_communities::NO_ADVERTISE],
        )
        .await
        .expect("Failed to add route");

    server1
        .client
        .add_route(
            "10.2.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            None,
            false,
            vec![well_known_communities::NO_EXPORT],
        )
        .await
        .expect("Failed to add route");

    server1
        .client
        .add_route(
            "10.3.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            None,
            false,
            vec![well_known_communities::NO_EXPORT_SUBCONFED],
        )
        .await
        .expect("Failed to add route");

    // Add normal route (should propagate)
    server1
        .client
        .add_route(
            "10.4.0.0/24".to_string(),
            "192.168.1.1".to_string(),
            Origin::Igp,
            vec![],
            None,
            None,
            false,
            vec![],
        )
        .await
        .expect("Failed to add route");

    // Poll for 3 seconds: only normal route propagates, only 1 UPDATE sent
    poll_while(
        || async {
            let Ok(routes) = server2.client.get_routes().await else {
                return false;
            };

            routes_match(
                &routes,
                &[Route {
                    prefix: "10.4.0.0/24".to_string(),
                    paths: vec![build_path(
                        vec![as_sequence(vec![65001])],
                        &server1.address,
                        server1.address.clone(),
                        Origin::Igp,
                        Some(100),
                        None,
                        false,
                        vec![],
                        vec![],
                    )],
                }],
            ) && server1
                .client
                .get_peer(server2.address.clone())
                .await
                .ok()
                .and_then(|(_, stats)| stats)
                .is_some_and(|s| s.update_sent == 1)
        },
        std::time::Duration::from_secs(3),
        "Route propagation and UPDATE count validation",
    )
    .await;
}
