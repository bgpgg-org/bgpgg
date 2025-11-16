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
//! This module tests AS_PATH manipulation:
//! - Originating routes: empty AS_PATH to iBGP peers, [local_AS] to eBGP peers
//! - eBGP: prepend local AS to AS_PATH when advertising to external peers
//! - iBGP: do NOT modify AS_PATH when advertising to internal peers

mod common;
pub use common::*;

use bgpgg::grpc::proto::Route;

#[tokio::test]
async fn test_as_path_prepending_ebgp_vs_ibgp() {
    // RFC 4271 Section 5.1.2: AS_PATH handling
    //
    // eBGP: When advertising to external peer, prepend local AS to AS_PATH
    // iBGP: When advertising to internal peer, AS_PATH MUST NOT be modified
    //
    // Topology: S1(AS65001) -> S2(AS65002) -> S3(AS65002) -> S4(AS65003)
    //                          eBGP           iBGP           eBGP
    let mut servers = [
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
    ];

    chain_servers(&mut servers).await;

    let [server1, server2, server3, server4] = &mut servers;

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

    // Verify AS_PATH at each hop:
    //
    // S1 -> S2 (eBGP): S1 creates AS_PATH=[65001]
    // S2 -> S3 (iBGP): S2 preserves AS_PATH=[65001] (does NOT prepend)
    // S3 -> S4 (eBGP): S3 prepends AS_PATH=[65002, 65001]
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])], // eBGP: S1 created AS_SEQUENCE with its AS
                    "192.168.1.1",
                    server1.address.clone(),
                )],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])], // iBGP: S2 did NOT modify AS_PATH
                    "192.168.1.1",
                    server2.address.clone(),
                )],
            }],
        ),
        (
            &server4,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65002, 65001])], // eBGP: S3 prepended its AS
                    "192.168.1.1",
                    server3.address.clone(),
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
    let mut servers = [
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
    ];

    chain_servers(&mut servers).await;

    let [server1, server2, server3] = &mut servers;

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

    // Verify AS_PATH at each hop:
    //
    // S1 -> S2 (iBGP): S1 sends empty AS_PATH (case b)
    // S2 -> S3 (eBGP): S2 creates AS_PATH=[65001] (prepends its AS)
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![], // iBGP: originating speaker sends empty AS_PATH
                    "192.168.1.1",
                    server1.address.clone(),
                )],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![as_sequence(vec![65001])], // eBGP: S2 prepended AS65001
                    "192.168.1.1",
                    server2.address.clone(),
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

    let mut servers = [
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
    ];

    chain_servers(&mut servers).await;

    let [server1, server2] = &mut servers;

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
                "192.168.1.1",
                server1.address.clone(),
            )],
        }],
    )])
    .await;
}
