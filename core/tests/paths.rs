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
//! This module tests the behavior of BGP path attributes, particularly AS_PATH
//! manipulation and propagation in both iBGP and eBGP scenarios.

mod common;
pub use common::*;

use bgpgg::grpc::proto::Route;

#[tokio::test]
async fn test_as_path_prepending_chain() {
    // RFC 4271 Section 5.1.2
    // Topology: AS65001 -> AS65002 -> AS65003
    //                      eBGP       eBGP
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
            65003,
            std::net::Ipv4Addr::new(3, 3, 3, 3),
            None,
            "127.0.0.3",
        )
        .await,
    ];

    chain_servers(&mut servers).await;

    let [server1, server2, server3] = &mut servers;

    // Server1 announces a route
    server1
        .client
        .announce_route("10.0.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route propagation with expected AS_PATH growth
    // S2 should see AS_PATH = [65001]
    // S3 should see AS_PATH = [65002, 65001] (AS65002 prepended by S2)
    poll_route_propagation(&[
        (
            server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![65001],
                    "192.168.1.1",
                    server1.address.clone(),
                )],
            }],
        ),
        (
            server3,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![65002, 65001],
                    "192.168.1.1",
                    server2.address.clone(),
                )],
            }],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_ibgp_ebgp_as_path_chain() {
    // RFC 4271 Section 5.1.2 and 9.1.2.1
    // iBGP should NOT modify AS_PATH, eBGP should prepend local AS
    // Topology: AS65001 -> AS65002 -> AS65002 -> AS65003
    //                      eBGP       iBGP       eBGP
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

    // Server1 announces a route
    server1
        .client
        .announce_route("10.0.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route propagation with expected AS_PATH behavior (RFC 4271 Section 5.1.2)
    // S1 (AS65001) originates, sends to S2 (AS65002) via eBGP: AS_PATH = [65001]
    // S2 receives [65001], sends to S3 (AS65002) via iBGP: AS_PATH = [65001] (unchanged)
    // S3 receives [65001], sends to S4 (AS65003) via eBGP: AS_PATH = [65002, 65001]
    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.0.0.0/24".to_string(),
                paths: vec![build_path(
                    vec![65001],
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
                    vec![65001],
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
                    vec![65002, 65001],
                    "192.168.1.1",
                    server3.address.clone(),
                )],
            }],
        ),
    ])
    .await;
}
