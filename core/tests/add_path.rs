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

/// Two servers peered with ADD-PATH enabled, announce a route, verify it propagates.
#[tokio::test]
async fn test_addpath_basic_propagation() {
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

    // Peer with ADD-PATH enabled in both directions
    let addpath_config = SessionConfig {
        add_path_send: Some(1), // All
        add_path_receive: Some(true),
        ..Default::default()
    };

    server1.add_peer_with_config(&server2, addpath_config).await;
    server2.add_peer_with_config(&server1, addpath_config).await;

    // Wait for Established
    poll_until(
        || async {
            let Ok(peers) = server1.client.get_peers().await else {
                return false;
            };
            peers
                .iter()
                .any(|p| p.state == BgpState::Established as i32)
        },
        "Timeout waiting for Established",
    )
    .await;

    // Server1 announces a route
    let server1_addr = server1.address.to_string();
    announce_route(
        &server1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Verify server2 receives it
    poll_route_exists(
        &server2,
        Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                as_path: vec![as_sequence(vec![65001])],
                next_hop: server1_addr.clone(),
                peer_address: server1_addr,
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            })],
        },
    )
    .await;
}
