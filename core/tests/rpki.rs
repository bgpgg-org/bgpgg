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

use bgpgg::config::{Config, RpkiCacheConfig};
use bgpgg::grpc::proto::RpkiValidation;
use bgpgg::net::{IpNetwork, Ipv4Net};
use bgpgg::rpki::vrp::Vrp;
use std::net::Ipv4Addr;
use utils::rtr::FakeCache;

/// Phase 10 test case 1: Basic validation state.
/// Inject VRPs via FakeCache, announce routes from peers with different origin ASes,
/// verify Valid/Invalid/NotFound via gRPC rpki_validation field.
#[tokio::test]
async fn test_rpki_basic_validation_state() {
    let mut cache = FakeCache::listen().await;

    // Chain: server2 (AS 65002) <-> server1 (AS 65001) <-> server3 (AS 65099)
    let [server2, server1, server3] = chain_servers(
        [
            start_test_server(Config::new(
                65002,
                "127.0.0.2:0",
                Ipv4Addr::new(2, 2, 2, 2),
                90,
            ))
            .await,
            start_test_server(Config {
                asn: 65001,
                listen_addr: "127.0.0.1:0".to_string(),
                router_id: Ipv4Addr::new(1, 1, 1, 1),
                rpki_caches: vec![RpkiCacheConfig {
                    address: cache.address(),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .await,
            start_test_server(Config::new(
                65099,
                "127.0.0.3:0",
                Ipv4Addr::new(3, 3, 3, 3),
                90,
            ))
            .await,
        ],
        PeerConfig::default(),
    )
    .await;

    // FakeCache: accept CacheSession, respond with VRPs
    cache.accept().await;
    cache.read_reset_query().await;

    // VRP: 10.0.0.0/8 max /24 AS 65002
    cache
        .send_vrps(&[Vrp {
            prefix: IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 0, 0),
                prefix_length: 8,
            }),
            max_length: 24,
            origin_as: 65002,
        }])
        .await;

    // Announce routes:
    //   10.0.0.0/24 from AS 65002 -> Valid (VRP covers, origin matches)
    //   192.168.1.0/24 from AS 65002 -> NotFound (no VRP covers this prefix)
    //   10.1.0.0/24 from AS 65099 -> Invalid (VRP covers, origin AS mismatch)
    for (server, prefix) in [
        (&server2, "10.0.0.0/24"),
        (&server2, "192.168.1.0/24"),
        (&server3, "10.1.0.0/24"),
    ] {
        announce_route(
            server,
            RouteParams {
                prefix: prefix.to_string(),
                next_hop: server.address.to_string(),
                ..Default::default()
            },
        )
        .await;
    }

    poll_rib(&[(
        &server1,
        vec![
            expected_route(
                "10.0.0.0/24",
                PathParams {
                    rpki_validation: RpkiValidation::RpkiValid as i32,
                    ..PathParams::from_peer(&server2)
                },
            ),
            expected_route(
                "192.168.1.0/24",
                PathParams {
                    rpki_validation: RpkiValidation::RpkiNotFound as i32,
                    ..PathParams::from_peer(&server2)
                },
            ),
            expected_route(
                "10.1.0.0/24",
                PathParams {
                    rpki_validation: RpkiValidation::RpkiInvalid as i32,
                    ..PathParams::from_peer(&server3)
                },
            ),
        ],
    )])
    .await;
}
