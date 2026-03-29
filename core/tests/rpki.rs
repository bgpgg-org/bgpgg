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

use bgpgg::bgp::ext_community::from_rpki_state_community;
use bgpgg::config::{Config, RpkiCacheConfig, TransportType};
use bgpgg::grpc::proto::{
    extended_community::{Community, Opaque},
    ExtendedCommunity, RpkiValidation, SessionConfig,
};
use bgpgg::net::{IpNetwork, Ipv4Net};
use bgpgg::rpki::vrp::{RpkiValidation as RpkiState, Vrp};
use std::net::Ipv4Addr;
use tokio::io::{AsyncRead, AsyncWrite};
use utils::rtr::{FakeCache, FakeSshCache, FakeTcpCache};

fn rpki_state_ext_community(state: RpkiState) -> ExtendedCommunity {
    let ec = from_rpki_state_community(state.to_u8());
    let bytes = ec.to_be_bytes();
    ExtendedCommunity {
        community: Some(Community::Opaque(Opaque {
            is_transitive: false,
            value: bytes[2..].to_vec(),
        })),
    }
}

/// Shared validation body: inject VRPs, announce routes, verify Valid/Invalid/NotFound.
async fn verify_basic_validation<S: AsyncRead + AsyncWrite + Unpin>(
    cache: &mut FakeCache<S>,
    server1: &TestServer,
    server2: &TestServer,
    server3: &TestServer,
) {
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
        (server2, "10.0.0.0/24"),
        (server2, "192.168.1.0/24"),
        (server3, "10.1.0.0/24"),
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
        server1,
        vec![
            expected_route(
                "10.0.0.0/24",
                PathParams {
                    rpki_validation: RpkiValidation::RpkiValid as i32,
                    ..PathParams::from_peer(server2)
                },
            ),
            expected_route(
                "192.168.1.0/24",
                PathParams {
                    rpki_validation: RpkiValidation::RpkiNotFound as i32,
                    ..PathParams::from_peer(server2)
                },
            ),
            expected_route(
                "10.1.0.0/24",
                PathParams {
                    rpki_validation: RpkiValidation::RpkiInvalid as i32,
                    ..PathParams::from_peer(server3)
                },
            ),
        ],
    )])
    .await;
}

/// Basic validation state over TCP transport.
#[tokio::test]
async fn test_rpki_basic_validation_tcp() {
    let mut cache = FakeTcpCache::listen().await;
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
    cache.accept().await;
    verify_basic_validation(&mut cache.cache, &server1, &server2, &server3).await;
}

/// Basic validation state over SSH transport.
#[tokio::test]
async fn test_rpki_basic_validation_ssh() {
    let mut cache = FakeSshCache::listen().await;
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
                    address: cache.address().to_string(),
                    transport: TransportType::Ssh,
                    ssh_username: Some("test".to_string()),
                    ssh_private_key_file: Some(cache.client_key_path().to_string()),
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
    cache.accept().await;
    verify_basic_validation(&mut cache.cache, &server1, &server2, &server3).await;
}

/// RFC 8097: RPKI state extended community send and eBGP stripping.
#[tokio::test]
async fn test_rpki_state_community_send_and_strip() {
    let mut cache = FakeTcpCache::listen().await;

    let validator = start_test_server(Config {
        asn: 65001,
        listen_addr: "127.0.0.1:0".to_string(),
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        rpki_caches: vec![RpkiCacheConfig {
            address: cache.address(),
            ..Default::default()
        }],
        ..Default::default()
    })
    .await;
    let receiver = start_test_server(Config::new(
        65001,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
    ))
    .await;
    let downstream = start_test_server(Config::new(
        65003,
        "127.0.0.3:0",
        Ipv4Addr::new(3, 3, 3, 3),
        90,
    ))
    .await;

    // validator <-> receiver (iBGP): send_rpki_community on this link
    peer_servers_with_config(
        &validator,
        &receiver,
        SessionConfig {
            send_rpki_community: Some(true),
            ..Default::default()
        },
    )
    .await;

    // validator <-> downstream (eBGP): default config
    peer_servers(&validator, &downstream).await;

    // Accept RPKI cache and provide VRPs
    cache.accept().await;
    cache.read_reset_query().await;
    cache
        .send_vrps(&[Vrp {
            prefix: IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 0, 0),
                prefix_length: 8,
            }),
            max_length: 24,
            origin_as: 65001,
        }])
        .await;

    // Validator announces its own route: 10.0.0.0/24 (Valid per VRP, origin AS matches)
    announce_route(
        &validator,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: validator.address.to_string(),
            ..Default::default()
        },
    )
    .await;

    poll_rib(&[
        (
            &receiver,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    next_hop: validator.address.to_string(),
                    peer_address: validator.address.to_string(),
                    local_pref: Some(100),
                    extended_communities: vec![rpki_state_ext_community(RpkiState::NotFound)],
                    ..Default::default()
                },
            )],
        ),
        (
            &downstream,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    as_path: vec![as_sequence(vec![65001])],
                    next_hop: validator.address.to_string(),
                    peer_address: validator.address.to_string(),
                    local_pref: Some(100),
                    extended_communities: vec![],
                    ..Default::default()
                },
            )],
        ),
    ])
    .await;
}

/// gRPC: GetRpkiValidation returns correct state and covering VRPs.
#[tokio::test]
async fn test_rpki_grpc_get_validation() {
    let mut cache = FakeTcpCache::listen().await;
    let server = start_test_server(Config {
        asn: 65001,
        listen_addr: "127.0.0.1:0".to_string(),
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        rpki_caches: vec![RpkiCacheConfig {
            address: cache.address(),
            ..Default::default()
        }],
        ..Default::default()
    })
    .await;

    cache.accept().await;
    cache.read_reset_query().await;

    // Inject VRP: 10.0.0.0/8 max /24 AS 65002
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

    // Wait for VRPs to be applied
    poll_until(
        || async {
            let resp = server.client.list_rpki_caches().await.unwrap();
            resp.total_vrp_count > 0
        },
        "VRPs not applied to server",
    )
    .await;

    // Valid: prefix covered, origin matches
    let resp = server
        .client
        .get_rpki_validation("10.0.0.0/24".to_string(), 65002)
        .await
        .unwrap();
    assert_eq!(resp.validation, RpkiValidation::RpkiValid as i32);
    assert_eq!(resp.covering_vrps.len(), 1);
    assert_eq!(resp.covering_vrps[0].prefix, "10.0.0.0/8");
    assert_eq!(resp.covering_vrps[0].max_length, 24);
    assert_eq!(resp.covering_vrps[0].origin_as, 65002);

    // Invalid: prefix covered, origin mismatch
    let resp = server
        .client
        .get_rpki_validation("10.1.0.0/24".to_string(), 65099)
        .await
        .unwrap();
    assert_eq!(resp.validation, RpkiValidation::RpkiInvalid as i32);
    assert!(!resp.covering_vrps.is_empty());

    // NotFound: no covering VRPs
    let resp = server
        .client
        .get_rpki_validation("192.168.1.0/24".to_string(), 65002)
        .await
        .unwrap();
    assert_eq!(resp.validation, RpkiValidation::RpkiNotFound as i32);
    assert!(resp.covering_vrps.is_empty());
}
