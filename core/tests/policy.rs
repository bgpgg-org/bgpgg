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

//! Policy integration tests - test actual route filtering behavior

mod utils;
pub use utils::*;

use bgpgg::grpc::proto::{
    defined_set_config, ActionsConfig, ConditionsConfig, DefinedSetConfig, Origin, PrefixMatch,
    PrefixSetData, Route, StatementConfig,
};
use tokio::time::Duration;

// Test helpers

/// Create a prefix-set with given name and prefixes
fn prefix_set(name: &str, prefixes: Vec<(&str, Option<&str>)>) -> DefinedSetConfig {
    DefinedSetConfig {
        set_type: "prefix-set".to_string(),
        name: name.to_string(),
        config: Some(defined_set_config::Config::PrefixSet(PrefixSetData {
            prefixes: prefixes
                .into_iter()
                .map(|(prefix, range)| PrefixMatch {
                    prefix: prefix.to_string(),
                    masklength_range: range.map(|s| s.to_string()),
                })
                .collect(),
        })),
    }
}

/// Create an export policy that rejects matching prefix-set, accepts rest
async fn apply_export_reject_policy(
    server: &mut TestServer,
    peer_addr: &str,
    set_name: &str,
    prefixes: Vec<(&str, Option<&str>)>,
) {
    // Add prefix-set
    server
        .client
        .add_defined_set(prefix_set(set_name, prefixes), false)
        .await
        .unwrap();

    // Create policy: reject matching prefixes, accept rest
    server
        .client
        .add_policy(
            "export-policy".to_string(),
            vec![
                StatementConfig {
                    conditions: Some(ConditionsConfig {
                        match_prefix_set: Some(bgpgg::grpc::proto::MatchSetRef {
                            set_name: set_name.to_string(),
                            match_option: "any".to_string(),
                        }),
                        ..Default::default()
                    }),
                    actions: Some(ActionsConfig {
                        reject: Some(true),
                        ..Default::default()
                    }),
                },
                StatementConfig {
                    conditions: None,
                    actions: Some(ActionsConfig {
                        accept: Some(true),
                        ..Default::default()
                    }),
                },
            ],
        )
        .await
        .unwrap();

    // Assign to peer
    server
        .client
        .set_policy_assignment(
            peer_addr.to_string(),
            "export".to_string(),
            vec!["export-policy".to_string()],
            None,
        )
        .await
        .unwrap();
}

// Tests

#[tokio::test]
async fn test_export_policy_prefix_match() {
    struct TestCase {
        desc: &'static str,
        blocked_prefixes: Vec<(&'static str, Option<&'static str>)>,
        announced: Vec<&'static str>,
        expected: Vec<&'static str>,
    }

    let cases = vec![
        TestCase {
            desc: "block single exact prefix",
            blocked_prefixes: vec![("10.1.0.0/24", None)],
            announced: vec!["10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24"],
            expected: vec!["10.0.0.0/24", "10.2.0.0/24"],
        },
        TestCase {
            desc: "block multiple prefixes",
            blocked_prefixes: vec![("10.1.0.0/24", None), ("10.2.0.0/24", None)],
            announced: vec!["10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24"],
            expected: vec!["10.0.0.0/24"],
        },
        TestCase {
            desc: "block with length range",
            blocked_prefixes: vec![("10.0.0.0/8", Some("24..32"))],
            announced: vec!["10.0.0.0/8", "10.1.0.0/24", "10.2.0.0/25"],
            expected: vec!["10.0.0.0/8"],
        },
    ];

    for tc in cases {
        let (server1, mut server2) = setup_two_peered_servers(None).await;

        // Apply export policy on server2
        apply_export_reject_policy(
            &mut server2,
            &server1.address.to_string(),
            "blocked",
            tc.blocked_prefixes,
        )
        .await;

        // Announce all routes
        for (i, prefix) in tc.announced.iter().enumerate() {
            announce_route(
                &mut server2,
                RouteParams {
                    prefix: prefix.to_string(),
                    next_hop: format!("192.168.1.{}", i + 1),
                    ..Default::default()
                },
            )
            .await;
        }

        // Build expected routes
        let peers = server1.client.get_peers().await.unwrap();
        let peer_addr = &peers[0].address;
        let expected: Vec<Route> = tc
            .expected
            .iter()
            .map(|prefix| Route {
                prefix: prefix.to_string(),
                paths: vec![build_path(PathParams {
                    as_path: vec![as_sequence(vec![65002])],
                    next_hop: server2.address.to_string(),
                    peer_address: peer_addr.clone(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                })],
            })
            .collect();

        // Verify routes propagate and stay stable
        poll_until_stable(
            || async {
                let routes = server1.client.get_routes().await.unwrap();
                routes_match(&routes, &expected)
            },
            Duration::from_millis(500),
            &format!("Test case failed: {}", tc.desc),
        )
        .await;
    }
}

#[tokio::test]
async fn test_export_policy_large_community_match() {
    use bgpgg::bgp::msg_update_types::LargeCommunity;
    use bgpgg::grpc::proto::{self, defined_set_config};

    let (server1, mut server2) = setup_two_peered_servers(None).await;

    // Add large-community-set
    server2
        .client
        .add_defined_set(
            DefinedSetConfig {
                set_type: "large-community-set".to_string(),
                name: "blocked-lcs".to_string(),
                config: Some(defined_set_config::Config::LargeCommunitySet(
                    proto::LargeCommunitySetData {
                        large_communities: vec![
                            "65536:100:200".to_string(),
                            "4200000000:1:2".to_string(),
                        ],
                    },
                )),
            },
            false,
        )
        .await
        .unwrap();

    // Create policy: reject routes with matching large communities
    server2
        .client
        .add_policy(
            "export-policy".to_string(),
            vec![
                StatementConfig {
                    conditions: Some(ConditionsConfig {
                        match_large_community_set: Some(proto::MatchSetRef {
                            set_name: "blocked-lcs".to_string(),
                            match_option: "any".to_string(),
                        }),
                        ..Default::default()
                    }),
                    actions: Some(ActionsConfig {
                        reject: Some(true),
                        ..Default::default()
                    }),
                },
                StatementConfig {
                    conditions: None,
                    actions: Some(ActionsConfig {
                        accept: Some(true),
                        ..Default::default()
                    }),
                },
            ],
        )
        .await
        .unwrap();

    // Assign to peer
    server2
        .client
        .set_policy_assignment(
            server1.address.to_string(),
            "export".to_string(),
            vec!["export-policy".to_string()],
            None,
        )
        .await
        .unwrap();

    // Announce route with blocked large community (should be rejected)
    announce_route(
        &mut server2,
        RouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            large_communities: vec![LargeCommunity::new(65536, 100, 200)],
            ..Default::default()
        },
    )
    .await;

    // Announce route with different large community (should propagate)
    announce_route(
        &mut server2,
        RouteParams {
            prefix: "10.2.0.0/24".to_string(),
            next_hop: "192.168.1.2".to_string(),
            large_communities: vec![LargeCommunity::new(65536, 999, 999)],
            ..Default::default()
        },
    )
    .await;

    // Announce route with no large communities (should propagate)
    announce_route(
        &mut server2,
        RouteParams {
            prefix: "10.3.0.0/24".to_string(),
            next_hop: "192.168.1.3".to_string(),
            ..Default::default()
        },
    )
    .await;

    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    let expected = vec![
        Route {
            prefix: "10.2.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                as_path: vec![as_sequence(vec![65002])],
                next_hop: server2.address.to_string(),
                peer_address: peer_addr.clone(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                large_communities: vec![proto::LargeCommunity {
                    global_admin: 65536,
                    local_data_1: 999,
                    local_data_2: 999,
                }],
                ..Default::default()
            })],
        },
        Route {
            prefix: "10.3.0.0/24".to_string(),
            paths: vec![build_path(PathParams {
                as_path: vec![as_sequence(vec![65002])],
                next_hop: server2.address.to_string(),
                peer_address: peer_addr.clone(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            })],
        },
    ];

    poll_until_stable(
        || async {
            let routes = server1.client.get_routes().await.unwrap();
            routes_match(&routes, &expected)
        },
        Duration::from_millis(500),
        "Routes with blocked large communities should be rejected",
    )
    .await;
}
