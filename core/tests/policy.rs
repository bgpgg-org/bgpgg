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

//! Policy API integration tests

mod utils;
pub use utils::*;

use bgpgg::config::Config;
use bgpgg::grpc::proto::{
    defined_set_config, defined_set_info, ActionsConfig, AsPathSetData, CommunitySetData,
    ConditionsConfig, DefinedSetConfig, DefinedSetInfo, MatchSetRef, NeighborSetData,
    PrefixMatch, PrefixSetData, PolicyInfo, StatementConfig, StatementInfo,
};
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_add_defined_sets() {
    let test_cases = vec![
        (
            "prefix-set",
            DefinedSetConfig {
                set_type: "prefix-set".to_string(),
                name: "test-prefixes".to_string(),
                config: Some(defined_set_config::Config::PrefixSet(PrefixSetData {
                    prefixes: vec![
                        PrefixMatch {
                            prefix: "10.0.0.0/8".to_string(),
                            masklength_range: Some("16..24".to_string()),
                        },
                        PrefixMatch {
                            prefix: "192.168.0.0/16".to_string(),
                            masklength_range: None,
                        },
                    ],
                })),
            },
            DefinedSetInfo {
                set_type: "prefix-set".to_string(),
                name: "test-prefixes".to_string(),
                set_data: Some(defined_set_info::SetData::PrefixSet(PrefixSetData {
                    prefixes: vec![
                        PrefixMatch {
                            prefix: "10.0.0.0/8".to_string(),
                            masklength_range: Some("16..24".to_string()),
                        },
                        PrefixMatch {
                            prefix: "192.168.0.0/16".to_string(),
                            masklength_range: None,
                        },
                    ],
                })),
            },
        ),
        (
            "neighbor-set",
            DefinedSetConfig {
                set_type: "neighbor-set".to_string(),
                name: "my-peers".to_string(),
                config: Some(defined_set_config::Config::NeighborSet(NeighborSetData {
                    addresses: vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
                })),
            },
            DefinedSetInfo {
                set_type: "neighbor-set".to_string(),
                name: "my-peers".to_string(),
                set_data: Some(defined_set_info::SetData::NeighborSet(NeighborSetData {
                    addresses: vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
                })),
            },
        ),
        (
            "as-path-set",
            DefinedSetConfig {
                set_type: "as-path-set".to_string(),
                name: "customer-asns".to_string(),
                config: Some(defined_set_config::Config::AsPathSet(AsPathSetData {
                    patterns: vec!["_65001$".to_string(), "_65002$".to_string()],
                })),
            },
            DefinedSetInfo {
                set_type: "as-path-set".to_string(),
                name: "customer-asns".to_string(),
                set_data: Some(defined_set_info::SetData::AsPathSet(AsPathSetData {
                    patterns: vec!["_65001$".to_string(), "_65002$".to_string()],
                })),
            },
        ),
        (
            "community-set",
            DefinedSetConfig {
                set_type: "community-set".to_string(),
                name: "no-export".to_string(),
                config: Some(defined_set_config::Config::CommunitySet(CommunitySetData {
                    communities: vec!["65000:100".to_string(), "65000:200".to_string()],
                })),
            },
            DefinedSetInfo {
                set_type: "community-set".to_string(),
                name: "no-export".to_string(),
                set_data: Some(defined_set_info::SetData::CommunitySet(CommunitySetData {
                    communities: vec!["65000:100".to_string(), "65000:200".to_string()],
                })),
            },
        ),
    ];

    for (desc, input, expected) in test_cases {
        let mut server = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
            true,
        ))
        .await;

        // Initially no defined sets
        let sets = server.client.list_defined_sets().await.unwrap();
        assert_eq!(sets.len(), 0, "{}: should start with no sets", desc);

        // Add the defined set
        let result = server.client.add_defined_set(input, false).await;
        assert!(result.is_ok(), "{}: add should succeed", desc);

        // Verify exact response
        let sets = server.client.list_defined_sets().await.unwrap();
        assert_eq!(sets, vec![expected], "{}: set data should match", desc);
    }
}

#[tokio::test]
async fn test_add_duplicate_set_fails() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    let prefix_set = DefinedSetConfig {
        set_type: "prefix-set".to_string(),
        name: "test-prefixes".to_string(),
        config: Some(defined_set_config::Config::PrefixSet(PrefixSetData {
            prefixes: vec![PrefixMatch {
                prefix: "10.0.0.0/8".to_string(),
                masklength_range: None,
            }],
        })),
    };

    // First add should succeed
    let result = server
        .client
        .add_defined_set(prefix_set.clone(), false)
        .await;
    assert!(result.is_ok());

    // Second add should fail (duplicate)
    let err = server
        .client
        .add_defined_set(prefix_set, false)
        .await
        .unwrap_err();
    assert!(err.message().contains("already exists"));
}

#[tokio::test]
async fn test_list_defined_sets() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    // Add two defined sets
    server
        .client
        .add_defined_set(
            DefinedSetConfig {
                set_type: "prefix-set".to_string(),
                name: "my-prefixes".to_string(),
                config: Some(defined_set_config::Config::PrefixSet(PrefixSetData {
                    prefixes: vec![PrefixMatch {
                        prefix: "10.0.0.0/8".to_string(),
                        masklength_range: None,
                    }],
                })),
            },
            false,
        )
        .await
        .unwrap();

    server
        .client
        .add_defined_set(
            DefinedSetConfig {
                set_type: "neighbor-set".to_string(),
                name: "my-neighbors".to_string(),
                config: Some(defined_set_config::Config::NeighborSet(NeighborSetData {
                    addresses: vec!["10.0.0.1".to_string()],
                })),
            },
            false,
        )
        .await
        .unwrap();

    // List and verify
    let sets = server.client.list_defined_sets().await.unwrap();
    assert_eq!(sets.len(), 2);

    let expected = vec![
        DefinedSetInfo {
            set_type: "prefix-set".to_string(),
            name: "my-prefixes".to_string(),
            set_data: Some(defined_set_info::SetData::PrefixSet(PrefixSetData {
                prefixes: vec![PrefixMatch {
                    prefix: "10.0.0.0/8".to_string(),
                    masklength_range: None,
                }],
            })),
        },
        DefinedSetInfo {
            set_type: "neighbor-set".to_string(),
            name: "my-neighbors".to_string(),
            set_data: Some(defined_set_info::SetData::NeighborSet(NeighborSetData {
                addresses: vec!["10.0.0.1".to_string()],
            })),
        },
    ];

    // Sort for consistent comparison
    let mut sets_sorted = sets.clone();
    sets_sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut expected_sorted = expected.clone();
    expected_sorted.sort_by(|a, b| a.name.cmp(&b.name));

    assert_eq!(sets_sorted, expected_sorted);
}

#[tokio::test]
async fn test_add_policy() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    // First add a defined set that the policy will reference
    server
        .client
        .add_defined_set(
            DefinedSetConfig {
                set_type: "prefix-set".to_string(),
                name: "customer-prefixes".to_string(),
                config: Some(defined_set_config::Config::PrefixSet(PrefixSetData {
                    prefixes: vec![PrefixMatch {
                        prefix: "10.0.0.0/8".to_string(),
                        masklength_range: Some("16..24".to_string()),
                    }],
                })),
            },
            false,
        )
        .await
        .unwrap();

    // Add a policy that references the defined set
    let result = server
        .client
        .add_policy(
            "customer-import".to_string(),
            vec![StatementConfig {
                conditions: Some(ConditionsConfig {
                    match_prefix_set: Some(MatchSetRef {
                        set_name: "customer-prefixes".to_string(),
                        match_option: "any".to_string(),
                    }),
                    ..Default::default()
                }),
                actions: Some(ActionsConfig {
                    local_pref: Some(200),
                    accept: Some(true),
                    ..Default::default()
                }),
            }],
        )
        .await;

    assert!(result.is_ok());

    // Verify the policy was added
    let policies = server.client.list_policies().await.unwrap();

    let expected = vec![PolicyInfo {
        name: "customer-import".to_string(),
        statements: vec![StatementInfo {
            conditions: Some(ConditionsConfig {
                match_prefix_set: Some(MatchSetRef {
                    set_name: "customer-prefixes".to_string(),
                    match_option: "any".to_string(),
                }),
                ..Default::default()
            }),
            actions: Some(ActionsConfig {
                local_pref: Some(200),
                accept: Some(true),
                ..Default::default()
            }),
        }],
    }];

    assert_eq!(policies, expected);
}

#[tokio::test]
async fn test_add_policy_missing_defined_set() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    // Try to add a policy that references a non-existent defined set
    let err = server
        .client
        .add_policy(
            "test-policy".to_string(),
            vec![StatementConfig {
                conditions: Some(ConditionsConfig {
                    match_prefix_set: Some(MatchSetRef {
                        set_name: "nonexistent-set".to_string(),
                        match_option: "any".to_string(),
                    }),
                    ..Default::default()
                }),
                actions: Some(ActionsConfig {
                    accept: Some(true),
                    ..Default::default()
                }),
            }],
        )
        .await
        .unwrap_err();

    assert!(err.message().contains("not found"));
}

