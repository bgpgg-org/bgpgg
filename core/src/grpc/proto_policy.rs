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

//! Policy proto conversions
//!
//! This module handles conversion between bgpgg's internal policy configuration
//! types and the protobuf Policy/DefinedSet message formats.

use super::proto::{
    ActionsConfig as ProtoActionsConfig, AsPathSetData, CommunitySetData,
    ConditionsConfig as ProtoConditionsConfig, DefinedSetConfig as ProtoDefinedSetConfig,
    DefinedSetInfo, MatchSetRef, NeighborSetData, PolicyInfo, PrefixMatch, PrefixSetData,
    StatementInfo,
};
use crate::config::{
    ActionsConfig, AsPathSetConfig, CommunityActionConfig, CommunitySetConfig, ConditionsConfig,
    DefinedSetConfig, LocalPrefActionConfig, MatchOptionConfig, MatchSetRefConfig, MedActionConfig,
    NeighborSetConfig, PrefixMatchConfig, PrefixSetConfig, StatementConfig,
};
use crate::server::PolicyInfoResponse;

pub(super) fn proto_to_defined_set_config(
    proto: &ProtoDefinedSetConfig,
) -> Result<DefinedSetConfig, String> {
    let name = proto.name.clone();

    let config = match proto.config.as_ref() {
        Some(super::proto::defined_set_config::Config::PrefixSet(ps)) => {
            let prefixes = ps
                .prefixes
                .iter()
                .map(|p| PrefixMatchConfig {
                    prefix: p.prefix.clone(),
                    masklength_range: p.masklength_range.clone(),
                })
                .collect();
            DefinedSetConfig::PrefixSet(PrefixSetConfig { name, prefixes })
        }
        Some(super::proto::defined_set_config::Config::AsPathSet(aps)) => {
            DefinedSetConfig::AsPathSet(AsPathSetConfig {
                name,
                patterns: aps.patterns.clone(),
            })
        }
        Some(super::proto::defined_set_config::Config::CommunitySet(cs)) => {
            DefinedSetConfig::CommunitySet(CommunitySetConfig {
                name,
                communities: cs.communities.clone(),
            })
        }
        Some(super::proto::defined_set_config::Config::NeighborSet(ns)) => {
            DefinedSetConfig::NeighborSet(NeighborSetConfig {
                name,
                neighbors: ns.addresses.clone(),
            })
        }
        Some(super::proto::defined_set_config::Config::ExtCommunitySet(ecs)) => {
            DefinedSetConfig::ExtCommunitySet(crate::config::ExtCommunitySetConfig {
                name,
                ext_communities: ecs.ext_communities.clone(),
            })
        }
        Some(super::proto::defined_set_config::Config::LargeCommunitySet(lcs)) => {
            DefinedSetConfig::LargeCommunitySet(crate::config::LargeCommunitySetConfig {
                name,
                large_communities: lcs.large_communities.clone(),
            })
        }
        None => return Err("missing set config data".to_string()),
    };

    Ok(config)
}

pub(super) fn proto_to_statement_config(
    proto: super::proto::StatementConfig,
) -> Result<StatementConfig, String> {
    let conditions = proto.conditions.map(|c| {
        let parse_match_option = |opt: String| match opt.as_str() {
            "all" => MatchOptionConfig::All,
            "invert" => MatchOptionConfig::Invert,
            _ => MatchOptionConfig::Any,
        };

        ConditionsConfig {
            match_prefix_set: c.match_prefix_set.map(|m| MatchSetRefConfig {
                set_name: m.set_name,
                match_option: parse_match_option(m.match_option),
            }),
            match_neighbor_set: c.match_neighbor_set.map(|m| MatchSetRefConfig {
                set_name: m.set_name,
                match_option: parse_match_option(m.match_option),
            }),
            match_as_path_set: c.match_as_path_set.map(|m| MatchSetRefConfig {
                set_name: m.set_name,
                match_option: parse_match_option(m.match_option),
            }),
            match_community_set: c.match_community_set.map(|m| MatchSetRefConfig {
                set_name: m.set_name,
                match_option: parse_match_option(m.match_option),
            }),
            match_ext_community_set: c.match_ext_community_set.map(|m| MatchSetRefConfig {
                set_name: m.set_name,
                match_option: parse_match_option(m.match_option),
            }),
            match_large_community_set: c.match_large_community_set.map(|m| MatchSetRefConfig {
                set_name: m.set_name,
                match_option: parse_match_option(m.match_option),
            }),
            prefix: c.prefix,
            neighbor: c.neighbor,
            has_asn: None,
            route_type: None,
            community: None,
        }
    });

    let actions = proto.actions.map(|a| ActionsConfig {
        local_pref: a.local_pref.map(LocalPrefActionConfig::Set),
        med: a.med.map(MedActionConfig::Set),
        community: if !a.add_communities.is_empty() || !a.remove_communities.is_empty() {
            Some(CommunityActionConfig {
                operation: if !a.add_communities.is_empty() {
                    "add".to_string()
                } else {
                    "remove".to_string()
                },
                communities: if !a.add_communities.is_empty() {
                    a.add_communities
                } else {
                    a.remove_communities
                },
            })
        } else {
            None
        },
        ext_community: None,   // TODO: Add proto support for extended communities
        large_community: None, // TODO: Add proto support for large communities
        accept: a.accept,
        reject: a.reject,
    });

    Ok(StatementConfig {
        name: None,
        conditions: conditions.unwrap_or_default(),
        actions: actions.unwrap_or_default(),
    })
}

pub(super) fn defined_set_config_to_proto(config: DefinedSetConfig) -> DefinedSetInfo {
    let (set_type, name, set_data) = match config {
        DefinedSetConfig::PrefixSet(ps) => (
            "prefix-set".to_string(),
            ps.name,
            Some(super::proto::defined_set_info::SetData::PrefixSet(
                PrefixSetData {
                    prefixes: ps
                        .prefixes
                        .into_iter()
                        .map(|p| PrefixMatch {
                            prefix: p.prefix,
                            masklength_range: p.masklength_range,
                        })
                        .collect(),
                },
            )),
        ),
        DefinedSetConfig::AsPathSet(aps) => (
            "as-path-set".to_string(),
            aps.name,
            Some(super::proto::defined_set_info::SetData::AsPathSet(
                AsPathSetData {
                    patterns: aps.patterns,
                },
            )),
        ),
        DefinedSetConfig::CommunitySet(cs) => (
            "community-set".to_string(),
            cs.name,
            Some(super::proto::defined_set_info::SetData::CommunitySet(
                CommunitySetData {
                    communities: cs.communities,
                },
            )),
        ),
        DefinedSetConfig::NeighborSet(ns) => (
            "neighbor-set".to_string(),
            ns.name,
            Some(super::proto::defined_set_info::SetData::NeighborSet(
                NeighborSetData {
                    addresses: ns.neighbors,
                },
            )),
        ),
        DefinedSetConfig::ExtCommunitySet(ecs) => (
            "ext-community-set".to_string(),
            ecs.name,
            Some(super::proto::defined_set_info::SetData::ExtCommunitySet(
                super::proto::ExtendedCommunitySetData {
                    ext_communities: ecs.ext_communities,
                },
            )),
        ),
        DefinedSetConfig::LargeCommunitySet(lcs) => (
            "large-community-set".to_string(),
            lcs.name,
            Some(super::proto::defined_set_info::SetData::LargeCommunitySet(
                super::proto::LargeCommunitySetData {
                    large_communities: lcs.large_communities,
                },
            )),
        ),
    };

    DefinedSetInfo {
        set_type,
        name,
        set_data,
    }
}

pub(super) fn policy_info_to_proto(info: PolicyInfoResponse) -> PolicyInfo {
    let statements = info
        .statements
        .into_iter()
        .map(|s| {
            let conditions = Some(ProtoConditionsConfig {
                match_prefix_set: s.conditions.match_prefix_set.map(|m| MatchSetRef {
                    set_name: m.set_name,
                    match_option: match m.match_option {
                        MatchOptionConfig::Any => "any".to_string(),
                        MatchOptionConfig::All => "all".to_string(),
                        MatchOptionConfig::Invert => "invert".to_string(),
                    },
                }),
                match_neighbor_set: s.conditions.match_neighbor_set.map(|m| MatchSetRef {
                    set_name: m.set_name,
                    match_option: match m.match_option {
                        MatchOptionConfig::Any => "any".to_string(),
                        MatchOptionConfig::All => "all".to_string(),
                        MatchOptionConfig::Invert => "invert".to_string(),
                    },
                }),
                match_as_path_set: s.conditions.match_as_path_set.map(|m| MatchSetRef {
                    set_name: m.set_name,
                    match_option: match m.match_option {
                        MatchOptionConfig::Any => "any".to_string(),
                        MatchOptionConfig::All => "all".to_string(),
                        MatchOptionConfig::Invert => "invert".to_string(),
                    },
                }),
                match_community_set: s.conditions.match_community_set.map(|m| MatchSetRef {
                    set_name: m.set_name,
                    match_option: match m.match_option {
                        MatchOptionConfig::Any => "any".to_string(),
                        MatchOptionConfig::All => "all".to_string(),
                        MatchOptionConfig::Invert => "invert".to_string(),
                    },
                }),
                match_ext_community_set: s.conditions.match_ext_community_set.map(|m| {
                    MatchSetRef {
                        set_name: m.set_name,
                        match_option: match m.match_option {
                            MatchOptionConfig::Any => "any".to_string(),
                            MatchOptionConfig::All => "all".to_string(),
                            MatchOptionConfig::Invert => "invert".to_string(),
                        },
                    }
                }),
                match_large_community_set: s.conditions.match_large_community_set.map(|m| {
                    MatchSetRef {
                        set_name: m.set_name,
                        match_option: match m.match_option {
                            MatchOptionConfig::Any => "any".to_string(),
                            MatchOptionConfig::All => "all".to_string(),
                            MatchOptionConfig::Invert => "invert".to_string(),
                        },
                    }
                }),
                prefix: s.conditions.prefix.clone(),
                neighbor: s.conditions.neighbor.clone(),
            });

            let (add_communities, remove_communities) = if let Some(comm) = s.actions.community {
                if comm.operation == "add" {
                    (comm.communities, vec![])
                } else {
                    (vec![], comm.communities)
                }
            } else {
                (vec![], vec![])
            };

            let actions = Some(ProtoActionsConfig {
                accept: s.actions.accept,
                reject: s.actions.reject,
                local_pref: s.actions.local_pref.map(|lp| match lp {
                    LocalPrefActionConfig::Set(v) => v,
                    LocalPrefActionConfig::Force { value, .. } => value,
                }),
                med: s.actions.med.and_then(|m| match m {
                    MedActionConfig::Set(v) => Some(v),
                    MedActionConfig::Remove { .. } => None,
                }),
                add_communities,
                remove_communities,
            });

            StatementInfo {
                conditions,
                actions,
            }
        })
        .collect();

    PolicyInfo {
        name: info.name,
        statements,
    }
}
