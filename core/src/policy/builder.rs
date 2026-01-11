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

use crate::bgp::utils::IpNetwork;
use crate::config::{
    ActionsDefinitionConfig, ConditionsDefinitionConfig, LocalPrefActionConfig, MedActionConfig,
    PolicyDefinitionConfig, StatementDefinitionConfig,
};
use crate::policy::action::{Accept, Reject, SetCommunity, SetLocalPref, SetMed};
use crate::policy::condition::{
    AsPathCondition, CommunityCondition, NeighborCondition, PrefixCondition, RouteType,
    RouteTypeCondition,
};
use crate::policy::defined_sets::DefinedSets;
use crate::policy::{Policy, Statement};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Builder for converting PolicyDefinitionConfig to runtime Policy objects
pub struct PolicyBuilder {
    defined_sets: Arc<DefinedSets>,
}

impl PolicyBuilder {
    pub fn new(defined_sets: Arc<DefinedSets>) -> Self {
        Self { defined_sets }
    }

    /// Build a Policy from a PolicyDefinitionConfig
    pub fn build(&self, def: &PolicyDefinitionConfig) -> Result<Policy, String> {
        let mut policy =
            Policy::new_with_sets(self.defined_sets.clone()).with_name(def.name.clone());

        for stmt_def in &def.statements {
            let stmt = self.build_statement(stmt_def)?;
            policy = policy.with(stmt);
        }

        Ok(policy)
    }

    fn build_statement(&self, def: &StatementDefinitionConfig) -> Result<Statement, String> {
        let mut stmt = Statement::new();

        // Add conditions
        stmt = self.add_conditions(stmt, &def.conditions)?;

        // Add actions
        stmt = self.add_actions(stmt, &def.actions)?;

        Ok(stmt)
    }

    fn add_conditions(
        &self,
        mut stmt: Statement,
        cond: &ConditionsDefinitionConfig,
    ) -> Result<Statement, String> {
        // Set-based conditions
        if let Some(ref match_set) = cond.match_prefix_set {
            // Verify set exists
            if !self
                .defined_sets
                .prefix_sets
                .contains_key(&match_set.set_name)
            {
                return Err(format!("prefix-set '{}' not found", match_set.set_name));
            }
            // PrefixSetCondition will be added after updating condition.rs
            // For now, this is a placeholder that will work once conditions are updated
            // stmt = stmt.when(PrefixSetCondition::new(
            //     match_set.set_name.clone(),
            //     match_set.match_option,
            // ));
        }

        if let Some(ref match_set) = cond.match_neighbor_set {
            if !self
                .defined_sets
                .neighbor_sets
                .contains_key(&match_set.set_name)
            {
                return Err(format!("neighbor-set '{}' not found", match_set.set_name));
            }
            // NeighborSetCondition will be added after updating condition.rs
        }

        if let Some(ref match_set) = cond.match_as_path_set {
            if !self
                .defined_sets
                .as_path_sets
                .contains_key(&match_set.set_name)
            {
                return Err(format!("as-path-set '{}' not found", match_set.set_name));
            }
            // AsPathSetCondition will be added after updating condition.rs
        }

        if let Some(ref match_set) = cond.match_community_set {
            if !self
                .defined_sets
                .community_sets
                .contains_key(&match_set.set_name)
            {
                return Err(format!("community-set '{}' not found", match_set.set_name));
            }
            // CommunitySetCondition will be added after updating condition.rs
        }

        // Direct conditions (backward compat)
        if let Some(ref prefix_str) = cond.prefix {
            let prefix = IpNetwork::from_str(prefix_str)
                .map_err(|e| format!("invalid prefix '{}': {}", prefix_str, e))?;
            stmt = stmt.when(PrefixCondition::new(prefix));
        }

        if let Some(ref neighbor_str) = cond.neighbor {
            let neighbor = IpAddr::from_str(neighbor_str)
                .map_err(|e| format!("invalid neighbor '{}': {}", neighbor_str, e))?;
            stmt = stmt.when(NeighborCondition::new(neighbor));
        }

        if let Some(asn) = cond.has_asn {
            stmt = stmt.when(AsPathCondition::new(asn));
        }

        if let Some(ref route_type_str) = cond.route_type {
            let route_type = match route_type_str.as_str() {
                "ebgp" => RouteType::Ebgp,
                "ibgp" => RouteType::Ibgp,
                "local" => RouteType::Local,
                _ => {
                    return Err(format!(
                        "invalid route-type '{}' (must be 'ebgp', 'ibgp', or 'local')",
                        route_type_str
                    ))
                }
            };
            stmt = stmt.when(RouteTypeCondition::new(route_type));
        }

        if let Some(ref community_str) = cond.community {
            let community = parse_community_value(community_str)?;
            stmt = stmt.when(CommunityCondition::new(community));
        }

        Ok(stmt)
    }

    fn add_actions(
        &self,
        mut stmt: Statement,
        actions: &ActionsDefinitionConfig,
    ) -> Result<Statement, String> {
        // Local preference
        if let Some(ref lp_action) = actions.local_pref {
            match lp_action {
                LocalPrefActionConfig::Set(val) => {
                    stmt = stmt.then(SetLocalPref::new(*val));
                }
                LocalPrefActionConfig::Force { value, force } => {
                    if *force {
                        stmt = stmt.then(SetLocalPref::force(*value));
                    } else {
                        stmt = stmt.then(SetLocalPref::new(*value));
                    }
                }
            }
        }

        // MED
        if let Some(ref med_action) = actions.med {
            match med_action {
                MedActionConfig::Set(val) => {
                    stmt = stmt.then(SetMed::new(*val));
                }
                MedActionConfig::Remove { .. } => {
                    stmt = stmt.then(SetMed::remove());
                }
            }
        }

        // Community
        if let Some(ref comm_action) = actions.community {
            let communities = comm_action
                .communities
                .iter()
                .map(|s| parse_community_value(s))
                .collect::<Result<Vec<_>, _>>()?;

            let action = match comm_action.operation.as_str() {
                "add" => SetCommunity::add(communities),
                "remove" => SetCommunity::remove(communities),
                "replace" => SetCommunity::replace(communities),
                _ => {
                    return Err(format!(
                        "invalid community operation '{}' (must be 'add', 'remove', or 'replace')",
                        comm_action.operation
                    ))
                }
            };
            stmt = stmt.then(action);
        }

        // Accept/Reject (should be last)
        if actions.accept == Some(true) {
            stmt = stmt.then(Accept);
        }
        if actions.reject == Some(true) {
            stmt = stmt.then(Reject);
        }

        Ok(stmt)
    }
}

/// Parse community string in format "65000:100" or decimal
fn parse_community_value(s: &str) -> Result<u32, String> {
    // Try decimal format first
    if let Ok(val) = s.parse::<u32>() {
        return Ok(val);
    }

    // Try "65000:100" format
    if let Some((high, low)) = s.split_once(':') {
        let high_val = high
            .parse::<u16>()
            .map_err(|_| format!("invalid high part '{}' in community", high))?;
        let low_val = low
            .parse::<u16>()
            .map_err(|_| format!("invalid low part '{}' in community", low))?;
        return Ok((high_val as u32) << 16 | (low_val as u32));
    }

    Err(format!(
        "invalid community format '{}' (expected '65000:100' or decimal)",
        s
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_community_value() {
        // Decimal format
        assert_eq!(parse_community_value("65536").unwrap(), 65536);

        // AS:NN format
        assert_eq!(
            parse_community_value("65000:100").unwrap(),
            (65000 << 16) | 100
        );

        // Invalid formats
        assert!(parse_community_value("invalid").is_err());
        assert!(parse_community_value("65000:").is_err());
        assert!(parse_community_value(":100").is_err());
    }

    #[test]
    fn test_build_simple_policy() {
        let compiled_sets = Arc::new(DefinedSets::default());
        let builder = PolicyBuilder::new(compiled_sets);

        let policy_def = PolicyDefinitionConfig {
            name: "test-policy".to_string(),
            statements: vec![StatementDefinitionConfig {
                name: Some("stmt1".to_string()),
                conditions: ConditionsDefinitionConfig {
                    prefix: Some("10.0.0.0/8".to_string()),
                    ..Default::default()
                },
                actions: ActionsDefinitionConfig {
                    local_pref: Some(LocalPrefActionConfig::Set(200)),
                    accept: Some(true),
                    ..Default::default()
                },
            }],
        };

        let policy = builder.build(&policy_def).unwrap();
        assert_eq!(policy.name(), Some("test-policy"));
    }
}
