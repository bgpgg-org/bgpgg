use crate::config::{
    ActionsDefinitionConfig, ConditionsDefinitionConfig, LocalPrefActionConfig, MedActionConfig,
    PolicyDefinitionConfig, StatementDefinitionConfig,
};
use crate::net::IpNetwork;
use crate::policy::action::{Accept, Action, Reject, SetCommunity, SetLocalPref, SetMed};
use crate::policy::condition::{
    AsPathCondition, AsPathSetCondition, CommunityCondition, CommunitySetCondition, Condition,
    NeighborCondition, NeighborSetCondition, PrefixCondition, PrefixSetCondition, RouteType,
    RouteTypeCondition,
};
use crate::policy::sets::DefinedSets;
use crate::rib::Path;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Result of policy evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyResult {
    /// Accept route, stop processing
    Accept,
    /// Reject route, stop processing
    Reject,
    /// No match, try next policy
    Continue,
}

/// A policy statement: if conditions match, apply actions
pub struct Statement {
    conditions: Vec<Box<dyn Condition>>,
    actions: Vec<Box<dyn Action>>,
}

impl Statement {
    pub fn new() -> Self {
        Self {
            conditions: Vec::new(),
            actions: Vec::new(),
        }
    }

    /// Add a condition that must match for this statement to apply
    pub fn when<C: Condition + 'static>(mut self, condition: C) -> Self {
        self.conditions.push(Box::new(condition));
        self
    }

    /// Add an action to apply if all conditions match
    pub fn then<A: Action + 'static>(mut self, action: A) -> Self {
        self.actions.push(Box::new(action));
        self
    }

    /// Check if all conditions match
    fn matches(&self, prefix: &IpNetwork, path: &Path) -> bool {
        // Empty conditions means match everything
        self.conditions.is_empty() || self.conditions.iter().all(|c| c.matches(prefix, path))
    }

    /// Apply all actions if conditions match
    /// Returns None if no match, Some(accept) if matched
    fn apply(&self, prefix: &IpNetwork, path: &mut Path) -> Option<bool> {
        if self.matches(prefix, path) {
            let mut accept = true;
            for action in &self.actions {
                if !action.apply(path) {
                    accept = false;
                }
            }
            Some(accept)
        } else {
            None // Didn't match, try next statement
        }
    }
}

impl Default for Statement {
    fn default() -> Self {
        Self::new()
    }
}

/// A policy consisting of multiple statements evaluated in order
pub struct Policy {
    name: Option<String>,
    statements: Vec<Statement>,
}

impl Policy {
    pub fn new() -> Self {
        Self {
            name: None,
            statements: Vec::new(),
        }
    }

    /// Set the policy name (for debugging)
    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Get the policy name
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Create a default inbound policy with AS loop prevention and default local pref
    pub fn default_in(local_asn: u16) -> Self {
        Self::new()
            .with(stmt_reject_as_loop(local_asn))
            .with(stmt_default_local_pref(100))
            .with(Statement::new().then(Accept))
    }

    /// Create a default outbound policy with iBGP reflection prevention
    pub fn default_out(local_asn: u16, peer_asn: u16) -> Self {
        if local_asn == peer_asn {
            Self::new()
                .with(stmt_reject_ibgp())
                .with(Statement::new().then(Accept))
        } else {
            Self::new().with(Statement::new().then(Accept))
        }
    }

    /// Create a policy from YAML config
    pub fn from_config(
        def: &PolicyDefinitionConfig,
        defined_sets: &DefinedSets,
    ) -> Result<Self, String> {
        let mut policy = Policy::new().with_name(def.name.clone());

        for stmt_def in &def.statements {
            let stmt = build_statement(stmt_def, defined_sets)?;
            policy = policy.with(stmt);
        }

        Ok(policy)
    }

    /// Add a statement to the policy
    pub fn with(mut self, statement: Statement) -> Self {
        self.statements.push(statement);
        self
    }

    /// Evaluate the policy against a route
    /// Returns PolicyResult indicating whether to Accept, Reject, or Continue
    pub fn evaluate(&self, prefix: &IpNetwork, path: &mut Path) -> PolicyResult {
        // Try each statement in order
        for statement in &self.statements {
            if let Some(accept) = statement.apply(prefix, path) {
                return if accept {
                    PolicyResult::Accept
                } else {
                    PolicyResult::Reject
                };
            }
        }
        // No statement matched - continue to next policy
        PolicyResult::Continue
    }

    /// Evaluate the policy against a route (convenience wrapper)
    /// Returns true if the route is accepted, false if rejected
    /// If no statements match, rejects the route
    pub fn accept(&self, prefix: &IpNetwork, path: &mut Path) -> bool {
        matches!(self.evaluate(prefix, path), PolicyResult::Accept)
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

/// Set default local preference if not already set
pub fn stmt_default_local_pref(value: u32) -> Statement {
    Statement::new().then(SetLocalPref::new(value))
}

/// Reject routes with local ASN in AS_PATH (AS loop prevention)
pub fn stmt_reject_as_loop(local_asn: u16) -> Statement {
    Statement::new()
        .when(AsPathCondition::new(local_asn))
        .then(Reject)
}

/// Reject routes learned via iBGP (for export to iBGP peers)
pub fn stmt_reject_ibgp() -> Statement {
    Statement::new()
        .when(RouteTypeCondition::new(RouteType::Ibgp))
        .then(Reject)
}

/// Build a statement from config
fn build_statement(
    def: &StatementDefinitionConfig,
    defined_sets: &DefinedSets,
) -> Result<Statement, String> {
    let mut stmt = Statement::new();

    // Add conditions
    stmt = add_conditions(stmt, &def.conditions, defined_sets)?;

    // Add actions
    stmt = add_actions(stmt, &def.actions)?;

    Ok(stmt)
}

/// Add conditions to a statement
fn add_conditions(
    mut stmt: Statement,
    cond: &ConditionsDefinitionConfig,
    defined_sets: &DefinedSets,
) -> Result<Statement, String> {
    // Set-based conditions - resolve sets at construction time
    if let Some(ref match_set) = cond.match_prefix_set {
        let prefix_set = defined_sets
            .prefix_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("prefix-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(PrefixSetCondition::new(
            Arc::new(prefix_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_neighbor_set {
        let neighbor_set = defined_sets
            .neighbor_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("neighbor-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(NeighborSetCondition::new(
            Arc::new(neighbor_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_as_path_set {
        let as_path_set = defined_sets
            .as_path_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("as-path-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(AsPathSetCondition::new(
            Arc::new(as_path_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_community_set {
        let community_set = defined_sets
            .community_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("community-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(CommunitySetCondition::new(
            Arc::new(community_set.clone()),
            match_set.match_option,
        ));
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

/// Add actions to a statement
fn add_actions(
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
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType};
    use crate::net::Ipv4Net;
    use crate::policy::action::{Accept, Reject, SetLocalPref, SetMed};
    use crate::policy::condition::{NeighborCondition, PrefixCondition};
    use crate::policy::test_helpers::{create_path, test_prefix};
    use crate::rib::RouteSource;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn test_statement_no_conditions() {
        let statement = Statement::new().then(SetLocalPref::new(100));
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert_eq!(statement.apply(&test_prefix(), &mut path), Some(true));
        assert_eq!(path.local_pref, Some(100));
    }

    #[test]
    fn test_statement_condition() {
        let prefix = test_prefix();
        let other_prefix = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(192, 168, 1, 0),
            prefix_length: 24,
        });
        let statement = Statement::new()
            .when(PrefixCondition::new(prefix))
            .then(SetLocalPref::new(200));
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));

        assert_eq!(statement.apply(&prefix, &mut path), Some(true));
        assert_eq!(path.local_pref, Some(200));

        path.local_pref = None;
        assert_eq!(statement.apply(&other_prefix, &mut path), None);
        assert_eq!(path.local_pref, None);
    }

    #[test]
    fn test_statement_multiple_conditions() {
        let prefix = test_prefix();
        let statement = Statement::new()
            .when(PrefixCondition::new(prefix))
            .when(NeighborCondition::new(test_ip(1)))
            .then(SetLocalPref::new(200));

        let mut path1 = create_path(RouteSource::Ebgp(test_ip(1)));
        assert_eq!(statement.apply(&prefix, &mut path1), Some(true));
        assert_eq!(path1.local_pref, Some(200));

        let mut path2 = create_path(RouteSource::Ebgp(test_ip(2)));
        assert_eq!(statement.apply(&prefix, &mut path2), None);
        assert_eq!(path2.local_pref, None);
    }

    #[test]
    fn test_statement_multiple_actions() {
        let statement = Statement::new()
            .then(SetLocalPref::new(200))
            .then(SetMed::remove());
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        path.med = Some(100);
        assert_eq!(statement.apply(&test_prefix(), &mut path), Some(true));
        assert_eq!(path.local_pref, Some(200));
        assert_eq!(path.med, None);
    }

    #[test]
    fn test_statement_reject() {
        let statement = Statement::new().then(Reject);
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert_eq!(statement.apply(&test_prefix(), &mut path), Some(false));
    }

    #[test]
    fn test_policy_accept_all() {
        let policy = Policy::new().with(Statement::new().then(Accept));
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&test_prefix(), &mut path));
    }

    #[test]
    fn test_policy_empty_rejects() {
        let policy = Policy::new();
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(!policy.accept(&test_prefix(), &mut path));
    }

    #[test]
    fn test_policy_statement_ordering() {
        let prefix = test_prefix();
        let other_prefix = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(192, 168, 1, 0),
            prefix_length: 24,
        });
        let policy = Policy::new()
            .with(
                Statement::new()
                    .when(PrefixCondition::new(prefix))
                    .then(SetLocalPref::new(200)),
            )
            .with(Statement::new().then(SetLocalPref::new(100)));

        let mut path1 = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&prefix, &mut path1));
        assert_eq!(path1.local_pref, Some(200));

        let mut path2 = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&other_prefix, &mut path2));
        assert_eq!(path2.local_pref, Some(100));
    }

    #[test]
    fn test_stmt_default_local_pref() {
        let policy = Policy::new().with(stmt_default_local_pref(100));
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&test_prefix(), &mut path));
        assert_eq!(path.local_pref, Some(100));
    }

    #[test]
    fn test_stmt_reject_as_loop() {
        let policy = Policy::new().with(stmt_reject_as_loop(65000));
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        path.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 1,
            asn_list: vec![65000],
        }];
        assert!(!policy.accept(&test_prefix(), &mut path));
    }

    #[test]
    fn test_stmt_reject_ibgp() {
        let policy = Policy::new()
            .with(stmt_reject_ibgp())
            .with(Statement::new().then(Accept));
        let mut ibgp_path = create_path(RouteSource::Ibgp(test_ip(1)));
        assert!(!policy.accept(&test_prefix(), &mut ibgp_path));
        let mut ebgp_path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&test_prefix(), &mut ebgp_path));
    }

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
    fn test_policy_from_config() {
        use crate::config::ConditionsDefinitionConfig;

        let defined_sets = DefinedSets::default();

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

        let policy = Policy::from_config(&policy_def, &defined_sets).unwrap();
        assert_eq!(policy.name(), Some("test-policy"));
    }
}
