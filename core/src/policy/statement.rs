use crate::bgp::utils::IpNetwork;
use crate::policy::action::{Accept, Action, Reject, SetLocalPref};
use crate::policy::condition::{AsPathCondition, Condition, RouteType, RouteTypeCondition};
use crate::policy::defined_sets::DefinedSets;
use crate::rib::Path;
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
    fn matches(&self, prefix: &IpNetwork, path: &Path, sets: &DefinedSets) -> bool {
        // Empty conditions means match everything
        self.conditions.is_empty()
            || self
                .conditions
                .iter()
                .all(|c| c.matches(prefix, path, sets))
    }

    /// Apply all actions if conditions match
    /// Returns None if no match, Some(accept) if matched
    fn apply(&self, prefix: &IpNetwork, path: &mut Path, sets: &DefinedSets) -> Option<bool> {
        if self.matches(prefix, path, sets) {
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
    defined_sets: Arc<DefinedSets>,
}

impl Policy {
    pub fn new() -> Self {
        Self {
            name: None,
            statements: Vec::new(),
            defined_sets: Arc::new(DefinedSets::default()),
        }
    }

    /// Create a new policy with defined sets
    pub fn new_with_sets(defined_sets: Arc<DefinedSets>) -> Self {
        Self {
            name: None,
            statements: Vec::new(),
            defined_sets,
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
            if let Some(accept) = statement.apply(prefix, path, &self.defined_sets) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType};
    use crate::bgp::utils::Ipv4Net;
    use crate::policy::action::{Accept, Reject, SetLocalPref, SetMed};
    use crate::policy::condition::{NeighborCondition, PrefixCondition};
    use crate::policy::test_helpers::{create_path, test_prefix};
    use crate::rib::RouteSource;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn empty_sets() -> DefinedSets {
        DefinedSets::default()
    }

    #[test]
    fn test_statement_no_conditions() {
        let statement = Statement::new().then(SetLocalPref::new(100));
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        let sets = empty_sets();
        assert_eq!(
            statement.apply(&test_prefix(), &mut path, &sets),
            Some(true)
        );
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
        let sets = empty_sets();

        assert_eq!(statement.apply(&prefix, &mut path, &sets), Some(true));
        assert_eq!(path.local_pref, Some(200));

        path.local_pref = None;
        assert_eq!(statement.apply(&other_prefix, &mut path, &sets), None);
        assert_eq!(path.local_pref, None);
    }

    #[test]
    fn test_statement_multiple_conditions() {
        let prefix = test_prefix();
        let statement = Statement::new()
            .when(PrefixCondition::new(prefix))
            .when(NeighborCondition::new(test_ip(1)))
            .then(SetLocalPref::new(200));
        let sets = empty_sets();

        let mut path1 = create_path(RouteSource::Ebgp(test_ip(1)));
        assert_eq!(statement.apply(&prefix, &mut path1, &sets), Some(true));
        assert_eq!(path1.local_pref, Some(200));

        let mut path2 = create_path(RouteSource::Ebgp(test_ip(2)));
        assert_eq!(statement.apply(&prefix, &mut path2, &sets), None);
        assert_eq!(path2.local_pref, None);
    }

    #[test]
    fn test_statement_multiple_actions() {
        let statement = Statement::new()
            .then(SetLocalPref::new(200))
            .then(SetMed::remove());
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        let sets = empty_sets();
        path.med = Some(100);
        assert_eq!(
            statement.apply(&test_prefix(), &mut path, &sets),
            Some(true)
        );
        assert_eq!(path.local_pref, Some(200));
        assert_eq!(path.med, None);
    }

    #[test]
    fn test_statement_reject() {
        let statement = Statement::new().then(Reject);
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        let sets = empty_sets();
        assert_eq!(
            statement.apply(&test_prefix(), &mut path, &sets),
            Some(false)
        );
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
}
