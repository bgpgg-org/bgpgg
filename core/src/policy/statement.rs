use crate::bgp::utils::IpNetwork;
use crate::policy::action::{Accept, Action, Reject, SetLocalPref};
use crate::policy::condition::{AsPathCondition, Condition, RouteType, RouteTypeCondition};
use crate::rib::Path;

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
    statements: Vec<Statement>,
}

impl Policy {
    pub fn new() -> Self {
        Self {
            statements: Vec::new(),
        }
    }

    /// Create a default inbound policy with AS loop prevention and default local pref
    pub fn default_in(local_asn: u16) -> Self {
        Self::new()
            .add(stmt_reject_as_loop(local_asn))
            .add(stmt_default_local_pref(100))
            .add(Statement::new().then(Accept))
    }

    /// Create a default outbound policy with iBGP reflection prevention
    pub fn default_out(local_asn: u16, peer_asn: u16) -> Self {
        if local_asn == peer_asn {
            Self::new()
                .add(stmt_reject_ibgp())
                .add(Statement::new().then(Accept))
        } else {
            Self::new().add(Statement::new().then(Accept))
        }
    }

    /// Add a statement to the policy
    pub fn add(mut self, statement: Statement) -> Self {
        self.statements.push(statement);
        self
    }

    /// Evaluate the policy against a route
    /// Returns true if the route is accepted, false if rejected
    /// If no statements match, rejects the route
    pub fn accept(&self, prefix: &IpNetwork, path: &mut Path) -> bool {
        // Try each statement in order
        for statement in &self.statements {
            if let Some(accept) = statement.apply(prefix, path) {
                return accept;
            }
        }
        // No statement matched - reject by default
        false
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
        let policy = Policy::new().add(Statement::new().then(Accept));
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
            .add(
                Statement::new()
                    .when(PrefixCondition::new(prefix))
                    .then(SetLocalPref::new(200)),
            )
            .add(Statement::new().then(SetLocalPref::new(100)));

        let mut path1 = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&prefix, &mut path1));
        assert_eq!(path1.local_pref, Some(200));

        let mut path2 = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&other_prefix, &mut path2));
        assert_eq!(path2.local_pref, Some(100));
    }

    #[test]
    fn test_stmt_default_local_pref() {
        let policy = Policy::new().add(stmt_default_local_pref(100));
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&test_prefix(), &mut path));
        assert_eq!(path.local_pref, Some(100));
    }

    #[test]
    fn test_stmt_reject_as_loop() {
        let policy = Policy::new().add(stmt_reject_as_loop(65000));
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
            .add(stmt_reject_ibgp())
            .add(Statement::new().then(Accept));
        let mut ibgp_path = create_path(RouteSource::Ibgp(test_ip(1)));
        assert!(!policy.accept(&test_prefix(), &mut ibgp_path));
        let mut ebgp_path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&test_prefix(), &mut ebgp_path));
    }
}
