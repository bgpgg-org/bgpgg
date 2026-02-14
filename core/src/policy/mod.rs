pub mod sets;
pub mod statement;

pub use sets::{DefinedSetType, DefinedSets};
pub use statement::{stmt_default_local_pref, CommunityOp, RouteType, Statement};

use crate::config::{Config, PolicyDefinitionConfig};
use crate::net::IpNetwork;
use crate::rib::Path;
use std::collections::HashMap;
use std::sync::Arc;

/// Built-in policy name for default import policy
pub const BUILTIN_POLICY_DEFAULT_IN: &str = "_default_in";

/// Built-in policy name for default export policy
pub const BUILTIN_POLICY_DEFAULT_OUT: &str = "_default_out";

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

/// A policy consisting of multiple statements evaluated in order
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub name: String,
    pub built_in: bool,
    statements: Vec<Statement>,
}

impl Policy {
    pub fn new(name: String) -> Self {
        Self {
            name,
            built_in: false,
            statements: Vec::new(),
        }
    }

    fn new_built_in(name: String) -> Self {
        Self {
            name,
            built_in: true,
            statements: Vec::new(),
        }
    }

    /// Get the statements (for API responses)
    pub fn statements(&self) -> &[Statement] {
        &self.statements
    }

    /// Create a default inbound policy with default local pref
    pub fn default_in() -> Self {
        use statement::{stmt_default_local_pref, Action};
        Self::new_built_in(BUILTIN_POLICY_DEFAULT_IN.to_string())
            .with(stmt_default_local_pref(100))
            .with(Statement::new().then(Action::Accept))
    }

    /// Create a default outbound policy
    pub fn default_out() -> Self {
        use statement::Action;
        Self::new_built_in(BUILTIN_POLICY_DEFAULT_OUT.to_string())
            .with(Statement::new().then(Action::Accept))
    }

    /// Create a policy from YAML config
    pub fn from_config(
        def: &PolicyDefinitionConfig,
        defined_sets: &DefinedSets,
    ) -> Result<Self, String> {
        let mut policy = Policy::new(def.name.clone());

        for stmt_def in &def.statements {
            let stmt = statement::build_statement(stmt_def, defined_sets)?;
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
        Self::new(String::new())
    }
}

/// Policy context containing compiled policies and defined sets
pub struct PolicyContext {
    pub policies: HashMap<String, Arc<Policy>>,
    pub defined_sets: Arc<DefinedSets>,
}

impl PolicyContext {
    /// Build policy context from config
    pub fn from_config(config: &Config) -> Result<Self, String> {
        // Compile defined sets
        let defined_sets = Arc::new(DefinedSets::new(&config.defined_sets)?);

        // Build named policies
        let mut policies = HashMap::new();
        for policy_def in &config.policy_definitions {
            let policy = Policy::from_config(policy_def, &defined_sets)?;
            policies.insert(policy_def.name.clone(), Arc::new(policy));
        }

        Ok(PolicyContext {
            policies,
            defined_sets,
        })
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::bgp::msg_update::{NextHopAddr, Origin};
    use crate::net::{IpNetwork, Ipv4Net};
    use crate::rib::{Path, RouteSource};
    use std::net::Ipv4Addr;

    pub fn create_path(source: RouteSource) -> Path {
        Path {
            local_path_id: 0,
            remote_path_id: None,
            origin: Origin::IGP,
            as_path: vec![],
            next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            source,
            local_pref: None,
            med: None,
            atomic_aggregate: false,
            aggregator: None,
            communities: vec![],
            extended_communities: vec![],
            large_communities: vec![],
            unknown_attrs: vec![],
            originator_id: None,
            cluster_list: vec![],
        }
    }

    pub fn test_prefix() -> IpNetwork {
        IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        })
    }
}
