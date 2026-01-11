pub mod sets;
pub mod statement;

pub use statement::{
    stmt_default_local_pref, stmt_reject_as_loop, stmt_reject_ibgp, CommunityOp, Policy,
    PolicyResult, RouteType, Statement,
};

// Re-export runtime structures
pub use sets::{DefinedSetType, DefinedSets};

use crate::config::Config;
use std::collections::HashMap;
use std::sync::Arc;

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
    use crate::bgp::msg_update::Origin;
    use crate::net::{IpNetwork, Ipv4Net};
    use crate::rib::{Path, RouteSource};
    use std::net::Ipv4Addr;

    pub fn create_path(source: RouteSource) -> Path {
        Path {
            origin: Origin::IGP,
            as_path: vec![],
            next_hop: Ipv4Addr::new(10, 0, 0, 1),
            source,
            local_pref: None,
            med: None,
            atomic_aggregate: false,
            communities: vec![],
            unknown_attrs: vec![],
        }
    }

    pub fn test_prefix() -> IpNetwork {
        IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        })
    }
}
