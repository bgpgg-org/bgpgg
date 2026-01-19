use crate::config::{
    ActionsConfig, ConditionsConfig, LocalPrefActionConfig, MatchOptionConfig, MedActionConfig,
    StatementConfig,
};
use crate::net::IpNetwork;
use crate::policy::sets::{
    AsPathSet, CommunitySet, DefinedSets, ExtCommunitySet, LargeCommunitySet, NeighborSet,
    PrefixSet,
};
use crate::rib::{Path, RouteSource};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

// ============================================================================
// Public types (re-exported)
// ============================================================================

/// Route type for matching route source
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteType {
    Ebgp,
    Ibgp,
    Local,
}

/// Community modification operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommunityOp {
    Add(Vec<u32>),
    Remove(Vec<u32>),
    Replace(Vec<u32>),
}

/// Extended Community modification operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtCommunityOp {
    Add(Vec<u64>),
    Remove(Vec<u64>),
    Replace(Vec<u64>),
}

/// Large Community modification operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LargeCommunityOp {
    Add(Vec<crate::bgp::msg_update_types::LargeCommunity>),
    Remove(Vec<crate::bgp::msg_update_types::LargeCommunity>),
    Replace(Vec<crate::bgp::msg_update_types::LargeCommunity>),
}

// ============================================================================
// Statement - the main type
// ============================================================================

/// A policy statement: if conditions match, apply actions
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    conditions: Vec<Condition>,
    actions: Vec<Action>,
}

impl Statement {
    pub fn new() -> Self {
        Self {
            conditions: Vec::new(),
            actions: Vec::new(),
        }
    }

    /// Add a condition that must match for this statement to apply
    pub fn when(mut self, condition: Condition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Add an action to apply if all conditions match
    pub fn then(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    /// Convert statement back to config format (for API responses)
    pub fn to_config(&self) -> StatementConfig {
        use crate::config::{CommunityActionConfig, MatchSetRefConfig};

        let mut conditions = ConditionsConfig::default();

        // Extract conditions
        for condition in &self.conditions {
            match condition {
                Condition::PrefixSet(arc_set, opt) => {
                    conditions.match_prefix_set = Some(MatchSetRefConfig {
                        set_name: arc_set.name.clone(),
                        match_option: *opt,
                    });
                }
                Condition::Prefix(ip) => {
                    conditions.prefix = Some(ip.to_string());
                }
                Condition::NeighborSet(arc_set, opt) => {
                    conditions.match_neighbor_set = Some(MatchSetRefConfig {
                        set_name: arc_set.name.clone(),
                        match_option: *opt,
                    });
                }
                Condition::Neighbor(ip) => {
                    conditions.neighbor = Some(ip.to_string());
                }
                Condition::AsPathSet(arc_set, opt) => {
                    conditions.match_as_path_set = Some(MatchSetRefConfig {
                        set_name: arc_set.name.clone(),
                        match_option: *opt,
                    });
                }
                Condition::AsPath(asn) => {
                    conditions.has_asn = Some(*asn);
                }
                Condition::CommunitySet(arc_set, opt) => {
                    conditions.match_community_set = Some(MatchSetRefConfig {
                        set_name: arc_set.name.clone(),
                        match_option: *opt,
                    });
                }
                Condition::ExtCommunitySet(arc_set, opt) => {
                    conditions.match_ext_community_set = Some(MatchSetRefConfig {
                        set_name: arc_set.name.clone(),
                        match_option: *opt,
                    });
                }
                Condition::LargeCommunitySet(arc_set, opt) => {
                    conditions.match_large_community_set = Some(MatchSetRefConfig {
                        set_name: arc_set.name.clone(),
                        match_option: *opt,
                    });
                }
                Condition::Community(comm) => {
                    let high = (*comm >> 16) as u16;
                    let low = (*comm & 0xFFFF) as u16;
                    conditions.community = Some(format!("{}:{}", high, low));
                }
                Condition::RouteType(rt) => {
                    conditions.route_type = Some(match rt {
                        RouteType::Ebgp => "ebgp".to_string(),
                        RouteType::Ibgp => "ibgp".to_string(),
                        RouteType::Local => "local".to_string(),
                    });
                }
            }
        }

        let mut actions = ActionsConfig::default();

        // Extract actions
        for action in &self.actions {
            match action {
                Action::Accept => {
                    actions.accept = Some(true);
                }
                Action::Reject => {
                    actions.reject = Some(true);
                }
                Action::SetLocalPref { value, force } => {
                    actions.local_pref = Some(if *force {
                        LocalPrefActionConfig::Force {
                            value: *value,
                            force: true,
                        }
                    } else {
                        LocalPrefActionConfig::Set(*value)
                    });
                }
                Action::SetMed(value) => {
                    actions.med = value
                        .map(MedActionConfig::Set)
                        .or(Some(MedActionConfig::Remove { remove: true }));
                }
                Action::SetCommunity(op) => match op {
                    CommunityOp::Add(comms) => {
                        actions.community = Some(CommunityActionConfig {
                            operation: "add".to_string(),
                            communities: comms
                                .iter()
                                .map(|c| {
                                    let high = (*c >> 16) as u16;
                                    let low = (*c & 0xFFFF) as u16;
                                    format!("{}:{}", high, low)
                                })
                                .collect(),
                        });
                    }
                    CommunityOp::Remove(comms) => {
                        actions.community = Some(CommunityActionConfig {
                            operation: "remove".to_string(),
                            communities: comms
                                .iter()
                                .map(|c| {
                                    let high = (*c >> 16) as u16;
                                    let low = (*c & 0xFFFF) as u16;
                                    format!("{}:{}", high, low)
                                })
                                .collect(),
                        });
                    }
                    CommunityOp::Replace(comms) => {
                        actions.community = Some(CommunityActionConfig {
                            operation: "replace".to_string(),
                            communities: comms
                                .iter()
                                .map(|c| {
                                    let high = (*c >> 16) as u16;
                                    let low = (*c & 0xFFFF) as u16;
                                    format!("{}:{}", high, low)
                                })
                                .collect(),
                        });
                    }
                },
                Action::SetExtCommunity(op) => {
                    use crate::bgp::ext_community::format_extended_community;
                    use crate::config::ExtCommunityActionConfig;

                    match op {
                        ExtCommunityOp::Add(ecs) => {
                            actions.ext_community = Some(ExtCommunityActionConfig {
                                operation: "add".to_string(),
                                ext_communities: ecs
                                    .iter()
                                    .map(|ec| format_extended_community(*ec))
                                    .collect(),
                            });
                        }
                        ExtCommunityOp::Remove(ecs) => {
                            actions.ext_community = Some(ExtCommunityActionConfig {
                                operation: "remove".to_string(),
                                ext_communities: ecs
                                    .iter()
                                    .map(|ec| format_extended_community(*ec))
                                    .collect(),
                            });
                        }
                        ExtCommunityOp::Replace(ecs) => {
                            actions.ext_community = Some(ExtCommunityActionConfig {
                                operation: "replace".to_string(),
                                ext_communities: ecs
                                    .iter()
                                    .map(|ec| format_extended_community(*ec))
                                    .collect(),
                            });
                        }
                    }
                }
                Action::SetLargeCommunity(op) => {
                    use crate::config::LargeCommunityActionConfig;

                    match op {
                        LargeCommunityOp::Add(lcs) => {
                            actions.large_community = Some(LargeCommunityActionConfig {
                                operation: "add".to_string(),
                                large_communities: lcs.iter().map(|lc| lc.to_string()).collect(),
                            });
                        }
                        LargeCommunityOp::Remove(lcs) => {
                            actions.large_community = Some(LargeCommunityActionConfig {
                                operation: "remove".to_string(),
                                large_communities: lcs.iter().map(|lc| lc.to_string()).collect(),
                            });
                        }
                        LargeCommunityOp::Replace(lcs) => {
                            actions.large_community = Some(LargeCommunityActionConfig {
                                operation: "replace".to_string(),
                                large_communities: lcs.iter().map(|lc| lc.to_string()).collect(),
                            });
                        }
                    }
                }
            }
        }

        StatementConfig {
            name: None,
            conditions,
            actions,
        }
    }

    /// Check if all conditions match
    fn matches(&self, prefix: &IpNetwork, path: &Path) -> bool {
        // Empty conditions means match everything
        self.conditions.is_empty() || self.conditions.iter().all(|c| c.matches(prefix, path))
    }

    /// Apply all actions if conditions match
    /// Returns None if no match, Some(accept) if matched
    pub(super) fn apply(&self, prefix: &IpNetwork, path: &mut Path) -> Option<bool> {
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

// ============================================================================
// Action - what statements do
// ============================================================================

/// Action enum - all possible action types
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Accept,
    Reject,
    SetLocalPref { value: u32, force: bool },
    SetMed(Option<u32>),
    SetCommunity(CommunityOp),
    SetExtCommunity(ExtCommunityOp),
    SetLargeCommunity(LargeCommunityOp),
}

impl Action {
    fn apply(&self, path: &mut Path) -> bool {
        match self {
            Action::Accept => true,
            Action::Reject => false,
            Action::SetLocalPref { value, force } => {
                if *force || path.local_pref.is_none() {
                    path.local_pref = Some(*value);
                }
                true
            }
            Action::SetMed(value) => {
                path.med = *value;
                true
            }
            Action::SetCommunity(op) => {
                match op {
                    CommunityOp::Add(to_add) => {
                        for &comm in to_add {
                            if !path.communities.contains(&comm) {
                                path.communities.push(comm);
                            }
                        }
                    }
                    CommunityOp::Remove(to_remove) => {
                        path.communities.retain(|comm| !to_remove.contains(comm));
                    }
                    CommunityOp::Replace(new_communities) => {
                        path.communities = new_communities.clone();
                    }
                }
                true
            }
            Action::SetExtCommunity(op) => {
                match op {
                    ExtCommunityOp::Add(to_add) => {
                        for &ec in to_add {
                            if !path.extended_communities.contains(&ec) {
                                path.extended_communities.push(ec);
                            }
                        }
                    }
                    ExtCommunityOp::Remove(to_remove) => {
                        path.extended_communities
                            .retain(|ec| !to_remove.contains(ec));
                    }
                    ExtCommunityOp::Replace(new_ext_communities) => {
                        path.extended_communities = new_ext_communities.clone();
                    }
                }
                true
            }
            Action::SetLargeCommunity(op) => {
                match op {
                    LargeCommunityOp::Add(to_add) => {
                        for &lc in to_add {
                            if !path.large_communities.contains(&lc) {
                                path.large_communities.push(lc);
                            }
                        }
                    }
                    LargeCommunityOp::Remove(to_remove) => {
                        path.large_communities.retain(|lc| !to_remove.contains(lc));
                    }
                    LargeCommunityOp::Replace(new_large_communities) => {
                        path.large_communities = new_large_communities.clone();
                    }
                }
                true
            }
        }
    }
}

// ============================================================================
// Condition - what statements match
// ============================================================================

/// Condition enum - all possible condition types
#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    Prefix(IpNetwork),
    PrefixSet(Arc<PrefixSet>, MatchOptionConfig),
    Neighbor(IpAddr),
    NeighborSet(Arc<NeighborSet>, MatchOptionConfig),
    AsPath(u16),
    AsPathSet(Arc<AsPathSet>, MatchOptionConfig),
    Community(u32),
    CommunitySet(Arc<CommunitySet>, MatchOptionConfig),
    ExtCommunitySet(Arc<ExtCommunitySet>, MatchOptionConfig),
    LargeCommunitySet(Arc<LargeCommunitySet>, MatchOptionConfig),
    RouteType(RouteType),
}

impl Condition {
    fn matches(&self, prefix: &IpNetwork, path: &Path) -> bool {
        match self {
            Condition::Prefix(p) => prefix == p,
            Condition::PrefixSet(set, match_opt) => match match_opt {
                MatchOptionConfig::Any => set.prefixes.iter().any(|pm| pm.contains(prefix)),
                MatchOptionConfig::All => set.prefixes.iter().all(|pm| pm.contains(prefix)),
                MatchOptionConfig::Invert => !set.prefixes.iter().any(|pm| pm.contains(prefix)),
            },
            Condition::Neighbor(neighbor) => match &path.source {
                RouteSource::Ebgp(addr) | RouteSource::Ibgp(addr) => *addr == *neighbor,
                RouteSource::Local => false,
            },
            Condition::NeighborSet(set, match_opt) => {
                let peer_ip = match &path.source {
                    RouteSource::Ebgp(addr) | RouteSource::Ibgp(addr) => *addr,
                    RouteSource::Local => return false,
                };
                match match_opt {
                    MatchOptionConfig::Any => set.neighbors.contains(&peer_ip),
                    MatchOptionConfig::All => set.neighbors.iter().all(|n| *n == peer_ip),
                    MatchOptionConfig::Invert => !set.neighbors.contains(&peer_ip),
                }
            }
            Condition::AsPath(asn) => path
                .as_path
                .iter()
                .flat_map(|segment| segment.asn_list.iter())
                .any(|&path_asn| path_asn == *asn),
            Condition::AsPathSet(set, match_opt) => {
                let as_path_str = path
                    .as_path
                    .iter()
                    .flat_map(|segment| segment.asn_list.iter())
                    .map(|asn| asn.to_string())
                    .collect::<Vec<_>>()
                    .join("_");
                match match_opt {
                    MatchOptionConfig::Any => set.patterns.iter().any(|r| r.is_match(&as_path_str)),
                    MatchOptionConfig::All => set.patterns.iter().all(|r| r.is_match(&as_path_str)),
                    MatchOptionConfig::Invert => {
                        !set.patterns.iter().any(|r| r.is_match(&as_path_str))
                    }
                }
            }
            Condition::Community(community) => path.communities.contains(community),
            Condition::CommunitySet(set, match_opt) => match match_opt {
                MatchOptionConfig::Any => {
                    path.communities.iter().any(|c| set.communities.contains(c))
                }
                MatchOptionConfig::All => {
                    path.communities.iter().all(|c| set.communities.contains(c))
                }
                MatchOptionConfig::Invert => {
                    !path.communities.iter().any(|c| set.communities.contains(c))
                }
            },
            Condition::ExtCommunitySet(set, match_opt) => match match_opt {
                MatchOptionConfig::Any => path
                    .extended_communities
                    .iter()
                    .any(|ec| set.ext_communities.contains(ec)),
                MatchOptionConfig::All => path
                    .extended_communities
                    .iter()
                    .all(|ec| set.ext_communities.contains(ec)),
                MatchOptionConfig::Invert => !path
                    .extended_communities
                    .iter()
                    .any(|ec| set.ext_communities.contains(ec)),
            },
            Condition::LargeCommunitySet(set, match_opt) => match match_opt {
                MatchOptionConfig::Any => path
                    .large_communities
                    .iter()
                    .any(|lc| set.large_communities.contains(lc)),
                MatchOptionConfig::All => path
                    .large_communities
                    .iter()
                    .all(|lc| set.large_communities.contains(lc)),
                MatchOptionConfig::Invert => !path
                    .large_communities
                    .iter()
                    .any(|lc| set.large_communities.contains(lc)),
            },
            Condition::RouteType(route_type) => matches!(
                (route_type, &path.source),
                (RouteType::Ebgp, RouteSource::Ebgp(_))
                    | (RouteType::Ibgp, RouteSource::Ibgp(_))
                    | (RouteType::Local, RouteSource::Local)
            ),
        }
    }
}

// ============================================================================
// Public helper functions
// ============================================================================

/// Set default local preference if not already set
pub fn stmt_default_local_pref(value: u32) -> Statement {
    Statement::new().then(Action::SetLocalPref {
        value,
        force: false,
    })
}

/// Reject routes with local ASN in AS_PATH (AS loop prevention)
pub fn stmt_reject_as_loop(local_asn: u16) -> Statement {
    Statement::new()
        .when(Condition::AsPath(local_asn))
        .then(Action::Reject)
}

/// Reject routes learned via iBGP (for export to iBGP peers)
pub fn stmt_reject_ibgp() -> Statement {
    Statement::new()
        .when(Condition::RouteType(RouteType::Ibgp))
        .then(Action::Reject)
}

// ============================================================================
// Internal functions (config parsing)
// ============================================================================

/// Build a statement from config
pub(super) fn build_statement(
    def: &StatementConfig,
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
    cond: &ConditionsConfig,
    defined_sets: &DefinedSets,
) -> Result<Statement, String> {
    // Set-based conditions - resolve sets at construction time
    if let Some(ref match_set) = cond.match_prefix_set {
        let prefix_set = defined_sets
            .prefix_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("prefix-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(Condition::PrefixSet(
            Arc::new(prefix_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_neighbor_set {
        let neighbor_set = defined_sets
            .neighbor_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("neighbor-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(Condition::NeighborSet(
            Arc::new(neighbor_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_as_path_set {
        let as_path_set = defined_sets
            .as_path_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("as-path-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(Condition::AsPathSet(
            Arc::new(as_path_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_community_set {
        let community_set = defined_sets
            .community_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("community-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(Condition::CommunitySet(
            Arc::new(community_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_ext_community_set {
        let ext_community_set = defined_sets
            .ext_community_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("ext-community-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(Condition::ExtCommunitySet(
            Arc::new(ext_community_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_large_community_set {
        let large_community_set = defined_sets
            .large_community_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("large-community-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(Condition::LargeCommunitySet(
            Arc::new(large_community_set.clone()),
            match_set.match_option,
        ));
    }

    // Direct conditions (backward compat)
    if let Some(ref prefix_str) = cond.prefix {
        let prefix = IpNetwork::from_str(prefix_str)
            .map_err(|e| format!("invalid prefix '{}': {}", prefix_str, e))?;
        stmt = stmt.when(Condition::Prefix(prefix));
    }

    if let Some(ref neighbor_str) = cond.neighbor {
        let neighbor = IpAddr::from_str(neighbor_str)
            .map_err(|e| format!("invalid neighbor '{}': {}", neighbor_str, e))?;
        stmt = stmt.when(Condition::Neighbor(neighbor));
    }

    if let Some(asn) = cond.has_asn {
        stmt = stmt.when(Condition::AsPath(asn));
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
        stmt = stmt.when(Condition::RouteType(route_type));
    }

    if let Some(ref community_str) = cond.community {
        let community = parse_community_value(community_str)?;
        stmt = stmt.when(Condition::Community(community));
    }

    Ok(stmt)
}

/// Add actions to a statement
fn add_actions(mut stmt: Statement, actions: &ActionsConfig) -> Result<Statement, String> {
    // Local preference
    if let Some(ref lp_action) = actions.local_pref {
        match lp_action {
            LocalPrefActionConfig::Set(val) => {
                stmt = stmt.then(Action::SetLocalPref {
                    value: *val,
                    force: false,
                });
            }
            LocalPrefActionConfig::Force { value, force } => {
                stmt = stmt.then(Action::SetLocalPref {
                    value: *value,
                    force: *force,
                });
            }
        }
    }

    // MED
    if let Some(ref med_action) = actions.med {
        match med_action {
            MedActionConfig::Set(val) => {
                stmt = stmt.then(Action::SetMed(Some(*val)));
            }
            MedActionConfig::Remove { .. } => {
                stmt = stmt.then(Action::SetMed(None));
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
            "add" => Action::SetCommunity(CommunityOp::Add(communities)),
            "remove" => Action::SetCommunity(CommunityOp::Remove(communities)),
            "replace" => Action::SetCommunity(CommunityOp::Replace(communities)),
            _ => {
                return Err(format!(
                    "invalid community operation '{}' (must be 'add', 'remove', or 'replace')",
                    comm_action.operation
                ))
            }
        };
        stmt = stmt.then(action);
    }

    // Extended Community
    if let Some(ref ec_action) = actions.ext_community {
        use crate::bgp::ext_community::parse_extended_community;

        let ext_communities = ec_action
            .ext_communities
            .iter()
            .map(|s| parse_extended_community(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("invalid extended community: {}", e))?;

        let action = match ec_action.operation.as_str() {
            "add" => Action::SetExtCommunity(ExtCommunityOp::Add(ext_communities)),
            "remove" => Action::SetExtCommunity(ExtCommunityOp::Remove(ext_communities)),
            "replace" => Action::SetExtCommunity(ExtCommunityOp::Replace(ext_communities)),
            _ => {
                return Err(format!(
                "invalid extended community operation '{}' (must be 'add', 'remove', or 'replace')",
                ec_action.operation
            ))
            }
        };
        stmt = stmt.then(action);
    }

    // Large Community
    if let Some(ref lc_action) = actions.large_community {
        use crate::bgp::large_community::parse_large_community;

        let large_communities = lc_action
            .large_communities
            .iter()
            .map(|s| parse_large_community(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("invalid large community: {}", e))?;

        let action = match lc_action.operation.as_str() {
            "add" => Action::SetLargeCommunity(LargeCommunityOp::Add(large_communities)),
            "remove" => Action::SetLargeCommunity(LargeCommunityOp::Remove(large_communities)),
            "replace" => Action::SetLargeCommunity(LargeCommunityOp::Replace(large_communities)),
            _ => {
                return Err(format!(
                "invalid large community operation '{}' (must be 'add', 'remove', or 'replace')",
                lc_action.operation
            ))
            }
        };
        stmt = stmt.then(action);
    }

    // Accept/Reject (should be last)
    if actions.accept == Some(true) {
        stmt = stmt.then(Action::Accept);
    }
    if actions.reject == Some(true) {
        stmt = stmt.then(Action::Reject);
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
    use crate::config::PolicyDefinitionConfig;
    use crate::net::Ipv4Net;
    use crate::policy::test_helpers::{create_path, test_prefix};
    use crate::policy::Policy;
    use crate::rib::RouteSource;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn test_statement_no_conditions() {
        let statement = Statement::new().then(Action::SetLocalPref {
            value: 100,
            force: false,
        });
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
        let statement =
            Statement::new()
                .when(Condition::Prefix(prefix))
                .then(Action::SetLocalPref {
                    value: 200,
                    force: false,
                });
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
            .when(Condition::Prefix(prefix))
            .when(Condition::Neighbor(test_ip(1)))
            .then(Action::SetLocalPref {
                value: 200,
                force: false,
            });

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
            .then(Action::SetLocalPref {
                value: 200,
                force: false,
            })
            .then(Action::SetMed(None));
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        path.med = Some(100);
        assert_eq!(statement.apply(&test_prefix(), &mut path), Some(true));
        assert_eq!(path.local_pref, Some(200));
        assert_eq!(path.med, None);
    }

    #[test]
    fn test_statement_reject() {
        let statement = Statement::new().then(Action::Reject);
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert_eq!(statement.apply(&test_prefix(), &mut path), Some(false));
    }

    #[test]
    fn test_policy_accept_all() {
        let policy = Policy::new("test".to_string()).with(Statement::new().then(Action::Accept));
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&test_prefix(), &mut path));
    }

    #[test]
    fn test_policy_empty_rejects() {
        let policy = Policy::new("test".to_string());
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
        let policy = Policy::new("test".to_string())
            .with(
                Statement::new()
                    .when(Condition::Prefix(prefix))
                    .then(Action::SetLocalPref {
                        value: 200,
                        force: false,
                    }),
            )
            .with(Statement::new().then(Action::SetLocalPref {
                value: 100,
                force: false,
            }));

        let mut path1 = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&prefix, &mut path1));
        assert_eq!(path1.local_pref, Some(200));

        let mut path2 = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&other_prefix, &mut path2));
        assert_eq!(path2.local_pref, Some(100));
    }

    #[test]
    fn test_stmt_default_local_pref() {
        let policy = Policy::new("test".to_string()).with(stmt_default_local_pref(100));
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(policy.accept(&test_prefix(), &mut path));
        assert_eq!(path.local_pref, Some(100));
    }

    #[test]
    fn test_stmt_reject_as_loop() {
        let policy = Policy::new("test".to_string()).with(stmt_reject_as_loop(65000));
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
        let policy = Policy::new("test".to_string())
            .with(stmt_reject_ibgp())
            .with(Statement::new().then(Action::Accept));
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
        use crate::config::ConditionsConfig;

        let defined_sets = DefinedSets::default();

        let policy_def = PolicyDefinitionConfig {
            name: "test-policy".to_string(),
            statements: vec![
                StatementConfig {
                    name: Some("stmt1".to_string()),
                    conditions: ConditionsConfig {
                        prefix: Some("10.0.0.0/8".to_string()),
                        ..Default::default()
                    },
                    actions: ActionsConfig {
                        local_pref: Some(LocalPrefActionConfig::Set(200)),
                        accept: Some(true),
                        ..Default::default()
                    },
                },
                StatementConfig {
                    name: Some("stmt2".to_string()),
                    conditions: ConditionsConfig {
                        prefix: Some("192.168.0.0/16".to_string()),
                        ..Default::default()
                    },
                    actions: ActionsConfig {
                        reject: Some(true),
                        ..Default::default()
                    },
                },
            ],
        };

        // Parse from config
        let actual = Policy::from_config(&policy_def, &defined_sets).unwrap();

        // Build expected policy manually
        let expected = Policy::new("test-policy".to_string())
            .with(
                Statement::new()
                    .when(Condition::Prefix("10.0.0.0/8".parse().unwrap()))
                    .then(Action::SetLocalPref {
                        value: 200,
                        force: false,
                    })
                    .then(Action::Accept),
            )
            .with(
                Statement::new()
                    .when(Condition::Prefix("192.168.0.0/16".parse().unwrap()))
                    .then(Action::Reject),
            );

        // Now we can directly compare policies!
        assert_eq!(actual, expected);
    }
}
