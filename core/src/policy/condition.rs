use crate::bgp::utils::IpNetwork;
use crate::config::MatchOptionConfig;
use crate::policy::defined_sets::DefinedSets;
use crate::rib::{Path, RouteSource};
use std::net::IpAddr;

/// A condition that can match against a route
pub trait Condition: std::fmt::Debug + Send + Sync {
    fn matches(&self, prefix: &IpNetwork, path: &Path, sets: &DefinedSets) -> bool;
}

/// Match specific prefix
#[derive(Debug, Clone)]
pub struct PrefixCondition {
    pub prefix: IpNetwork,
}

impl PrefixCondition {
    pub fn new(prefix: IpNetwork) -> Self {
        Self { prefix }
    }
}

impl Condition for PrefixCondition {
    fn matches(&self, prefix: &IpNetwork, _path: &Path, _sets: &DefinedSets) -> bool {
        prefix == &self.prefix
    }
}

/// Match routes from a specific neighbor
#[derive(Debug, Clone)]
pub struct NeighborCondition {
    pub neighbor: IpAddr,
}

impl NeighborCondition {
    pub fn new(neighbor: IpAddr) -> Self {
        Self { neighbor }
    }
}

impl Condition for NeighborCondition {
    fn matches(&self, _prefix: &IpNetwork, path: &Path, _sets: &DefinedSets) -> bool {
        match &path.source {
            RouteSource::Ebgp(addr) | RouteSource::Ibgp(addr) => *addr == self.neighbor,
            RouteSource::Local => false,
        }
    }
}

/// Match routes with AS in AS_PATH
#[derive(Debug, Clone)]
pub struct AsPathCondition {
    pub asn: u16,
}

impl AsPathCondition {
    pub fn new(asn: u16) -> Self {
        Self { asn }
    }
}

impl Condition for AsPathCondition {
    fn matches(&self, _prefix: &IpNetwork, path: &Path, _sets: &DefinedSets) -> bool {
        path.as_path
            .iter()
            .flat_map(|segment| segment.asn_list.iter())
            .any(|&asn| asn == self.asn)
    }
}

/// Match routes by source type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteType {
    Ebgp,
    Ibgp,
    Local,
}

#[derive(Debug, Clone)]
pub struct RouteTypeCondition {
    pub route_type: RouteType,
}

impl RouteTypeCondition {
    pub fn new(route_type: RouteType) -> Self {
        Self { route_type }
    }
}

impl Condition for RouteTypeCondition {
    fn matches(&self, _prefix: &IpNetwork, path: &Path, _sets: &DefinedSets) -> bool {
        matches!(
            (&self.route_type, &path.source),
            (RouteType::Ebgp, RouteSource::Ebgp(_))
                | (RouteType::Ibgp, RouteSource::Ibgp(_))
                | (RouteType::Local, RouteSource::Local)
        )
    }
}

/// Match routes with specific community value
#[derive(Debug, Clone)]
pub struct CommunityCondition {
    pub community: u32,
}

impl CommunityCondition {
    pub fn new(community: u32) -> Self {
        Self { community }
    }
}

impl Condition for CommunityCondition {
    fn matches(&self, _prefix: &IpNetwork, path: &Path, _sets: &DefinedSets) -> bool {
        path.communities.contains(&self.community)
    }
}

/// Match routes against a prefix-set
#[derive(Debug, Clone)]
pub struct PrefixSetCondition {
    pub set_name: String,
    pub match_option: MatchOptionConfig,
}

impl PrefixSetCondition {
    pub fn new(set_name: String, match_option: MatchOptionConfig) -> Self {
        Self {
            set_name,
            match_option,
        }
    }
}

impl Condition for PrefixSetCondition {
    fn matches(&self, prefix: &IpNetwork, _path: &Path, sets: &DefinedSets) -> bool {
        let Some(prefix_set) = sets.prefix_sets.get(&self.set_name) else {
            return false;
        };

        match self.match_option {
            MatchOptionConfig::Any => prefix_set.prefixes.iter().any(|pm| pm.contains(prefix)),
            MatchOptionConfig::All => prefix_set.prefixes.iter().all(|pm| pm.contains(prefix)),
            MatchOptionConfig::Invert => !prefix_set.prefixes.iter().any(|pm| pm.contains(prefix)),
        }
    }
}

/// Match routes against a neighbor-set
#[derive(Debug, Clone)]
pub struct NeighborSetCondition {
    pub set_name: String,
    pub match_option: MatchOptionConfig,
}

impl NeighborSetCondition {
    pub fn new(set_name: String, match_option: MatchOptionConfig) -> Self {
        Self {
            set_name,
            match_option,
        }
    }
}

impl Condition for NeighborSetCondition {
    fn matches(&self, _prefix: &IpNetwork, path: &Path, sets: &DefinedSets) -> bool {
        let Some(neighbor_set) = sets.neighbor_sets.get(&self.set_name) else {
            return false;
        };

        let peer_ip = match &path.source {
            RouteSource::Ebgp(addr) | RouteSource::Ibgp(addr) => *addr,
            RouteSource::Local => return false,
        };

        match self.match_option {
            MatchOptionConfig::Any => neighbor_set.neighbors.iter().any(|n| *n == peer_ip),
            MatchOptionConfig::All => neighbor_set.neighbors.iter().all(|n| *n == peer_ip),
            MatchOptionConfig::Invert => !neighbor_set.neighbors.iter().any(|n| *n == peer_ip),
        }
    }
}

/// Match routes against an AS-PATH set (regex patterns)
#[derive(Debug, Clone)]
pub struct AsPathSetCondition {
    pub set_name: String,
    pub match_option: MatchOptionConfig,
}

impl AsPathSetCondition {
    pub fn new(set_name: String, match_option: MatchOptionConfig) -> Self {
        Self {
            set_name,
            match_option,
        }
    }
}

impl Condition for AsPathSetCondition {
    fn matches(&self, _prefix: &IpNetwork, path: &Path, sets: &DefinedSets) -> bool {
        let Some(as_path_set) = sets.as_path_sets.get(&self.set_name) else {
            return false;
        };

        // Convert AS_PATH to string for regex matching
        let as_path_str = path
            .as_path
            .iter()
            .flat_map(|segment| segment.asn_list.iter())
            .map(|asn| asn.to_string())
            .collect::<Vec<_>>()
            .join("_");

        match self.match_option {
            MatchOptionConfig::Any => as_path_set
                .patterns
                .iter()
                .any(|r| r.is_match(&as_path_str)),
            MatchOptionConfig::All => as_path_set
                .patterns
                .iter()
                .all(|r| r.is_match(&as_path_str)),
            MatchOptionConfig::Invert => !as_path_set
                .patterns
                .iter()
                .any(|r| r.is_match(&as_path_str)),
        }
    }
}

/// Match routes against a community-set
#[derive(Debug, Clone)]
pub struct CommunitySetCondition {
    pub set_name: String,
    pub match_option: MatchOptionConfig,
}

impl CommunitySetCondition {
    pub fn new(set_name: String, match_option: MatchOptionConfig) -> Self {
        Self {
            set_name,
            match_option,
        }
    }
}

impl Condition for CommunitySetCondition {
    fn matches(&self, _prefix: &IpNetwork, path: &Path, sets: &DefinedSets) -> bool {
        let Some(community_set) = sets.community_sets.get(&self.set_name) else {
            return false;
        };

        match self.match_option {
            MatchOptionConfig::Any => community_set
                .communities
                .iter()
                .any(|comm| path.communities.contains(comm)),
            MatchOptionConfig::All => community_set
                .communities
                .iter()
                .all(|comm| path.communities.contains(comm)),
            MatchOptionConfig::Invert => !community_set
                .communities
                .iter()
                .any(|comm| path.communities.contains(comm)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType};
    use crate::bgp::utils::Ipv4Net;
    use crate::policy::test_helpers::{create_path, test_prefix};
    use crate::rib::RouteSource;
    use std::net::Ipv4Addr;

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn empty_sets() -> DefinedSets {
        DefinedSets::default()
    }

    #[test]
    fn test_prefix_condition() {
        let prefix = test_prefix();
        let other_prefix = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(192, 168, 1, 0),
            prefix_length: 24,
        });
        let condition = PrefixCondition::new(prefix);
        let path = create_path(RouteSource::Ebgp(test_ip(1)));
        let sets = empty_sets();
        assert!(condition.matches(&prefix, &path, &sets));
        assert!(!condition.matches(&other_prefix, &path, &sets));
    }

    #[test]
    fn test_neighbor_condition() {
        let condition = NeighborCondition::new(test_ip(1));
        let path1 = create_path(RouteSource::Ebgp(test_ip(1)));
        let sets = empty_sets();
        assert!(condition.matches(&test_prefix(), &path1, &sets));

        let path2 = create_path(RouteSource::Ebgp(test_ip(2)));
        assert!(!condition.matches(&test_prefix(), &path2, &sets));

        let path3 = create_path(RouteSource::Local);
        assert!(!condition.matches(&test_prefix(), &path3, &sets));
    }

    #[test]
    fn test_as_path_condition() {
        let condition = AsPathCondition::new(65001);
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        let sets = empty_sets();
        path.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 2,
            asn_list: vec![65001, 65002],
        }];
        assert!(condition.matches(&test_prefix(), &path, &sets));

        path.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 2,
            asn_list: vec![65002, 65003],
        }];
        assert!(!condition.matches(&test_prefix(), &path, &sets));
    }

    #[test]
    fn test_route_type_condition() {
        let ebgp = RouteTypeCondition::new(RouteType::Ebgp);
        let ibgp = RouteTypeCondition::new(RouteType::Ibgp);
        let local = RouteTypeCondition::new(RouteType::Local);
        let sets = empty_sets();

        let ebgp_path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(ebgp.matches(&test_prefix(), &ebgp_path, &sets));
        assert!(!ibgp.matches(&test_prefix(), &ebgp_path, &sets));

        let ibgp_path = create_path(RouteSource::Ibgp(test_ip(1)));
        assert!(ibgp.matches(&test_prefix(), &ibgp_path, &sets));

        let local_path = create_path(RouteSource::Local);
        assert!(local.matches(&test_prefix(), &local_path, &sets));
    }

    #[test]
    fn test_community_condition() {
        let condition = CommunityCondition::new(65001);
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        let sets = empty_sets();

        path.communities = vec![65001, 65002];
        assert!(condition.matches(&test_prefix(), &path, &sets));

        path.communities = vec![65002, 65003];
        assert!(!condition.matches(&test_prefix(), &path, &sets));

        path.communities = vec![];
        assert!(!condition.matches(&test_prefix(), &path, &sets));
    }
}
