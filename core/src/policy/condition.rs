use crate::bgp::utils::IpNetwork;
use crate::rib::{Path, RouteSource};
use std::net::IpAddr;

/// A condition that can match against a route
pub trait Condition: std::fmt::Debug + Send + Sync {
    fn matches(&self, prefix: &IpNetwork, path: &Path) -> bool;
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
    fn matches(&self, prefix: &IpNetwork, _path: &Path) -> bool {
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
    fn matches(&self, _prefix: &IpNetwork, path: &Path) -> bool {
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
    fn matches(&self, _prefix: &IpNetwork, path: &Path) -> bool {
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
    fn matches(&self, _prefix: &IpNetwork, path: &Path) -> bool {
        matches!(
            (&self.route_type, &path.source),
            (RouteType::Ebgp, RouteSource::Ebgp(_))
                | (RouteType::Ibgp, RouteSource::Ibgp(_))
                | (RouteType::Local, RouteSource::Local)
        )
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

    #[test]
    fn test_prefix_condition() {
        let prefix = test_prefix();
        let other_prefix = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(192, 168, 1, 0),
            prefix_length: 24,
        });
        let condition = PrefixCondition::new(prefix);
        let path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(condition.matches(&prefix, &path));
        assert!(!condition.matches(&other_prefix, &path));
    }

    #[test]
    fn test_neighbor_condition() {
        let condition = NeighborCondition::new(test_ip(1));
        let path1 = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(condition.matches(&test_prefix(), &path1));

        let path2 = create_path(RouteSource::Ebgp(test_ip(2)));
        assert!(!condition.matches(&test_prefix(), &path2));

        let path3 = create_path(RouteSource::Local);
        assert!(!condition.matches(&test_prefix(), &path3));
    }

    #[test]
    fn test_as_path_condition() {
        let condition = AsPathCondition::new(65001);
        let mut path = create_path(RouteSource::Ebgp(test_ip(1)));
        path.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 2,
            asn_list: vec![65001, 65002],
        }];
        assert!(condition.matches(&test_prefix(), &path));

        path.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 2,
            asn_list: vec![65002, 65003],
        }];
        assert!(!condition.matches(&test_prefix(), &path));
    }

    #[test]
    fn test_route_type_condition() {
        let ebgp = RouteTypeCondition::new(RouteType::Ebgp);
        let ibgp = RouteTypeCondition::new(RouteType::Ibgp);
        let local = RouteTypeCondition::new(RouteType::Local);

        let ebgp_path = create_path(RouteSource::Ebgp(test_ip(1)));
        assert!(ebgp.matches(&test_prefix(), &ebgp_path));
        assert!(!ibgp.matches(&test_prefix(), &ebgp_path));

        let ibgp_path = create_path(RouteSource::Ibgp(test_ip(1)));
        assert!(ibgp.matches(&test_prefix(), &ibgp_path));

        let local_path = create_path(RouteSource::Local);
        assert!(local.matches(&test_prefix(), &local_path));
    }
}
