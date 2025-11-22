use crate::bgp::utils::IpNetwork;
use crate::policy::ExportPolicy;
use crate::rib::Path;

/// Don't send routes learned via iBGP to iBGP peers
///
/// This prevents routing loops in iBGP meshes by ensuring that routes
/// learned from one iBGP peer are not re-advertised to other iBGP peers.
#[derive(Debug, Clone)]
pub struct NoIbgpReflection {
    local_asn: u16,
    peer_asn: u16,
}

impl NoIbgpReflection {
    pub fn new(local_asn: u16, peer_asn: u16) -> Self {
        Self {
            local_asn,
            peer_asn,
        }
    }

    fn is_ibgp(&self) -> bool {
        self.peer_asn == self.local_asn
    }
}

impl ExportPolicy for NoIbgpReflection {
    fn accept(&self, _prefix: &IpNetwork, path: &Path) -> bool {
        // If sending to iBGP peer and route was learned via iBGP, reject
        if self.is_ibgp() && path.source.is_ibgp() {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_update::Origin;
    use crate::bgp::utils::Ipv4Net;
    use crate::rib::RouteSource;
    use std::net::Ipv4Addr;

    fn create_test_path(source: RouteSource) -> Path {
        Path {
            origin: Origin::IGP,
            as_path: vec![],
            next_hop: Ipv4Addr::new(10, 0, 0, 1),
            source,
            local_pref: None,
            med: None,
        }
    }

    fn test_prefix() -> IpNetwork {
        IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        })
    }

    #[test]
    fn test_no_ibgp_reflection() {
        // Should block iBGP -> iBGP
        let ibgp_policy = NoIbgpReflection::new(65000, 65000);
        let ibgp_path = create_test_path(RouteSource::Ibgp("10.0.0.1".to_string()));
        assert!(!ibgp_policy.accept(&test_prefix(), &ibgp_path));

        // Should allow eBGP -> iBGP
        let ebgp_path = create_test_path(RouteSource::Ebgp("10.0.0.1".to_string()));
        assert!(ibgp_policy.accept(&test_prefix(), &ebgp_path));

        // Should allow iBGP -> eBGP
        let ebgp_policy = NoIbgpReflection::new(65000, 65001);
        assert!(ebgp_policy.accept(&test_prefix(), &ibgp_path));
    }
}
