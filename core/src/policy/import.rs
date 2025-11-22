use crate::bgp::utils::IpNetwork;
use crate::debug;
use crate::policy::ImportPolicy;
use crate::rib::Path;

/// Set default local preference if not already set
///
/// BGP routes need a local preference for tie-breaking during best path selection.
/// This policy sets a default value (typically 100) if the path doesn't have one.
#[derive(Debug, Clone)]
pub struct DefaultLocalPref {
    default_value: u32,
}

impl DefaultLocalPref {
    /// Create a new DefaultLocalPref policy with value 100
    pub fn new() -> Self {
        Self { default_value: 100 }
    }

    /// Create a new DefaultLocalPref policy with a custom default value
    pub fn with_value(default_value: u32) -> Self {
        Self { default_value }
    }
}

impl Default for DefaultLocalPref {
    fn default() -> Self {
        Self::new()
    }
}

impl ImportPolicy for DefaultLocalPref {
    fn accept(&self, _prefix: &IpNetwork, path: &mut Path) -> bool {
        if path.local_pref.is_none() {
            path.local_pref = Some(self.default_value);
        }
        true
    }
}

/// Remove MULTI_EXIT_DISC attribute from routes
///
/// RFC 4271: BGP speaker MUST implement a mechanism to remove MED.
/// This must be done prior to route selection.
#[derive(Debug, Clone)]
pub struct RemoveMed;

impl ImportPolicy for RemoveMed {
    fn accept(&self, _prefix: &IpNetwork, path: &mut Path) -> bool {
        path.med = None;
        true
    }
}

/// Prevent AS loops by rejecting routes with our ASN in the AS_PATH
///
/// RFC 4271 Section 9.1.2.1: AS loop detection
/// If the local AS appears in the AS_PATH, reject the route (loop detected)
#[derive(Debug, Clone)]
pub struct AsLoopPrevention {
    local_asn: u16,
}

impl AsLoopPrevention {
    pub fn new(local_asn: u16) -> Self {
        Self { local_asn }
    }
}

impl ImportPolicy for AsLoopPrevention {
    fn accept(&self, _prefix: &IpNetwork, path: &mut Path) -> bool {
        // Check if local ASN appears in AS_PATH (across all segments)
        let has_local_asn = path
            .as_path
            .iter()
            .flat_map(|segment| segment.asn_list.iter())
            .any(|&asn| asn == self.local_asn);

        if has_local_asn {
            debug!("rejecting route due to AS loop", "local_asn" => self.local_asn);
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin};
    use crate::bgp::utils::Ipv4Net;
    use crate::rib::RouteSource;
    use std::net::Ipv4Addr;

    fn create_path() -> Path {
        Path {
            origin: Origin::IGP,
            as_path: vec![],
            next_hop: Ipv4Addr::new(10, 0, 0, 1),
            source: RouteSource::Ebgp("10.0.0.1".to_string()),
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
    fn test_default_local_pref() {
        let policy = DefaultLocalPref::new();
        let mut path = create_path();

        assert!(policy.accept(&test_prefix(), &mut path));
        assert_eq!(path.local_pref, Some(100));
    }

    #[test]
    fn test_default_local_pref_preserves_existing() {
        let policy = DefaultLocalPref::new();
        let mut path = create_path();
        path.local_pref = Some(150);

        assert!(policy.accept(&test_prefix(), &mut path));
        assert_eq!(path.local_pref, Some(150));
    }

    #[test]
    fn test_remove_med() {
        let policy = RemoveMed;
        let mut path = create_path();
        path.med = Some(100);

        assert!(policy.accept(&test_prefix(), &mut path));
        assert_eq!(path.med, None);
    }

    #[test]
    fn test_as_loop_prevention() {
        let policy = AsLoopPrevention::new(65000);
        let mut path = create_path();
        path.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 3,
            asn_list: vec![65001, 65000, 65002],
        }];

        assert!(!policy.accept(&test_prefix(), &mut path));
    }

    #[test]
    fn test_as_loop_prevention_no_loop() {
        let policy = AsLoopPrevention::new(65000);
        let mut path = create_path();
        path.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 2,
            asn_list: vec![65001, 65002],
        }];

        assert!(policy.accept(&test_prefix(), &mut path));
    }
}
