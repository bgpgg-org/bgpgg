use crate::debug;
use crate::rib::Path;

/// Trait for import policies that determine whether a path should be accepted
/// and can modify path attributes during import
pub trait ImportPolicy: Send + Sync {
    /// Evaluate whether this path should be accepted on import
    ///
    /// Can modify path attributes (e.g., set local_pref, communities)
    /// Returns `true` if the path is accepted, `false` if rejected
    fn accept(&self, path: &mut Path) -> bool;
}

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
    fn accept(&self, path: &mut Path) -> bool {
        if path.local_pref.is_none() {
            path.local_pref = Some(self.default_value);
        }
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
    fn accept(&self, path: &mut Path) -> bool {
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

/// Trait for export policies that determine whether a path should be exported to a peer
pub trait ExportPolicy: Send + Sync {
    /// Evaluate whether this path should be exported
    ///
    /// Returns `true` if the path is accepted, `false` if rejected
    fn accept(&self, path: &Path) -> bool;
}

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
    fn accept(&self, path: &Path) -> bool {
        // If sending to iBGP peer and route was learned via iBGP, reject
        if self.is_ibgp() && path.source.is_ibgp() {
            return false;
        }
        true
    }
}

/// A chain of import policies that are evaluated in sequence
///
/// All policies must return `true` for the path to be accepted.
/// Evaluation stops at the first policy that returns `false`.
pub struct ImportPolicyChain {
    policies: Vec<Box<dyn ImportPolicy>>,
}

impl ImportPolicyChain {
    /// Create a new import policy chain with standard policies
    pub fn new(local_asn: u16) -> Self {
        Self {
            policies: Vec::new(),
        }
        .add(DefaultLocalPref::new())
        .add(AsLoopPrevention::new(local_asn))
    }

    /// Add a policy to the chain
    pub fn add<P: ImportPolicy + 'static>(mut self, policy: P) -> Self {
        self.policies.push(Box::new(policy));
        self
    }

    /// Evaluate all policies in the chain
    ///
    /// Policies can modify the path. Returns `true` if all policies accept, `false` otherwise
    pub fn accept(&self, path: &mut Path) -> bool {
        for policy in &self.policies {
            if !policy.accept(path) {
                return false;
            }
        }
        true
    }
}

/// A chain of export policies that are evaluated in sequence
///
/// All policies must return `true` for the path to be exported.
/// Evaluation stops at the first policy that returns `false`.
pub struct ExportPolicyChain {
    policies: Vec<Box<dyn ExportPolicy>>,
}

impl ExportPolicyChain {
    /// Create a new export policy chain with standard policies
    pub fn new(local_asn: u16, peer_asn: u16) -> Self {
        Self {
            policies: Vec::new(),
        }
        .add(NoIbgpReflection::new(local_asn, peer_asn))
    }

    /// Add a policy to the chain
    pub fn add<P: ExportPolicy + 'static>(mut self, policy: P) -> Self {
        self.policies.push(Box::new(policy));
        self
    }

    /// Evaluate all policies in the chain
    ///
    /// Returns `true` if all policies accept the path, `false` otherwise
    pub fn accept(&self, path: &Path) -> bool {
        for policy in &self.policies {
            if !policy.accept(path) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_update::Origin;
    use crate::rib::{Path, RouteSource};
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

    #[test]
    fn test_no_ibgp_reflection() {
        // Should block iBGP -> iBGP
        let ibgp_policy = NoIbgpReflection::new(65000, 65000);
        let ibgp_path = create_test_path(RouteSource::Ibgp("10.0.0.1".to_string()));
        assert!(!ibgp_policy.accept(&ibgp_path));

        // Should allow eBGP -> iBGP
        let ebgp_path = create_test_path(RouteSource::Ebgp("10.0.0.1".to_string()));
        assert!(ibgp_policy.accept(&ebgp_path));

        // Should allow iBGP -> eBGP
        let ebgp_policy = NoIbgpReflection::new(65000, 65001);
        assert!(ebgp_policy.accept(&ibgp_path));
    }
}
