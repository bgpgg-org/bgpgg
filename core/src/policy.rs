use crate::debug;
use crate::rib::Path;

/// Context information for policy evaluation (both import and export)
#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// ASN of the peer
    pub peer_asn: u16,
    /// Local router's ASN
    pub local_asn: u16,
}

impl PolicyContext {
    /// Create a new policy context
    pub fn new(peer_asn: u16, local_asn: u16) -> Self {
        Self {
            peer_asn,
            local_asn,
        }
    }

    /// Check if this is an iBGP session (peer ASN matches local ASN)
    pub fn is_ibgp(&self) -> bool {
        self.peer_asn == self.local_asn
    }
}

/// Trait for import policies that determine whether a path should be accepted
/// and can modify path attributes during import
pub trait ImportPolicy: Send + Sync {
    /// Evaluate whether this path should be accepted on import
    ///
    /// Can modify path attributes (e.g., set local_pref, communities)
    /// Returns `true` if the path is accepted, `false` if rejected
    fn accept(&self, path: &mut Path, context: &PolicyContext) -> bool;
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
    fn accept(&self, path: &mut Path, _context: &PolicyContext) -> bool {
        if path.local_pref.is_none() {
            path.local_pref = Some(self.default_value);
        }
        true
    }
}

/// Prevent AS loops by rejecting routes with our ASN in the AS_PATH
///
/// RFC 4271 Section 9.1.2.1: AS loop detection
/// - eBGP: Local AS should not appear in AS_PATH at all
/// - iBGP: Local AS can appear once (normal), but more than once indicates a loop
#[derive(Debug, Clone)]
pub struct AsLoopPrevention;

impl ImportPolicy for AsLoopPrevention {
    fn accept(&self, path: &mut Path, context: &PolicyContext) -> bool {
        // Count occurrences of local ASN in AS_PATH (across all segments)
        let local_asn_count = path
            .as_path
            .iter()
            .flat_map(|segment| segment.asn_list.iter())
            .filter(|&&asn| asn == context.local_asn)
            .count();

        match &path.source {
            crate::rib::RouteSource::Ebgp(_) => {
                // eBGP: local AS should not appear in AS_PATH at all
                if local_asn_count > 0 {
                    debug!("rejecting eBGP route due to AS loop", "local_asn" => context.local_asn);
                    return false;
                }
            }
            crate::rib::RouteSource::Ibgp(_) => {
                // iBGP: local AS can appear once (normal), but more than once is a loop
                if local_asn_count > 1 {
                    debug!("rejecting iBGP route due to AS loop", "local_asn" => context.local_asn, "count" => local_asn_count);
                    return false;
                }
            }
            crate::rib::RouteSource::Local => {
                // Local routes are trusted
            }
        }

        true
    }
}

/// Trait for export policies that determine whether a path should be exported to a peer
pub trait ExportPolicy: Send + Sync {
    /// Evaluate whether this path should be exported
    ///
    /// Returns `true` if the path is accepted, `false` if rejected
    fn accept(&self, path: &Path, context: &PolicyContext) -> bool;
}

/// Don't send routes learned via iBGP to iBGP peers
///
/// This prevents routing loops in iBGP meshes by ensuring that routes
/// learned from one iBGP peer are not re-advertised to other iBGP peers.
#[derive(Debug, Clone)]
pub struct NoIbgpReflection;

impl ExportPolicy for NoIbgpReflection {
    fn accept(&self, path: &Path, context: &PolicyContext) -> bool {
        // If sending to iBGP peer and route was learned via iBGP, reject
        if context.is_ibgp() && path.source.is_ibgp() {
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

impl Default for ImportPolicyChain {
    /// Create a default import policy chain with standard policies
    fn default() -> Self {
        Self::new()
            .add(DefaultLocalPref::new())
            .add(AsLoopPrevention)
    }
}

impl ImportPolicyChain {
    /// Create a new empty policy chain
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Add a policy to the chain
    pub fn add<P: ImportPolicy + 'static>(mut self, policy: P) -> Self {
        self.policies.push(Box::new(policy));
        self
    }

    /// Evaluate all policies in the chain
    ///
    /// Policies can modify the path. Returns `true` if all policies accept, `false` otherwise
    pub fn accept(&self, path: &mut Path, context: &PolicyContext) -> bool {
        // If no policies, allow by default
        if self.policies.is_empty() {
            return true;
        }

        // All policies must pass
        for policy in &self.policies {
            if !policy.accept(path, context) {
                return false;
            }
        }
        true
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

/// A chain of export policies that are evaluated in sequence
///
/// All policies must return `true` for the path to be exported.
/// Evaluation stops at the first policy that returns `false`.
pub struct ExportPolicyChain {
    policies: Vec<Box<dyn ExportPolicy>>,
}

impl Default for ExportPolicyChain {
    /// Create a default export policy chain with NoIbgpReflection
    fn default() -> Self {
        Self::new().add(NoIbgpReflection)
    }
}

impl ExportPolicyChain {
    /// Create a new empty policy chain
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Add a policy to the chain
    pub fn add<P: ExportPolicy + 'static>(mut self, policy: P) -> Self {
        self.policies.push(Box::new(policy));
        self
    }

    /// Evaluate all policies in the chain
    ///
    /// Returns `true` if all policies accept the path, `false` otherwise
    pub fn accept(&self, path: &Path, context: &PolicyContext) -> bool {
        // If no policies, allow by default
        if self.policies.is_empty() {
            return true;
        }

        // All policies must pass
        for policy in &self.policies {
            if !policy.accept(path, context) {
                return false;
            }
        }
        true
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
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
        let policy = NoIbgpReflection;

        // Should block iBGP -> iBGP
        let ibgp_path = create_test_path(RouteSource::Ibgp("10.0.0.1".to_string()));
        let ibgp_context = PolicyContext::new(65000, 65000);
        assert!(!policy.accept(&ibgp_path, &ibgp_context));

        // Should allow eBGP -> iBGP
        let ebgp_path = create_test_path(RouteSource::Ebgp("10.0.0.1".to_string()));
        assert!(policy.accept(&ebgp_path, &ibgp_context));

        // Should allow iBGP -> eBGP
        let ebgp_context = PolicyContext::new(65001, 65000);
        assert!(policy.accept(&ibgp_path, &ebgp_context));
    }
}
