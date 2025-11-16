use crate::rib::Path;

/// Context information provided when evaluating export policies
#[derive(Debug, Clone)]
pub struct ExportContext {
    /// ASN of the peer we're exporting to
    pub peer_asn: u16,
    /// Local router's ASN
    pub local_asn: u16,
}

impl ExportContext {
    /// Create a new export context
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

/// Trait for export policies that determine whether a path should be exported to a peer
pub trait ExportPolicy: Send + Sync {
    /// Evaluate whether this path should be exported
    ///
    /// Returns `true` if the path is accepted, `false` if rejected
    fn accept(&self, path: &Path, context: &ExportContext) -> bool;
}

/// Don't send routes learned via iBGP to iBGP peers
///
/// This prevents routing loops in iBGP meshes by ensuring that routes
/// learned from one iBGP peer are not re-advertised to other iBGP peers.
#[derive(Debug, Clone)]
pub struct NoIbgpReflection;

impl ExportPolicy for NoIbgpReflection {
    fn accept(&self, path: &Path, context: &ExportContext) -> bool {
        // If sending to iBGP peer and route was learned via iBGP, reject
        if context.is_ibgp() && path.source.is_ibgp() {
            return false;
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

impl Default for ExportPolicyChain {
    /// Create a default policy chain with NoIbgpReflection
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
    pub fn accept(&self, path: &Path, context: &ExportContext) -> bool {
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
        let ibgp_context = ExportContext::new(65000, 65000);
        assert!(!policy.accept(&ibgp_path, &ibgp_context));

        // Should allow eBGP -> iBGP
        let ebgp_path = create_test_path(RouteSource::Ebgp("10.0.0.1".to_string()));
        assert!(policy.accept(&ebgp_path, &ibgp_context));

        // Should allow iBGP -> eBGP
        let ebgp_context = ExportContext::new(65001, 65000);
        assert!(policy.accept(&ibgp_path, &ebgp_context));
    }
}
