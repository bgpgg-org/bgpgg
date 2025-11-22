use crate::bgp::utils::IpNetwork;
use crate::rib::Path;

pub mod export;
pub mod import;

pub use export::*;
pub use import::*;

/// Trait for import policies that determine whether a path should be accepted
/// and can modify path attributes during import
pub trait ImportPolicy: Send + Sync {
    /// Evaluate whether this path should be accepted on import
    ///
    /// Can modify path attributes (e.g., set local_pref, communities)
    /// Returns `true` if the path is accepted, `false` if rejected
    fn accept(&self, prefix: &IpNetwork, path: &mut Path) -> bool;
}

/// Trait for export policies that determine whether a path should be exported to a peer
pub trait ExportPolicy: Send + Sync {
    /// Evaluate whether this path should be exported
    ///
    /// Returns `true` if the path is accepted, `false` if rejected
    fn accept(&self, prefix: &IpNetwork, path: &Path) -> bool;
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
    pub fn accept(&self, prefix: &IpNetwork, path: &mut Path) -> bool {
        for policy in &self.policies {
            if !policy.accept(prefix, path) {
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
    pub fn accept(&self, prefix: &IpNetwork, path: &Path) -> bool {
        for policy in &self.policies {
            if !policy.accept(prefix, path) {
                return false;
            }
        }
        true
    }
}
