// Copyright 2025 bgpgg Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::bgp::utils::IpNetwork;
use crate::peer::SessionType;
use crate::rib::path::Path;

/// Source of a route
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RouteSource {
    /// Route learned from an EBGP peer (external AS)
    Ebgp(String),
    /// Route learned from an IBGP peer (same AS)
    Ibgp(String),
    /// Route originated locally by this router
    Local,
}

impl RouteSource {
    /// Create a RouteSource based on BGP session type
    pub fn from_session(session_type: SessionType, peer_addr: String) -> Self {
        match session_type {
            SessionType::Ebgp => RouteSource::Ebgp(peer_addr),
            SessionType::Ibgp => RouteSource::Ibgp(peer_addr),
        }
    }

    /// Check if this route was learned via iBGP
    pub fn is_ibgp(&self) -> bool {
        matches!(self, RouteSource::Ibgp(_))
    }
}

/// Represents a route with one or more paths to a prefix
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Route {
    pub prefix: IpNetwork,
    pub paths: Vec<Path>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_source_from_session() {
        assert_eq!(
            RouteSource::from_session(SessionType::Ebgp, "10.0.0.1".to_string()),
            RouteSource::Ebgp("10.0.0.1".to_string())
        );
        assert_eq!(
            RouteSource::from_session(SessionType::Ibgp, "10.0.0.2".to_string()),
            RouteSource::Ibgp("10.0.0.2".to_string())
        );
    }

    #[test]
    fn test_is_ibgp() {
        assert!(RouteSource::Ibgp("10.0.0.1".to_string()).is_ibgp());
        assert!(!RouteSource::Ebgp("10.0.0.2".to_string()).is_ibgp());
        assert!(!RouteSource::Local.is_ibgp());
    }
}
