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

use crate::net::IpNetwork;
use crate::peer::SessionType;
use crate::rib::path::Path;
use std::net::IpAddr;
use std::sync::Arc;

/// Source of a route
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum RouteSource {
    /// Route learned from an EBGP peer (external AS)
    Ebgp(IpAddr),
    /// Route learned from an IBGP peer (same AS)
    Ibgp(IpAddr),
    /// Route originated locally by this router
    Local,
}

impl RouteSource {
    /// Create a RouteSource based on BGP session type
    pub fn from_session(session_type: SessionType, peer_addr: IpAddr) -> Self {
        match session_type {
            SessionType::Ebgp => RouteSource::Ebgp(peer_addr),
            SessionType::Ibgp => RouteSource::Ibgp(peer_addr),
        }
    }

    /// Check if this route was learned via iBGP
    pub fn is_ibgp(&self) -> bool {
        matches!(self, RouteSource::Ibgp(_))
    }

    /// Check if this route was learned via eBGP
    pub fn is_ebgp(&self) -> bool {
        matches!(self, RouteSource::Ebgp(_))
    }

    /// Check if this route was originated locally
    pub fn is_local(&self) -> bool {
        matches!(self, RouteSource::Local)
    }
}

/// Represents a route with one or more paths to a prefix
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Route {
    pub prefix: IpNetwork,
    pub paths: Vec<Arc<Path>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_route_source_from_session() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            RouteSource::from_session(SessionType::Ebgp, ip1),
            RouteSource::Ebgp(ip1)
        );
        assert_eq!(
            RouteSource::from_session(SessionType::Ibgp, ip2),
            RouteSource::Ibgp(ip2)
        );
    }

    #[test]
    fn test_is_ibgp() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(RouteSource::Ibgp(ip1).is_ibgp());
        assert!(!RouteSource::Ebgp(ip2).is_ibgp());
        assert!(!RouteSource::Local.is_ibgp());
    }

    #[test]
    fn test_is_ebgp() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(RouteSource::Ebgp(ip1).is_ebgp());
        assert!(!RouteSource::Ibgp(ip2).is_ebgp());
        assert!(!RouteSource::Local.is_ebgp());
    }

    #[test]
    fn test_is_local() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(RouteSource::Local.is_local());
        assert!(!RouteSource::Ebgp(ip1).is_local());
        assert!(!RouteSource::Ibgp(ip2).is_local());
    }
}
