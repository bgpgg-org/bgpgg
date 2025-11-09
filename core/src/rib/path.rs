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

use crate::bgp::msg_update::Origin;
use crate::rib::types::RouteSource;
use std::cmp::Ordering;
use std::net::Ipv4Addr;

/// Represents a BGP path with all its attributes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Path {
    pub origin: Origin,
    pub as_path: Vec<u16>,
    pub next_hop: Ipv4Addr,
    pub source: RouteSource,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
}

impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Path {
    /// Compare paths for BGP best path selection per RFC 4271 Section 9.1.2.2
    /// Returns Ordering::Greater if self is better (higher preference)
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Step 1: Prefer the route with the highest degree of preference (LOCAL_PREF)
        let self_local_pref = self.local_pref.unwrap_or(100);
        let other_local_pref = other.local_pref.unwrap_or(100);
        match self_local_pref.cmp(&other_local_pref) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Step 2: Prefer the route with the shortest AS_PATH
        match other.as_path.len().cmp(&self.as_path.len()) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Step 3: Prefer the route with the lowest ORIGIN type (IGP < EGP < INCOMPLETE)
        let self_origin = self.origin as u8;
        let other_origin = other.origin as u8;
        match other_origin.cmp(&self_origin) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Step 4: Prefer the route with the lowest MULTI_EXIT_DISC (MED)
        // Note: MED comparison should ideally only be done for routes from same neighboring AS
        let self_med = self.med.unwrap_or(0);
        let other_med = other.med.unwrap_or(0);
        match other_med.cmp(&self_med) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Step 5: Prefer eBGP-learned routes over iBGP-learned routes
        match (&self.source, &other.source) {
            (RouteSource::Ebgp(_), RouteSource::Ibgp(_)) => return Ordering::Greater,
            (RouteSource::Ibgp(_), RouteSource::Ebgp(_)) => return Ordering::Less,
            // Local routes are considered better than any BGP-learned route
            (RouteSource::Local, RouteSource::Ebgp(_) | RouteSource::Ibgp(_)) => {
                return Ordering::Greater
            }
            (RouteSource::Ebgp(_) | RouteSource::Ibgp(_), RouteSource::Local) => {
                return Ordering::Less
            }
            _ => {}
        }

        // Step 6: If both paths are external, prefer the route from the BGP speaker
        // with the lowest BGP Identifier (using peer address as proxy)
        match (&self.source, &other.source) {
            (RouteSource::Ebgp(a), RouteSource::Ebgp(b)) => {
                b.cmp(a) // reverse for "prefer lower"
            }
            (RouteSource::Ibgp(a), RouteSource::Ibgp(b)) => {
                b.cmp(a) // also break ties for iBGP routes
            }
            _ => Ordering::Equal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn make_base_path() -> Path {
        Path {
            origin: Origin::IGP,
            as_path: vec![65001],
            next_hop: Ipv4Addr::new(192, 168, 1, 1),
            source: RouteSource::Ebgp("10.0.0.1".to_string()),
            local_pref: Some(100),
            med: None,
        }
    }

    #[test]
    fn test_local_pref_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.local_pref = Some(200);
        path2.local_pref = Some(100);

        assert!(path1 > path2);
    }

    #[test]
    fn test_as_path_length_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.as_path = vec![65001];
        path2.as_path = vec![65001, 65002];

        assert!(path1 > path2);
    }

    #[test]
    fn test_origin_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.origin = Origin::IGP;
        path2.origin = Origin::INCOMPLETE;

        assert!(path1 > path2);
    }

    #[test]
    fn test_med_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.med = Some(50);
        path2.med = Some(100);

        assert!(path1 > path2);
    }

    #[test]
    fn test_med_missing_treated_as_zero() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.med = None; // treated as 0
        path2.med = Some(100);

        // path1 (MED=0) should be preferred over path2 (MED=100)
        assert!(path1 > path2);
    }

    #[test]
    fn test_local_vs_ebgp_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.source = RouteSource::Local;
        path2.source = RouteSource::Ebgp("10.0.0.1".to_string());

        assert!(path1 > path2);
    }

    #[test]
    fn test_local_vs_ibgp_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.source = RouteSource::Local;
        path2.source = RouteSource::Ibgp("10.0.0.1".to_string());

        assert!(path1 > path2);
    }

    #[test]
    fn test_ebgp_vs_ibgp_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.source = RouteSource::Ebgp("10.0.0.1".to_string());
        path2.source = RouteSource::Ibgp("10.0.0.2".to_string());

        assert!(path1 > path2);
    }

    #[test]
    fn test_peer_address_tiebreaker() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.source = RouteSource::Ebgp("10.0.0.1".to_string());
        path2.source = RouteSource::Ebgp("10.0.0.2".to_string());

        // Lower peer address should win
        assert!(path1 > path2);
    }
}
