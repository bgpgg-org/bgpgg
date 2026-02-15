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

use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::net::{IpNetwork, Ipv4Net, Ipv6Net};
use crate::rib::{Path, Route};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

/// Adj-RIB-In: Per-peer input routing table
///
/// Stores routes received from a specific BGP peer before any import policy
/// or best path selection has been applied.
pub struct AdjRibIn {
    // Per-AFI/SAFI tables
    ipv4_unicast: HashMap<Ipv4Net, Route>, // AFI=1, SAFI=1
    ipv6_unicast: HashMap<Ipv6Net, Route>, // AFI=2, SAFI=1
}

impl AdjRibIn {
    pub fn add_route(&mut self, prefix: IpNetwork, path: Arc<Path>) {
        match prefix {
            IpNetwork::V4(net) => Self::add_to_table(&mut self.ipv4_unicast, net, prefix, path),
            IpNetwork::V6(net) => Self::add_to_table(&mut self.ipv6_unicast, net, prefix, path),
        }
    }

    pub fn get_all_routes(&self) -> Vec<Route> {
        let mut routes = Vec::new();
        routes.extend(self.ipv4_unicast.values().cloned());
        routes.extend(self.ipv6_unicast.values().cloned());
        routes
    }

    pub fn prefix_count(&self) -> usize {
        self.ipv4_unicast.len() + self.ipv6_unicast.len()
    }

    #[cfg(test)]
    pub fn clear(&mut self) {
        self.ipv4_unicast.clear();
        self.ipv6_unicast.clear();
    }
}

impl Default for AdjRibIn {
    fn default() -> Self {
        Self::new()
    }
}

impl AdjRibIn {
    pub fn new() -> Self {
        AdjRibIn {
            ipv4_unicast: HashMap::new(),
            ipv6_unicast: HashMap::new(),
        }
    }

    pub fn remove_route(&mut self, prefix: IpNetwork, remote_path_id: Option<u32>) {
        match prefix {
            IpNetwork::V4(net) => {
                Self::remove_from_table(&mut self.ipv4_unicast, &net, remote_path_id)
            }
            IpNetwork::V6(net) => {
                Self::remove_from_table(&mut self.ipv6_unicast, &net, remote_path_id)
            }
        }
    }

    /// Add or replace a path in a table. Matches by remote_path_id:
    /// - If a path with the same remote_path_id exists, replace it
    /// - Otherwise, add a new path
    ///
    /// Without ADD-PATH, remote_path_id is None on both sides -> one path per prefix.
    fn add_to_table<K: Eq + Hash>(
        table: &mut HashMap<K, Route>,
        key: K,
        prefix: IpNetwork,
        path: Arc<Path>,
    ) {
        if let Some(route) = table.get_mut(&key) {
            if let Some(existing) = route
                .paths
                .iter_mut()
                .find(|p| p.remote_path_id == path.remote_path_id)
            {
                *existing = path;
            } else {
                route.paths.push(path);
            }
        } else {
            table.insert(
                key,
                Route {
                    prefix,
                    paths: vec![path],
                },
            );
        }
    }

    /// Remove a path by remote_path_id. Removes the Route entry if no paths remain.
    /// Without ADD-PATH, remote_path_id is None -> removes the single path.
    fn remove_from_table<K: Eq + Hash>(
        table: &mut HashMap<K, Route>,
        key: &K,
        remote_path_id: Option<u32>,
    ) {
        if let Some(route) = table.get_mut(key) {
            route.paths.retain(|p| p.remote_path_id != remote_path_id);
            if route.paths.is_empty() {
                table.remove(key);
            }
        }
    }

    /// Clear all routes for a specific AFI/SAFI
    /// Returns the number of routes deleted
    pub fn clear_afi_safi(&mut self, afi_safi: AfiSafi) -> usize {
        match (afi_safi.afi, afi_safi.safi) {
            (Afi::Ipv4, Safi::Unicast) => {
                let count = self.ipv4_unicast.len();
                self.ipv4_unicast.clear();
                count
            }
            (Afi::Ipv6, Safi::Unicast) => {
                let count = self.ipv6_unicast.len();
                self.ipv6_unicast.clear();
                count
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType};
    use crate::net::Ipv4Net;
    use crate::test_helpers::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_peer_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    }

    fn test_bgp_id() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    #[test]
    fn test_new_adj_rib_in() {
        let rib_in = AdjRibIn::new();
        assert_eq!(rib_in.get_all_routes().len(), 0);
    }

    #[test]
    fn test_add_route() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();
        let path = create_test_path(test_peer_ip(), test_bgp_id());

        rib_in.add_route(prefix, path.clone());

        let routes = rib_in.get_all_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, prefix);
        assert_eq!(routes[0].paths[0].attrs, path.attrs);
    }

    #[test]
    fn test_add_multiple_routes() {
        let peer_ip = test_peer_ip();
        let mut rib_in = AdjRibIn::new();

        let prefix1 = create_test_prefix();
        let prefix2 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 24,
        });

        let path1 = create_test_path(peer_ip, test_bgp_id());
        let path2 = create_test_path(peer_ip, test_bgp_id());

        rib_in.add_route(prefix1, path1.clone());
        rib_in.add_route(prefix2, path2.clone());

        let mut routes = rib_in.get_all_routes();
        routes.sort_by_key(|r| format!("{:?}", r.prefix));

        let mut expected = [
            Route {
                prefix: prefix1,
                paths: vec![path1],
            },
            Route {
                prefix: prefix2,
                paths: vec![path2],
            },
        ];
        expected.sort_by_key(|r| format!("{:?}", r.prefix));

        assert_eq!(routes.len(), expected.len());
        for (route, exp) in routes.iter().zip(expected.iter()) {
            assert!(route.attrs_eq(exp));
        }
    }

    #[test]
    fn test_add_route_overwrite() {
        let peer_ip = test_peer_ip();
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer_ip, test_bgp_id());
        let path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.attrs.as_path = vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 2,
                asn_list: vec![300, 400],
            }];
        });

        rib_in.add_route(prefix, path1);
        rib_in.add_route(prefix, Arc::clone(&path2));

        let routes = rib_in.get_all_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].paths[0].as_path(),
            &vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 2,
                asn_list: vec![300, 400],
            }]
        );
    }

    #[test]
    fn test_remove_route() {
        let peer_ip = test_peer_ip();
        let mut rib_in = AdjRibIn::new();
        let prefix1 = create_test_prefix();
        let prefix2 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 24,
        });

        let path1 = create_test_path(peer_ip, test_bgp_id());
        let path2 = create_test_path(peer_ip, test_bgp_id());

        rib_in.add_route(prefix1, path1);
        rib_in.add_route(prefix2, path2.clone());

        rib_in.remove_route(prefix1, None);

        let routes = rib_in.get_all_routes();
        assert_eq!(routes.len(), 1);
        assert!(routes[0].attrs_eq(&Route {
            prefix: prefix2,
            paths: vec![path2]
        }));
    }

    #[test]
    fn test_remove_nonexistent_route() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        rib_in.remove_route(prefix, None);
        assert_eq!(rib_in.get_all_routes().len(), 0);
    }

    #[test]
    fn test_clear_afi_safi() {
        use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};

        let peer_ip = test_peer_ip();
        let mut rib_in = AdjRibIn::new();

        // Add IPv4 and IPv6 routes
        let ipv4_prefix = create_test_prefix();
        let ipv6_prefix = IpNetwork::V6(crate::net::Ipv6Net {
            address: std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            prefix_length: 64,
        });

        rib_in.add_route(ipv4_prefix, create_test_path(peer_ip, test_bgp_id()));
        rib_in.add_route(ipv6_prefix, create_test_path(peer_ip, test_bgp_id()));

        assert_eq!(rib_in.prefix_count(), 2);

        // Clear IPv4/Unicast
        let count = rib_in.clear_afi_safi(AfiSafi::new(Afi::Ipv4, Safi::Unicast));
        assert_eq!(count, 1);
        assert_eq!(rib_in.prefix_count(), 1);

        // Clear IPv6/Unicast
        let count = rib_in.clear_afi_safi(AfiSafi::new(Afi::Ipv6, Safi::Unicast));
        assert_eq!(count, 1);
        assert_eq!(rib_in.prefix_count(), 0);

        // Clearing again returns 0
        let count = rib_in.clear_afi_safi(AfiSafi::new(Afi::Ipv4, Safi::Unicast));
        assert_eq!(count, 0);
    }

    #[test]
    fn test_clear() {
        let peer_ip = test_peer_ip();
        let mut rib_in = AdjRibIn::new();

        rib_in.add_route(
            create_test_prefix(),
            create_test_path(peer_ip, test_bgp_id()),
        );
        rib_in.add_route(
            IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 1, 0, 0),
                prefix_length: 24,
            }),
            create_test_path(peer_ip, test_bgp_id()),
        );

        assert_eq!(rib_in.get_all_routes().len(), 2);

        rib_in.clear();
        assert_eq!(rib_in.get_all_routes().len(), 0);
    }

    #[test]
    fn test_addpath_multiple_paths_coexist() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        let path1 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
        });
        let path2 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(2);
            p.attrs.as_path = vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 3,
                asn_list: vec![100, 200, 300],
            }];
        });

        rib_in.add_route(prefix, path1);
        rib_in.add_route(prefix, path2);

        let routes = rib_in.get_all_routes();
        assert_eq!(routes.len(), 1, "same prefix should be one Route");
        assert_eq!(routes[0].paths.len(), 2, "two paths should coexist");
    }

    #[test]
    fn test_addpath_replace_by_remote_path_id() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        let path1 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
            p.attrs.med = Some(10);
        });
        let path1_updated = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
            p.attrs.med = Some(20);
        });

        rib_in.add_route(prefix, path1);
        rib_in.add_route(prefix, path1_updated);

        let routes = rib_in.get_all_routes();
        assert_eq!(routes[0].paths.len(), 1, "same path_id should replace");
        assert_eq!(routes[0].paths[0].med(), Some(20));
    }

    #[test]
    fn test_addpath_withdraw_one_path() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        let path1 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
        });
        let path2 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(2);
        });

        rib_in.add_route(prefix, path1);
        rib_in.add_route(prefix, path2);
        assert_eq!(rib_in.get_all_routes()[0].paths.len(), 2);

        // Withdraw path_id=1, path_id=2 should remain
        rib_in.remove_route(prefix, Some(1));
        let routes = rib_in.get_all_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].paths.len(), 1);
        assert_eq!(routes[0].paths[0].remote_path_id, Some(2));
    }

    #[test]
    fn test_addpath_withdraw_all_removes_entry() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        let path1 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
        });

        rib_in.add_route(prefix, path1);
        rib_in.remove_route(prefix, Some(1));

        assert_eq!(rib_in.prefix_count(), 0, "entry should be removed");
    }

    #[test]
    fn test_non_addpath() {
        // Without ADD-PATH, remote_path_id is None on all paths.
        // add_route should overwrite, remove_route should remove.
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        let path1 = create_test_path(test_peer_ip(), test_bgp_id());
        let path2 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.attrs.med = Some(50);
        });

        rib_in.add_route(prefix, path1);
        rib_in.add_route(prefix, path2);

        // Should have replaced (both have remote_path_id=None)
        let routes = rib_in.get_all_routes();
        assert_eq!(routes[0].paths.len(), 1);
        assert_eq!(routes[0].paths[0].med(), Some(50));

        rib_in.remove_route(prefix, None);
        assert_eq!(rib_in.prefix_count(), 0);
    }
}
