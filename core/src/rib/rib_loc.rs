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
use crate::rib::types::{Path, Route};
use crate::rib::Rib;
use std::collections::HashMap;
use std::net::SocketAddr;

/// Loc-RIB: Local routing table
///
/// Contains the best paths selected after applying import policies
/// and the BGP best path selection algorithm.
pub(super) struct LocRib {
    // Map from prefix to best route(s)
    routes: HashMap<IpNetwork, Route>,
}

impl Rib for LocRib {
    fn add_route(&mut self, prefix: IpNetwork, path: Path) {
        self.routes
            .entry(prefix)
            .and_modify(|route| {
                // Check if we already have a path from this peer, if so replace it
                if let Some(existing_path) = route
                    .paths
                    .iter_mut()
                    .find(|p| p.from_peer == path.from_peer)
                {
                    *existing_path = path.clone();
                } else {
                    route.paths.push(path.clone());
                }
            })
            .or_insert_with(|| Route {
                prefix,
                paths: vec![path],
            });
    }

    fn get_all_routes(&self) -> Vec<Route> {
        self.routes.values().cloned().collect()
    }

    fn clear(&mut self) {
        self.routes.clear();
    }
}

impl LocRib {
    pub(super) fn new() -> Self {
        LocRib {
            routes: HashMap::new(),
        }
    }

    pub(super) fn remove_routes_from_peer(&mut self, peer_addr: SocketAddr) {
        for route in self.routes.values_mut() {
            route.paths.retain(|p| p.from_peer != peer_addr);
        }
        self.routes.retain(|_, route| !route.paths.is_empty());
    }

    fn get_best_path(&self, prefix: &IpNetwork) -> Option<&Path> {
        self.routes.get(prefix).and_then(|route| {
            // Simple best path: first path (in real BGP: complex decision process)
            route.paths.first()
        })
    }

    pub(super) fn routes_len(&self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::test_helpers::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_new_loc_rib() {
        let loc_rib = LocRib::new();
        assert_eq!(loc_rib.get_all_routes(), vec![]);
        assert_eq!(loc_rib.routes_len(), 0);
    }

    #[test]
    fn test_add_route() {
        let mut loc_rib = LocRib::new();
        let peer_addr: SocketAddr = "192.0.2.1:179".parse().unwrap();
        let prefix = create_test_prefix();
        let path = create_test_path(peer_addr);

        loc_rib.add_route(prefix, path.clone());

        assert_eq!(
            loc_rib.get_all_routes(),
            vec![Route {
                prefix,
                paths: vec![path]
            }]
        );
    }

    #[test]
    fn test_add_multiple_routes_different_prefixes() {
        let mut loc_rib = LocRib::new();
        let peer_addr: SocketAddr = "192.0.2.1:179".parse().unwrap();

        let prefix1 = create_test_prefix();
        let prefix2 = IpNetwork::V4(crate::bgp::utils::Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 24,
        });

        let path1 = create_test_path(peer_addr);
        let path2 = create_test_path(peer_addr);

        loc_rib.add_route(prefix1, path1.clone());
        loc_rib.add_route(prefix2, path2.clone());

        let mut routes = loc_rib.get_all_routes();
        routes.sort_by_key(|r| format!("{:?}", r.prefix));

        let mut expected = vec![
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

        assert_eq!(routes, expected);
    }

    #[test]
    fn test_add_multiple_paths_same_prefix_different_peers() {
        let mut loc_rib = LocRib::new();
        let peer1: SocketAddr = "192.0.2.1:179".parse().unwrap();
        let peer2: SocketAddr = "192.0.2.2:179".parse().unwrap();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer1);
        let path2 = create_test_path(peer2);

        loc_rib.add_route(prefix, path1.clone());
        loc_rib.add_route(prefix, path2.clone());

        let routes = loc_rib.get_all_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, prefix);

        let mut paths = routes[0].paths.clone();
        paths.sort_by_key(|p| format!("{:?}", p.from_peer));

        let mut expected_paths = vec![path1, path2];
        expected_paths.sort_by_key(|p| format!("{:?}", p.from_peer));

        assert_eq!(paths, expected_paths);
    }

    #[test]
    fn test_add_route_same_peer_updates_path() {
        let mut loc_rib = LocRib::new();
        let peer_addr: SocketAddr = "192.0.2.1:179".parse().unwrap();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer_addr);
        let mut path2 = create_test_path(peer_addr);
        path2.as_path = vec![300, 400];

        loc_rib.add_route(prefix, path1);
        loc_rib.add_route(prefix, path2.clone());

        assert_eq!(
            loc_rib.get_all_routes(),
            vec![Route {
                prefix,
                paths: vec![path2]
            }]
        );
    }

    #[test]
    fn test_remove_routes_from_peer() {
        let mut loc_rib = LocRib::new();
        let peer1: SocketAddr = "192.0.2.1:179".parse().unwrap();
        let peer2: SocketAddr = "192.0.2.2:179".parse().unwrap();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer1);
        let path2 = create_test_path(peer2);

        loc_rib.add_route(prefix, path1);
        loc_rib.add_route(prefix, path2.clone());

        loc_rib.remove_routes_from_peer(peer1);

        assert_eq!(
            loc_rib.get_all_routes(),
            vec![Route {
                prefix,
                paths: vec![path2]
            }]
        );
    }

    #[test]
    fn test_remove_routes_from_peer_removes_empty_routes() {
        let mut loc_rib = LocRib::new();
        let peer_addr: SocketAddr = "192.0.2.1:179".parse().unwrap();
        let prefix = create_test_prefix();
        let path = create_test_path(peer_addr);

        loc_rib.add_route(prefix, path);
        loc_rib.remove_routes_from_peer(peer_addr);

        assert_eq!(loc_rib.get_all_routes(), vec![]);
        assert_eq!(loc_rib.routes_len(), 0);
    }
}
