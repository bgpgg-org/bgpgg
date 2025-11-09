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
use crate::rib::{Path, Route};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Adj-RIB-In: Per-peer input routing table
///
/// Stores routes received from a specific BGP peer before any import policy
/// or best path selection has been applied.
pub struct AdjRibIn {
    // Map from prefix to routes learned from this specific peer
    routes: HashMap<IpNetwork, Route>,
}

impl AdjRibIn {
    pub fn add_route(&mut self, prefix: IpNetwork, path: Path) {
        self.routes.insert(
            prefix,
            Route {
                prefix,
                paths: vec![path],
            },
        );
    }

    pub fn get_all_routes(&self) -> Vec<Route> {
        self.routes.values().cloned().collect()
    }

    #[cfg(test)]
    pub fn clear(&mut self) {
        self.routes.clear();
    }
}

impl AdjRibIn {
    pub fn new(_peer_ip: String) -> Self {
        AdjRibIn {
            routes: HashMap::new(),
        }
    }

    pub fn remove_route(&mut self, prefix: IpNetwork) {
        self.routes.remove(&prefix);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::test_helpers::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_new_adj_rib_in() {
        let peer_ip = "192.0.2.1".to_string();
        let rib_in = AdjRibIn::new(peer_ip);

        assert_eq!(rib_in.get_all_routes().len(), 0);
    }

    #[test]
    fn test_add_route() {
        let peer_ip = "192.0.2.1".to_string();
        let mut rib_in = AdjRibIn::new(peer_ip.clone());
        let prefix = create_test_prefix();
        let path = create_test_path(peer_ip.clone());

        rib_in.add_route(prefix, path.clone());

        let routes = rib_in.get_all_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, prefix);
        assert_eq!(routes[0].paths[0], path);
    }

    #[test]
    fn test_add_multiple_routes() {
        let peer_ip = "192.0.2.1".to_string();
        let mut rib_in = AdjRibIn::new(peer_ip.clone());

        let prefix1 = create_test_prefix();
        let prefix2 = IpNetwork::V4(crate::bgp::utils::Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 24,
        });

        let path1 = create_test_path(peer_ip.clone());
        let path2 = create_test_path(peer_ip.clone());

        rib_in.add_route(prefix1, path1.clone());
        rib_in.add_route(prefix2, path2.clone());

        let mut routes = rib_in.get_all_routes();
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
    fn test_add_route_overwrite() {
        let peer_ip = "192.0.2.1".to_string();
        let mut rib_in = AdjRibIn::new(peer_ip.clone());
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer_ip.clone());
        let mut path2 = create_test_path(peer_ip.clone());
        path2.as_path = vec![300, 400];

        rib_in.add_route(prefix, path1);
        rib_in.add_route(prefix, path2.clone());

        let routes = rib_in.get_all_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].paths[0].as_path, vec![300, 400]);
    }

    #[test]
    fn test_remove_route() {
        let peer_ip = "192.0.2.1".to_string();
        let mut rib_in = AdjRibIn::new(peer_ip.clone());
        let prefix1 = create_test_prefix();
        let prefix2 = IpNetwork::V4(crate::bgp::utils::Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 24,
        });

        let path1 = create_test_path(peer_ip.clone());
        let path2 = create_test_path(peer_ip.clone());

        rib_in.add_route(prefix1, path1);
        rib_in.add_route(prefix2, path2.clone());

        rib_in.remove_route(prefix1);

        let routes = rib_in.get_all_routes();
        assert_eq!(
            routes,
            vec![Route {
                prefix: prefix2,
                paths: vec![path2]
            }]
        );
    }

    #[test]
    fn test_remove_nonexistent_route() {
        let peer_ip = "192.0.2.1".to_string();
        let mut rib_in = AdjRibIn::new(peer_ip.clone());
        let prefix = create_test_prefix();

        rib_in.remove_route(prefix);
        assert_eq!(rib_in.get_all_routes().len(), 0);
    }

    #[test]
    fn test_clear() {
        let peer_ip = "192.0.2.1".to_string();
        let mut rib_in = AdjRibIn::new(peer_ip.clone());

        rib_in.add_route(create_test_prefix(), create_test_path(peer_ip.clone()));
        rib_in.add_route(
            IpNetwork::V4(crate::bgp::utils::Ipv4Net {
                address: Ipv4Addr::new(10, 1, 0, 0),
                prefix_length: 24,
            }),
            create_test_path(peer_ip.clone()),
        );

        assert_eq!(rib_in.get_all_routes().len(), 2);

        rib_in.clear();
        assert_eq!(rib_in.get_all_routes().len(), 0);
    }
}
