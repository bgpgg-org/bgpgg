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

/// Adj-RIB-Out: Per-peer output routing table
///
/// Stores routes that will be advertised to a specific BGP peer
/// after export policy has been applied.
pub(super) struct AdjRibOut {
    // Map from prefix to routes to advertise to this peer
    routes: HashMap<IpNetwork, Route>,
    peer_addr: SocketAddr,
}

impl Rib for AdjRibOut {
    fn add_route(&mut self, prefix: IpNetwork, path: Path) {
        self.routes.insert(
            prefix,
            Route {
                prefix,
                paths: vec![path],
            },
        );
    }

    fn get_all_routes(&self) -> Vec<Route> {
        self.routes.values().cloned().collect()
    }

    fn clear(&mut self) {
        self.routes.clear()
    }
}

impl AdjRibOut {
    pub(super) fn new(peer_addr: SocketAddr) -> Self {
        AdjRibOut {
            routes: HashMap::new(),
            peer_addr,
        }
    }

    pub(super) fn remove_route(&mut self, prefix: IpNetwork) {
        self.routes.remove(&prefix);
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
    fn test_new_adj_rib_out() {
        let peer_addr: SocketAddr = "192.0.2.1:179".parse().unwrap();
        let rib_out = AdjRibOut::new(peer_addr);

        assert_eq!(rib_out.get_all_routes(), vec![]);
        assert_eq!(rib_out.routes_len(), 0);
    }

    #[test]
    fn test_add_route() {
        let peer_addr: SocketAddr = "192.0.2.1:179".parse().unwrap();
        let mut rib_out = AdjRibOut::new(peer_addr);
        let prefix = create_test_prefix();
        let path = create_test_path(peer_addr);

        rib_out.add_route(prefix, path.clone());

        assert_eq!(
            rib_out.get_all_routes(),
            vec![Route {
                prefix,
                paths: vec![path]
            }]
        );
        assert_eq!(rib_out.routes_len(), 1);
    }

    #[test]
    fn test_add_multiple_routes() {
        let peer_addr: SocketAddr = "192.0.2.1:179".parse().unwrap();
        let mut rib_out = AdjRibOut::new(peer_addr);

        let prefix1 = create_test_prefix();
        let prefix2 = IpNetwork::V4(crate::bgp::utils::Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 24,
        });

        let path1 = create_test_path(peer_addr);
        let path2 = create_test_path(peer_addr);

        rib_out.add_route(prefix1, path1.clone());
        rib_out.add_route(prefix2, path2.clone());

        let mut routes = rib_out.get_all_routes();
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
        assert_eq!(rib_out.routes_len(), 2);
    }

    #[test]
    fn test_add_route_overwrite() {
        let peer_addr: SocketAddr = "192.0.2.1:179".parse().unwrap();
        let mut rib_out = AdjRibOut::new(peer_addr);
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer_addr);
        let mut path2 = create_test_path(peer_addr);
        path2.as_path = vec![300, 400];

        rib_out.add_route(prefix, path1);
        rib_out.add_route(prefix, path2.clone());

        let routes = rib_out.get_all_routes();
        assert_eq!(
            routes,
            vec![Route {
                prefix,
                paths: vec![path2]
            }]
        );
    }

    #[test]
    fn test_remove_route() {
        let peer_addr: SocketAddr = "192.0.2.1:179".parse().unwrap();
        let mut rib_out = AdjRibOut::new(peer_addr);
        let prefix1 = create_test_prefix();
        let prefix2 = IpNetwork::V4(crate::bgp::utils::Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 24,
        });

        let path1 = create_test_path(peer_addr);
        let path2 = create_test_path(peer_addr);

        rib_out.add_route(prefix1, path1);
        rib_out.add_route(prefix2, path2.clone());

        rib_out.remove_route(prefix1);

        assert_eq!(
            rib_out.get_all_routes(),
            vec![Route {
                prefix: prefix2,
                paths: vec![path2]
            }]
        );
        assert_eq!(rib_out.routes_len(), 1);
    }

    #[test]
    fn test_remove_nonexistent_route() {
        let peer_addr: SocketAddr = "192.0.2.1:179".parse().unwrap();
        let mut rib_out = AdjRibOut::new(peer_addr);
        let prefix = create_test_prefix();

        rib_out.remove_route(prefix);
        assert_eq!(rib_out.get_all_routes(), vec![]);
    }

    #[test]
    fn test_clear() {
        let peer_addr: SocketAddr = "192.0.2.1:179".parse().unwrap();
        let mut rib_out = AdjRibOut::new(peer_addr);

        rib_out.add_route(create_test_prefix(), create_test_path(peer_addr));
        rib_out.add_route(
            IpNetwork::V4(crate::bgp::utils::Ipv4Net {
                address: Ipv4Addr::new(10, 1, 0, 0),
                prefix_length: 24,
            }),
            create_test_path(peer_addr),
        );

        assert_eq!(rib_out.routes_len(), 2);

        rib_out.clear();
        assert_eq!(rib_out.get_all_routes(), vec![]);
        assert_eq!(rib_out.routes_len(), 0);
    }
}
