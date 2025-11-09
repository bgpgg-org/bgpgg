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
use crate::rib::{Path, Route, RouteSource};
use crate::{debug, info};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

/// Loc-RIB: Local routing table
///
/// Contains the best paths selected after applying import policies
/// and the BGP best path selection algorithm.
pub struct LocRib {
    // Map from prefix to best route(s)
    routes: HashMap<IpNetwork, Route>,
    local_asn: u16,
}

impl LocRib {
    fn add_route(&mut self, prefix: IpNetwork, path: Path) {
        self.routes
            .entry(prefix)
            .and_modify(|route| {
                // Check if we already have a path from this source, if so replace it
                if let Some(existing_path) =
                    route.paths.iter_mut().find(|p| p.source == path.source)
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

    /// Remove paths from a specific peer for a given prefix.
    /// Returns true if a path was actually removed.
    fn remove_peer_path(&mut self, prefix: IpNetwork, peer_ip: String) -> bool {
        if let Some(route) = self.routes.get_mut(&prefix) {
            let had_path = route.paths.iter().any(|p| {
                matches!(
                    &p.source,
                    RouteSource::Ebgp(ip) | RouteSource::Ibgp(ip) if ip == &peer_ip
                )
            });
            route.paths.retain(|p| {
                !matches!(
                    &p.source,
                    RouteSource::Ebgp(ip) | RouteSource::Ibgp(ip) if ip == &peer_ip
                )
            });

            // Remove route if no paths left
            if route.paths.is_empty() {
                self.routes.remove(&prefix);
            }

            had_path
        } else {
            false
        }
    }

    pub fn get_all_routes(&self) -> Vec<Route> {
        self.routes.values().cloned().collect()
    }

    /// Update Loc-RIB from delta changes (withdrawn and announced routes)
    /// Returns the set of prefixes that changed for propagation to other peers
    pub fn update_from_peer(
        &mut self,
        peer_ip: String,
        withdrawn: Vec<IpNetwork>,
        announced: Vec<(IpNetwork, Path)>,
    ) -> Vec<IpNetwork> {
        let mut changed_prefixes = Vec::new();

        // Process withdrawals
        for prefix in withdrawn {
            info!("withdrawing route from Loc-RIB", "prefix" => format!("{:?}", prefix), "peer_ip" => &peer_ip);

            if self.remove_peer_path(prefix, peer_ip.clone()) {
                changed_prefixes.push(prefix);
            }
        }

        // Process announcements - apply import policy and add to Loc-RIB
        for (prefix, mut path) in announced {
            if self.apply_import_policy(&mut path) {
                info!("adding route to Loc-RIB", "prefix" => format!("{:?}", prefix), "peer_ip" => &peer_ip);
                self.add_route(prefix, path);
                changed_prefixes.push(prefix);
            } else {
                debug!("route rejected by import policy", "prefix" => format!("{:?}", prefix), "peer_ip" => &peer_ip);

                // Implicit withdrawal: remove any existing route for this prefix from this peer
                if self.remove_peer_path(prefix, peer_ip.clone()) {
                    changed_prefixes.push(prefix);
                }
            }
        }

        // Run best path selection on changed prefixes only
        self.run_best_path_selection(&changed_prefixes);

        // Return changed prefixes for propagation
        changed_prefixes
    }

    fn apply_import_policy(&self, path: &mut Path) -> bool {
        // Set default local preference if not set
        // TODO: only do this for iBGP
        if path.local_pref.is_none() {
            path.local_pref = Some(100);
        }

        // Reject routes with our own ASN (loop prevention)
        if path.as_path.contains(&self.local_asn) {
            debug!("rejecting route due to AS loop", "local_asn" => self.local_asn);
            return false;
        }

        // Accept by default
        true
    }

    fn run_best_path_selection(&mut self, changed_prefixes: &[IpNetwork]) {
        for prefix in changed_prefixes {
            if let Some(route) = self.routes.get_mut(prefix) {
                if route.paths.len() > 1 {
                    debug!("running best path selection", "prefix" => format!("{:?}", prefix), "num_paths" => route.paths.len());

                    // Find the best path using Ord implementation
                    // paths are compared such that "greater" means "better"
                    if let Some(best_path) = route.paths.iter().max().cloned() {
                        route.paths = vec![best_path];
                    }
                } else {
                    debug!("skipping best path selection (single path)", "prefix" => format!("{:?}", prefix));
                }
            }
        }
    }
}

impl LocRib {
    pub fn new(local_asn: u16) -> Self {
        LocRib {
            routes: HashMap::new(),
            local_asn,
        }
    }

    /// Add a locally originated route
    pub fn add_local_route(
        &mut self,
        prefix: IpNetwork,
        next_hop: Ipv4Addr,
        origin: crate::bgp::msg_update::Origin,
    ) {
        let path = Path {
            origin,
            as_path: vec![self.local_asn],
            next_hop,
            source: RouteSource::Local,
            local_pref: Some(100),
            med: None,
        };

        info!("adding local route to Loc-RIB", "prefix" => format!("{:?}", prefix), "next_hop" => next_hop.to_string());
        self.add_route(prefix, path);
        self.run_best_path_selection(&[prefix]);
    }

    /// Remove a locally originated route
    pub fn remove_local_route(&mut self, prefix: IpNetwork) {
        info!("removing local route from Loc-RIB", "prefix" => format!("{:?}", prefix));

        if let Some(route) = self.routes.get_mut(&prefix) {
            route.paths.retain(|p| p.source != RouteSource::Local);
        }
        self.routes.retain(|_, route| !route.paths.is_empty());
        self.run_best_path_selection(&[prefix]);
    }

    pub fn remove_routes_from_peer(&mut self, peer_ip: String) -> Vec<IpNetwork> {
        let mut changed_prefixes = Vec::new();

        for (prefix, route) in self.routes.iter_mut() {
            let original_len = route.paths.len();
            route.paths.retain(|p| {
                !matches!(
                    &p.source,
                    RouteSource::Ebgp(ip) | RouteSource::Ibgp(ip) if ip == &peer_ip
                )
            });
            // If paths were removed, this prefix was affected
            if route.paths.len() != original_len {
                changed_prefixes.push(*prefix);
            }
        }
        self.routes.retain(|_, route| !route.paths.is_empty());

        // Run best path selection on all affected prefixes
        self.run_best_path_selection(&changed_prefixes);

        changed_prefixes
    }

    pub fn routes_len(&self) -> usize {
        self.routes.len()
    }

    /// Get the best path for a specific prefix, if any
    pub fn get_best_path(&self, prefix: &IpNetwork) -> Option<&Path> {
        self.routes
            .get(prefix)
            .and_then(|route| route.paths.first())
    }

    /// Check if a prefix exists in Loc-RIB
    pub fn has_prefix(&self, prefix: &IpNetwork) -> bool {
        self.routes.contains_key(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::test_helpers::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_new_loc_rib() {
        let loc_rib = LocRib::new(65000);
        assert_eq!(loc_rib.get_all_routes(), vec![]);
        assert_eq!(loc_rib.routes_len(), 0);
    }

    #[test]
    fn test_add_route() {
        let mut loc_rib = LocRib::new(65000);
        let peer_ip = "192.0.2.1".to_string();
        let prefix = create_test_prefix();
        let path = create_test_path(peer_ip.clone());

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
        let mut loc_rib = LocRib::new(65000);
        let peer_ip = "192.0.2.1".to_string();

        let prefix1 = create_test_prefix();
        let prefix2 = IpNetwork::V4(crate::bgp::utils::Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 24,
        });

        let path1 = create_test_path(peer_ip.clone());
        let path2 = create_test_path(peer_ip.clone());

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
        let mut loc_rib = LocRib::new(65000);
        let peer1 = "192.0.2.1".to_string();
        let peer2 = "192.0.2.2".to_string();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer1.clone());
        let path2 = create_test_path(peer2.clone());

        loc_rib.add_route(prefix, path1.clone());
        loc_rib.add_route(prefix, path2.clone());

        let routes = loc_rib.get_all_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, prefix);

        let mut paths = routes[0].paths.clone();
        paths.sort_by_key(|p| format!("{:?}", p.source));

        let mut expected_paths = vec![path1, path2];
        expected_paths.sort_by_key(|p| format!("{:?}", p.source));

        assert_eq!(paths, expected_paths);
    }

    #[test]
    fn test_add_route_same_peer_updates_path() {
        let mut loc_rib = LocRib::new(65000);
        let peer_ip = "192.0.2.1".to_string();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer_ip.clone());
        let mut path2 = create_test_path(peer_ip.clone());
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
        let mut loc_rib = LocRib::new(65000);
        let peer1 = "192.0.2.1".to_string();
        let peer2 = "192.0.2.2".to_string();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer1.clone());
        let path2 = create_test_path(peer2.clone());

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
        let mut loc_rib = LocRib::new(65000);
        let peer_ip = "192.0.2.1".to_string();
        let prefix = create_test_prefix();
        let path = create_test_path(peer_ip.clone());

        loc_rib.add_route(prefix, path);
        loc_rib.remove_routes_from_peer(peer_ip);

        assert_eq!(loc_rib.get_all_routes(), vec![]);
        assert_eq!(loc_rib.routes_len(), 0);
    }
}
