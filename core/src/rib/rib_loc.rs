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

use crate::bgp::msg_update::{AsPathSegment, Origin};
use crate::bgp::utils::IpNetwork;
use crate::rib::{Path, Route, RouteSource};
use crate::{debug, info};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// Loc-RIB: Local routing table
///
/// Contains the best paths selected after applying import policies
/// and the BGP best path selection algorithm.
pub struct LocRib {
    // Map from prefix to best route(s)
    routes: HashMap<IpNetwork, Route>,
}

impl LocRib {
    fn add_route(&mut self, prefix: IpNetwork, path: Arc<Path>) {
        match self.routes.entry(prefix) {
            Entry::Occupied(mut entry) => {
                let route = entry.get_mut();
                // Check if we already have a path from this source, if so replace it
                if let Some(existing_path) =
                    route.paths.iter_mut().find(|p| p.source == path.source)
                {
                    *existing_path = path;
                } else {
                    route.paths.push(path);
                }
                // Keep paths sorted (best first)
                route.paths.sort_by(|a, b| b.cmp(a));
            }
            Entry::Vacant(entry) => {
                entry.insert(Route {
                    prefix,
                    paths: vec![path],
                });
            }
        }
    }

    /// Remove paths from a specific peer for a given prefix.
    /// Returns true if a path was actually removed.
    fn remove_peer_path(&mut self, prefix: IpNetwork, peer_ip: IpAddr) -> bool {
        if let Some(route) = self.routes.get_mut(&prefix) {
            let had_path = route.paths.iter().any(|p| {
                matches!(
                    &p.source,
                    RouteSource::Ebgp(ip) | RouteSource::Ibgp(ip) if *ip == peer_ip
                )
            });
            route.paths.retain(|p| {
                !matches!(
                    &p.source,
                    RouteSource::Ebgp(ip) | RouteSource::Ibgp(ip) if *ip == peer_ip
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
    /// Applies import policy (via closure) before adding routes
    /// Returns the set of prefixes where the best path actually changed
    pub fn update_from_peer<F>(
        &mut self,
        peer_ip: IpAddr,
        withdrawn: Vec<IpNetwork>,
        announced: Vec<(IpNetwork, Arc<Path>)>,
        import_policy: F,
    ) -> Vec<IpNetwork>
    where
        F: Fn(&IpNetwork, &mut Path) -> bool,
    {
        // Collect affected prefixes and snapshot old best BEFORE mutations
        let mut affected: Vec<IpNetwork> = withdrawn.clone();
        for (prefix, _) in &announced {
            if !affected.contains(prefix) {
                affected.push(*prefix);
            }
        }
        let old_best: HashMap<IpNetwork, Option<Arc<Path>>> = affected
            .iter()
            .map(|p| (*p, self.get_best_path(p).map(Arc::clone)))
            .collect();

        // Process withdrawals
        for prefix in withdrawn {
            info!("withdrawing route from Loc-RIB", "prefix" => format!("{:?}", prefix), "peer_ip" => peer_ip.to_string());
            self.remove_peer_path(prefix, peer_ip);
        }

        // Process announcements - apply import policy and add to Loc-RIB
        for (prefix, path_arc) in announced {
            // Clone inner Path for policy mutation
            let mut path = (*path_arc).clone();
            if import_policy(&prefix, &mut path) {
                info!("adding route to Loc-RIB", "prefix" => format!("{:?}", prefix), "peer_ip" => peer_ip.to_string());
                self.add_route(prefix, Arc::new(path));
            } else {
                debug!("route rejected by import policy", "prefix" => format!("{:?}", prefix), "peer_ip" => peer_ip.to_string());
                self.remove_peer_path(prefix, peer_ip);
            }
        }

        // Return only prefixes where best path actually changed
        affected
            .into_iter()
            .filter(|p| old_best.get(p).unwrap() != &self.get_best_path(p).map(Arc::clone))
            .collect()
    }
}

impl Default for LocRib {
    fn default() -> Self {
        Self::new()
    }
}

impl LocRib {
    pub fn new() -> Self {
        LocRib {
            routes: HashMap::new(),
        }
    }

    /// Add a locally originated route
    #[allow(clippy::too_many_arguments)]
    pub fn add_local_route(
        &mut self,
        prefix: IpNetwork,
        next_hop: Ipv4Addr,
        origin: Origin,
        as_path: Vec<AsPathSegment>,
        local_pref: Option<u32>,
        med: Option<u32>,
        atomic_aggregate: bool,
        communities: Vec<u32>,
    ) {
        // RFC 4271 Section 5.1.2: when originating a route (as_path is empty),
        // AS_PATH is empty when sent to iBGP peers, or [local_asn] when sent to eBGP peers.
        // We store it as provided and add local_asn during export based on peer type.
        // If as_path is not empty, it's used as-is (for testing or route injection).
        let path = Arc::new(Path {
            origin,
            as_path,
            next_hop,
            source: RouteSource::Local,
            local_pref: local_pref.or(Some(100)), // Default to 100 if not provided
            med,
            atomic_aggregate,
            communities,
            unknown_attrs: vec![],
        });

        info!("adding local route to Loc-RIB", "prefix" => format!("{:?}", prefix), "next_hop" => next_hop.to_string());
        self.add_route(prefix, path);
    }

    /// Remove a locally originated route
    /// Returns true if a route was actually removed.
    pub fn remove_local_route(&mut self, prefix: IpNetwork) -> bool {
        info!("removing local route from Loc-RIB", "prefix" => format!("{:?}", prefix));

        if let Some(route) = self.routes.get_mut(&prefix) {
            let original_len = route.paths.len();
            route.paths.retain(|p| p.source != RouteSource::Local);
            let removed = route.paths.len() != original_len;

            // Remove this specific route if no paths left
            if route.paths.is_empty() {
                self.routes.remove(&prefix);
            }

            removed
        } else {
            false
        }
    }

    /// Remove all routes from a peer. Returns prefixes where best path changed.
    pub fn remove_routes_from_peer(&mut self, peer_ip: IpAddr) -> Vec<IpNetwork> {
        // Snapshot old best for all prefixes that have paths from this peer
        let old_best: HashMap<IpNetwork, Option<Arc<Path>>> = self
            .routes
            .iter()
            .filter(|(_, route)| {
                route.paths.iter().any(|p| {
                    matches!(&p.source, RouteSource::Ebgp(ip) | RouteSource::Ibgp(ip) if *ip == peer_ip)
                })
            })
            .map(|(prefix, _)| (*prefix, self.get_best_path(prefix).map(Arc::clone)))
            .collect();

        // Remove paths from this peer
        for route in self.routes.values_mut() {
            route.paths.retain(|p| {
                !matches!(
                    &p.source,
                    RouteSource::Ebgp(ip) | RouteSource::Ibgp(ip) if *ip == peer_ip
                )
            });
        }
        self.routes.retain(|_, route| !route.paths.is_empty());

        // Return only prefixes where best changed
        old_best
            .into_iter()
            .filter(|(prefix, old)| old != &self.get_best_path(prefix).map(Arc::clone))
            .map(|(prefix, _)| prefix)
            .collect()
    }

    pub fn routes_len(&self) -> usize {
        self.routes.len()
    }

    /// Get the best path for a specific prefix, if any
    pub fn get_best_path(&self, prefix: &IpNetwork) -> Option<&Arc<Path>> {
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
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType};
    use crate::test_helpers::*;

    fn test_peer_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    }

    fn test_peer_ip2() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))
    }

    #[test]
    fn test_new_loc_rib() {
        let loc_rib = LocRib::new();
        assert_eq!(loc_rib.get_all_routes(), vec![]);
        assert_eq!(loc_rib.routes_len(), 0);
    }

    #[test]
    fn test_add_route() {
        let mut loc_rib = LocRib::new();
        let peer_ip = test_peer_ip();
        let prefix = create_test_prefix();
        let path = create_test_path(peer_ip);

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
        let peer_ip = test_peer_ip();

        let prefix1 = create_test_prefix();
        let prefix2 = IpNetwork::V4(crate::bgp::utils::Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 24,
        });

        let path1 = create_test_path(peer_ip);
        let path2 = create_test_path(peer_ip);

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
        let peer1 = test_peer_ip();
        let peer2 = test_peer_ip2();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer1);
        let path2 = create_test_path(peer2);

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
        let mut loc_rib = LocRib::new();
        let peer_ip = test_peer_ip();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer_ip);
        let path2 = create_test_path_with(peer_ip, |p| {
            p.as_path = vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 2,
                asn_list: vec![300, 400],
            }];
        });

        loc_rib.add_route(prefix, path1);
        loc_rib.add_route(prefix, Arc::clone(&path2));

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
        let peer1 = test_peer_ip();
        let peer2 = test_peer_ip2();
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
        let peer_ip = test_peer_ip();
        let prefix = create_test_prefix();
        let path = create_test_path(peer_ip);

        loc_rib.add_route(prefix, path);
        loc_rib.remove_routes_from_peer(peer_ip);

        assert_eq!(loc_rib.get_all_routes(), vec![]);
        assert_eq!(loc_rib.routes_len(), 0);
    }

    #[test]
    fn test_add_and_remove_local_route() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();
        let next_hop = Ipv4Addr::new(192, 0, 2, 1);

        loc_rib.add_local_route(
            prefix,
            next_hop,
            Origin::IGP,
            vec![],
            None,
            None,
            false,
            vec![],
        );
        assert_eq!(loc_rib.routes_len(), 1);
        assert!(loc_rib.has_prefix(&prefix));

        assert!(loc_rib.remove_local_route(prefix));
        assert_eq!(loc_rib.routes_len(), 0);
        assert!(!loc_rib.has_prefix(&prefix));

        // Removing again should return false
        assert!(!loc_rib.remove_local_route(prefix));
    }

    #[test]
    fn test_add_local_route_with_custom_local_pref() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();
        let next_hop = Ipv4Addr::new(192, 0, 2, 1);

        loc_rib.add_local_route(
            prefix,
            next_hop,
            Origin::IGP,
            vec![],
            Some(200), // Custom LOCAL_PREF
            None,
            false,
            vec![],
        );

        let path = loc_rib.get_best_path(&prefix).unwrap();
        assert_eq!(path.local_pref, Some(200));
    }
}
