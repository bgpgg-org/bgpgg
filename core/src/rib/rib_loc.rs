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

use crate::bgp::msg_update::{AsPathSegment, NextHopAddr, Origin};
use crate::log::{debug, info};
use crate::net::{IpNetwork, Ipv4Net, Ipv6Net};
use crate::rib::{Path, Route, RouteSource};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;

#[cfg(test)]
use std::net::Ipv4Addr;

/// Loc-RIB: Local routing table
///
/// Contains the best paths selected after applying import policies
/// and the BGP best path selection algorithm.
pub struct LocRib {
    // Per-AFI/SAFI tables
    ipv4_unicast: HashMap<Ipv4Net, Route>, // AFI=1, SAFI=1
    ipv6_unicast: HashMap<Ipv6Net, Route>, // AFI=2, SAFI=1

    /// Track stale routes during Graceful Restart (RFC 4724)
    /// Key: (peer_ip, afi_safi), Value: set of stale prefixes
    /// Routes are marked stale when peer disconnects with GR enabled
    /// Routes are unmarked when refreshed during GR, or removed after EOR/timer expiry
    stale_routes: HashMap<(IpAddr, crate::bgp::multiprotocol::AfiSafi), HashSet<IpNetwork>>,
}

// Helper functions to avoid code duplication

fn add_route<K: Eq + Hash>(
    table: &mut HashMap<K, Route>,
    key: K,
    prefix: IpNetwork,
    path: Arc<Path>,
) {
    if let Some(route) = table.get_mut(&key) {
        if let Some(existing) = route.paths.iter_mut().find(|p| p.source == path.source) {
            *existing = path;
        } else {
            route.paths.push(path);
        }
        route.paths.sort_by(|a, b| b.cmp(a));
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

fn remove_peer_paths<K: Eq + Hash>(
    table: &mut HashMap<K, Route>,
    key: &K,
    peer_ip: IpAddr,
) -> bool {
    if let Some(route) = table.get_mut(key) {
        let had_path = route.paths.iter().any(|p| {
            matches!(&p.source, RouteSource::Ebgp(ip) | RouteSource::Ibgp(ip) if *ip == peer_ip)
        });
        route.paths.retain(|p| {
            !matches!(&p.source, RouteSource::Ebgp(ip) | RouteSource::Ibgp(ip) if *ip == peer_ip)
        });
        if route.paths.is_empty() {
            table.remove(key);
        }
        had_path
    } else {
        false
    }
}

fn remove_local_paths<K: Eq + Hash>(table: &mut HashMap<K, Route>, key: &K) -> bool {
    if let Some(route) = table.get_mut(key) {
        let original_len = route.paths.len();
        route.paths.retain(|p| p.source != RouteSource::Local);
        let removed = route.paths.len() != original_len;
        if route.paths.is_empty() {
            table.remove(key);
        }
        removed
    } else {
        false
    }
}

fn is_path_from_peer(path: &Path, peer_ip: IpAddr) -> bool {
    matches!(&path.source, RouteSource::Ebgp(ip) | RouteSource::Ibgp(ip) if *ip == peer_ip)
}

fn remove_all_peer_paths<K: Eq + Hash>(table: &mut HashMap<K, Route>, peer_ip: IpAddr) {
    for route in table.values_mut() {
        route.paths.retain(|p| !is_path_from_peer(p, peer_ip));
    }
    table.retain(|_, route| !route.paths.is_empty());
}

impl LocRib {
    fn add_route(&mut self, prefix: IpNetwork, path: Arc<Path>) {
        match prefix {
            IpNetwork::V4(v4_prefix) => add_route(&mut self.ipv4_unicast, v4_prefix, prefix, path),
            IpNetwork::V6(v6_prefix) => add_route(&mut self.ipv6_unicast, v6_prefix, prefix, path),
        }
    }

    fn get_prefixes_from_peer(&self, peer_ip: IpAddr) -> Vec<IpNetwork> {
        let mut prefixes = Vec::new();

        for (prefix, route) in &self.ipv4_unicast {
            if route.paths.iter().any(|p| is_path_from_peer(p, peer_ip)) {
                prefixes.push(IpNetwork::V4(*prefix));
            }
        }

        for (prefix, route) in &self.ipv6_unicast {
            if route.paths.iter().any(|p| is_path_from_peer(p, peer_ip)) {
                prefixes.push(IpNetwork::V6(*prefix));
            }
        }

        prefixes
    }

    fn clear_peer_paths(&mut self, peer_ip: IpAddr) {
        remove_all_peer_paths(&mut self.ipv4_unicast, peer_ip);
        remove_all_peer_paths(&mut self.ipv6_unicast, peer_ip);
    }

    /// Remove paths from a specific peer for a given prefix.
    /// Returns true if a path was actually removed.
    fn remove_peer_path(&mut self, prefix: IpNetwork, peer_ip: IpAddr) -> bool {
        match prefix {
            IpNetwork::V4(v4_prefix) => {
                remove_peer_paths(&mut self.ipv4_unicast, &v4_prefix, peer_ip)
            }
            IpNetwork::V6(v6_prefix) => {
                remove_peer_paths(&mut self.ipv6_unicast, &v6_prefix, peer_ip)
            }
        }
    }

    pub fn get_all_routes(&self) -> Vec<Route> {
        let mut routes = Vec::new();
        routes.extend(self.ipv4_unicast.values().cloned());
        routes.extend(self.ipv6_unicast.values().cloned());
        routes
    }

    /// Get iterator over routes for streaming
    pub fn iter_routes(&self) -> impl Iterator<Item = &Route> {
        self.ipv4_unicast.values().chain(self.ipv6_unicast.values())
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
            info!(prefix = ?prefix, peer_ip = %peer_ip, "withdrawing route from Loc-RIB");
            self.remove_peer_path(prefix, peer_ip);
        }

        // Process announcements - apply import policy and add to Loc-RIB
        for (prefix, path_arc) in announced {
            // Clone inner Path for policy mutation
            let mut path = (*path_arc).clone();
            if import_policy(&prefix, &mut path) {
                info!(prefix = ?prefix, peer_ip = %peer_ip, "adding route to Loc-RIB");
                self.add_route(prefix, Arc::new(path));
            } else {
                debug!(prefix = ?prefix, peer_ip = %peer_ip, "route rejected by import policy");
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
            ipv4_unicast: HashMap::new(),
            ipv6_unicast: HashMap::new(),
            stale_routes: HashMap::new(),
        }
    }

    /// Add a locally originated route
    #[allow(clippy::too_many_arguments)]
    pub fn add_local_route(
        &mut self,
        prefix: IpNetwork,
        next_hop: NextHopAddr,
        origin: Origin,
        as_path: Vec<AsPathSegment>,
        local_pref: Option<u32>,
        med: Option<u32>,
        atomic_aggregate: bool,
        communities: Vec<u32>,
        extended_communities: Vec<u64>,
        large_communities: Vec<crate::bgp::msg_update_types::LargeCommunity>,
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
            aggregator: None,
            communities,
            extended_communities,
            large_communities,
            unknown_attrs: vec![],
        });

        self.add_route(prefix, path);
    }

    /// Remove a locally originated route
    /// Returns true if a route was actually removed.
    pub fn remove_local_route(&mut self, prefix: IpNetwork) -> bool {
        info!(prefix = ?prefix, "removing local route from Loc-RIB");

        match prefix {
            IpNetwork::V4(v4_prefix) => remove_local_paths(&mut self.ipv4_unicast, &v4_prefix),
            IpNetwork::V6(v6_prefix) => remove_local_paths(&mut self.ipv6_unicast, &v6_prefix),
        }
    }

    /// Remove all routes from a peer. Returns prefixes where best path changed.
    pub fn remove_routes_from_peer(&mut self, peer_ip: IpAddr) -> Vec<IpNetwork> {
        let prefixes = self.get_prefixes_from_peer(peer_ip);

        let old_best: HashMap<IpNetwork, Option<Arc<Path>>> = prefixes
            .iter()
            .map(|p| (*p, self.get_best_path(p).map(Arc::clone)))
            .collect();

        self.clear_peer_paths(peer_ip);

        old_best
            .into_iter()
            .filter_map(|(prefix, old)| {
                if old.as_ref() != self.get_best_path(&prefix) {
                    Some(prefix)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn routes_len(&self) -> usize {
        self.ipv4_unicast.len() + self.ipv6_unicast.len()
    }

    /// Get the best path for a specific prefix, if any
    pub fn get_best_path(&self, prefix: &IpNetwork) -> Option<&Arc<Path>> {
        match prefix {
            IpNetwork::V4(v4_prefix) => self
                .ipv4_unicast
                .get(v4_prefix)
                .and_then(|route| route.paths.first()),
            IpNetwork::V6(v6_prefix) => self
                .ipv6_unicast
                .get(v6_prefix)
                .and_then(|route| route.paths.first()),
        }
    }

    /// Check if a prefix exists in Loc-RIB
    pub fn has_prefix(&self, prefix: &IpNetwork) -> bool {
        match prefix {
            IpNetwork::V4(v4_prefix) => self.ipv4_unicast.contains_key(v4_prefix),
            IpNetwork::V6(v6_prefix) => self.ipv6_unicast.contains_key(v6_prefix),
        }
    }

    /// Get all routes from IPv4 Unicast table as iterator (zero-copy)
    pub fn iter_ipv4_unicast_routes(&self) -> impl Iterator<Item = (IpNetwork, Arc<Path>)> + '_ {
        self.ipv4_unicast.values().filter_map(|route| {
            route
                .paths
                .first()
                .map(|path| (route.prefix, Arc::clone(path)))
        })
    }

    /// Get all routes from IPv6 Unicast table as iterator (zero-copy)
    pub fn iter_ipv6_unicast_routes(&self) -> impl Iterator<Item = (IpNetwork, Arc<Path>)> + '_ {
        self.ipv6_unicast.values().filter_map(|route| {
            route
                .paths
                .first()
                .map(|path| (route.prefix, Arc::clone(path)))
        })
    }

    /// Mark all routes from a peer for a specific AFI/SAFI as stale (RFC 4724 Graceful Restart)
    /// Returns the count of routes marked as stale
    pub fn mark_peer_routes_stale(
        &mut self,
        peer_ip: IpAddr,
        afi_safi: crate::bgp::multiprotocol::AfiSafi,
    ) -> usize {
        use crate::bgp::multiprotocol::{Afi, Safi};

        let prefixes: Vec<IpNetwork> = self
            .get_prefixes_from_peer(peer_ip)
            .into_iter()
            .filter(|prefix| {
                matches!(
                    (afi_safi.afi, afi_safi.safi, prefix),
                    (Afi::Ipv4, Safi::Unicast, IpNetwork::V4(_))
                        | (Afi::Ipv6, Safi::Unicast, IpNetwork::V6(_))
                )
            })
            .collect();

        let count = prefixes.len();
        if count > 0 {
            self.stale_routes
                .entry((peer_ip, afi_safi))
                .or_default()
                .extend(prefixes);
            info!(peer_ip = %peer_ip, afi_safi = %afi_safi, count = count,
                  "marked routes as stale for Graceful Restart");
        }
        count
    }

    /// Check if a specific route is marked as stale
    pub fn is_route_stale(
        &self,
        peer_ip: IpAddr,
        afi_safi: crate::bgp::multiprotocol::AfiSafi,
        prefix: IpNetwork,
    ) -> bool {
        self.stale_routes
            .get(&(peer_ip, afi_safi))
            .map(|set| set.contains(&prefix))
            .unwrap_or(false)
    }

    /// Mark a route as refreshed (remove from stale set) during Graceful Restart
    pub fn mark_peer_routes_refreshed(&mut self, peer_ip: IpAddr, prefix: IpNetwork) {
        let afi_safi = prefix.afi_safi();
        if let Some(stale_set) = self.stale_routes.get_mut(&(peer_ip, afi_safi)) {
            if stale_set.remove(&prefix) {
                debug!(peer_ip = %peer_ip, prefix = ?prefix, "route refreshed during GR");
            }
        }
    }

    /// Remove all stale routes from a peer for a specific AFI/SAFI
    /// Returns prefixes where the best path changed
    pub fn remove_peer_routes_stale(
        &mut self,
        peer_ip: IpAddr,
        afi_safi: crate::bgp::multiprotocol::AfiSafi,
    ) -> Vec<IpNetwork> {
        let stale_prefixes = self
            .stale_routes
            .remove(&(peer_ip, afi_safi))
            .unwrap_or_default();

        if stale_prefixes.is_empty() {
            return Vec::new();
        }

        info!(peer_ip = %peer_ip, afi_safi = %afi_safi, count = stale_prefixes.len(),
              "removing stale routes after GR timer expiry/EOR");

        let mut changed_prefixes = Vec::new();

        for prefix in stale_prefixes {
            // Snapshot old best path
            let old_best = self.get_best_path(&prefix).map(Arc::clone);

            // Remove path from peer
            let removed = self.remove_peer_path(prefix, peer_ip);

            if removed {
                // Check if best path changed
                let new_best = self.get_best_path(&prefix);
                if old_best.as_ref() != new_best {
                    changed_prefixes.push(prefix);
                }
            }
        }

        changed_prefixes
    }

    /// Check if a peer has any stale routes (is in GR restart mode)
    pub fn has_stale_routes_for_peer(&self, peer_ip: IpAddr) -> bool {
        self.stale_routes.keys().any(|(ip, _)| *ip == peer_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType};
    use crate::net::{Ipv4Net, Ipv6Net};
    use crate::test_helpers::*;
    use std::net::Ipv6Addr;

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
        let prefix2 = IpNetwork::V4(Ipv4Net {
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
            NextHopAddr::Ipv4(next_hop),
            Origin::IGP,
            vec![],
            None,
            None,
            false,
            vec![],
            vec![],
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
            NextHopAddr::Ipv4(next_hop),
            Origin::IGP,
            vec![],
            Some(200), // Custom LOCAL_PREF
            None,
            false,
            vec![],
            vec![],
            vec![],
        );

        let path = loc_rib.get_best_path(&prefix).unwrap();
        assert_eq!(path.local_pref, Some(200));
    }

    #[test]
    fn test_mixed_ipv4_ipv6_routes() {
        let mut loc_rib = LocRib::new();
        let peer_ip = test_peer_ip();

        let prefix_v4 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        });
        let prefix_v6 = IpNetwork::V6(Ipv6Net {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            prefix_length: 32,
        });

        loc_rib.add_route(prefix_v4, create_test_path(peer_ip));
        loc_rib.add_route(prefix_v6, create_test_path(peer_ip));

        assert_eq!(loc_rib.routes_len(), 2);
        assert!(loc_rib.has_prefix(&prefix_v4));
        assert!(loc_rib.has_prefix(&prefix_v6));

        let routes = loc_rib.get_all_routes();
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn test_iter_routes_mixed_families() {
        let mut loc_rib = LocRib::new();
        let peer_ip = test_peer_ip();

        let prefix_v4 = create_test_prefix(); // IPv4
        let prefix_v6 = IpNetwork::V6(Ipv6Net {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            prefix_length: 32,
        });

        loc_rib.add_route(prefix_v4, create_test_path(peer_ip));
        loc_rib.add_route(prefix_v6, create_test_path(peer_ip));

        let count = loc_rib.iter_routes().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_iter_by_afi() {
        let mut loc_rib = LocRib::new();
        let peer_ip = test_peer_ip();

        let prefix_v4 = create_test_prefix();
        let prefix_v6 = IpNetwork::V6(Ipv6Net {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            prefix_length: 32,
        });

        loc_rib.add_route(prefix_v4, create_test_path(peer_ip));
        loc_rib.add_route(prefix_v6, create_test_path(peer_ip));

        let ipv4_routes: Vec<_> = loc_rib.iter_ipv4_unicast_routes().collect();
        assert_eq!(ipv4_routes.len(), 1);
        assert_eq!(ipv4_routes[0].0, prefix_v4);

        let ipv6_routes: Vec<_> = loc_rib.iter_ipv6_unicast_routes().collect();
        assert_eq!(ipv6_routes.len(), 1);
        assert_eq!(ipv6_routes[0].0, prefix_v6);
    }

    #[test]
    fn test_remove_routes_from_peer_mixed() {
        let mut loc_rib = LocRib::new();
        let peer1 = test_peer_ip();
        let peer2 = test_peer_ip2();

        let prefix_v4 = create_test_prefix();
        let prefix_v6 = IpNetwork::V6(Ipv6Net {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            prefix_length: 32,
        });

        loc_rib.add_route(prefix_v4, create_test_path(peer1));
        loc_rib.add_route(prefix_v6, create_test_path(peer2));

        let changed = loc_rib.remove_routes_from_peer(peer1);

        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0], prefix_v4);
        assert!(!loc_rib.has_prefix(&prefix_v4));
        assert!(loc_rib.has_prefix(&prefix_v6));
    }

    #[test]
    fn test_empty_tables() {
        let loc_rib = LocRib::new();
        assert_eq!(loc_rib.routes_len(), 0);
        assert_eq!(loc_rib.get_all_routes().len(), 0);
        assert_eq!(loc_rib.iter_routes().count(), 0);
    }
}
