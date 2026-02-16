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
use crate::log::{debug, info};
use crate::net::{IpNetwork, Ipv4Net, Ipv6Net};
use crate::rib::path_id::{BitmapPathIdAllocator, PathIdAllocator};
use crate::rib::{Path, PathAttrs, PrefixPath, Route, RouteSource};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;

/// Result of applying a peer update to the Loc-RIB.
pub struct RouteDelta {
    /// Prefixes where the best path changed (for non-ADD-PATH peers)
    pub best_changed: Vec<IpNetwork>,
    /// All prefixes with any path added or removed (for ADD-PATH peers)
    pub changed: Vec<IpNetwork>,
}

#[cfg(test)]
use std::net::Ipv4Addr;

/// Loc-RIB: Local routing table
///
/// Contains the best paths selected after applying import policies
/// and the BGP best path selection algorithm.
pub struct LocRib<A: PathIdAllocator = BitmapPathIdAllocator> {
    // Per-AFI/SAFI tables
    ipv4_unicast: HashMap<Ipv4Net, Route>, // AFI=1, SAFI=1
    ipv6_unicast: HashMap<Ipv6Net, Route>, // AFI=2, SAFI=1

    /// ADD-PATH local path ID allocator (RFC 7911)
    path_ids: A,
}

// Helper functions to avoid code duplication

/// Insert or update a path in a route's path list.
/// - If a matching path exists (same source, same remote_path_id) and attrs differ,
///   replace it while inheriting the existing local_path_id.
/// - If no match, allocate a fresh local_path_id and append.
fn upsert_path<K: Eq + Hash, A: PathIdAllocator>(
    table: &mut HashMap<K, Route>,
    key: K,
    prefix: IpNetwork,
    mut path: Arc<Path>,
    path_ids: &mut A,
) {
    let route = table.entry(key).or_insert_with(|| Route {
        prefix,
        paths: vec![],
    });

    match route.paths.iter_mut().find(|p| p.matches_remote(&path)) {
        Some(existing) => {
            if existing.attrs != path.attrs {
                Arc::make_mut(&mut path).local_path_id = existing.local_path_id;
                *existing = path;
            }
        }
        None => {
            Arc::make_mut(&mut path).local_path_id = Some(path_ids.alloc());
            route.paths.push(path);
        }
    }

    route.paths.sort_by(|a, b| b.best_path_cmp(a));
}

/// Remove paths matching a predicate and return their freed local_path_ids.
fn remove_paths<K: Eq + Hash, F: Fn(&Path) -> bool>(
    table: &mut HashMap<K, Route>,
    key: &K,
    should_remove: F,
) -> Vec<u32> {
    let Some(route) = table.get_mut(key) else {
        return Vec::new();
    };
    let freed_path_ids: Vec<u32> = route
        .paths
        .iter()
        .filter(|p| should_remove(p))
        .filter_map(|p| p.local_path_id)
        .collect();
    route.paths.retain(|p| !should_remove(p));

    if route.paths.is_empty() {
        table.remove(key);
    }

    freed_path_ids
}

fn is_path_from_peer(path: &Path, peer_ip: IpAddr) -> bool {
    path.attrs.source.peer_ip() == Some(peer_ip)
}

/// Remove all paths from a peer and return their local_path_ids for freeing.
fn remove_all_peer_paths<K: Eq + Hash>(table: &mut HashMap<K, Route>, peer_ip: IpAddr) -> Vec<u32> {
    let mut freed_path_ids = Vec::new();
    for route in table.values_mut() {
        freed_path_ids.extend(
            route
                .paths
                .iter()
                .filter(|p| is_path_from_peer(p, peer_ip))
                .filter_map(|p| p.local_path_id),
        );
        route.paths.retain(|p| !is_path_from_peer(p, peer_ip));
    }
    table.retain(|_, route| !route.paths.is_empty());
    freed_path_ids
}

fn mark_stale_in_table<K: Eq + Hash>(table: &mut HashMap<K, Route>, peer_ip: IpAddr) -> usize {
    let mut count = 0;
    for route in table.values_mut() {
        for path in &mut route.paths {
            if is_path_from_peer(path, peer_ip) {
                Arc::make_mut(path).stale = true;
                count += 1;
            }
        }
    }
    count
}

fn sweep_stale_in_table<K: Eq + Hash + Copy>(
    table: &mut HashMap<K, Route>,
    peer_ip: IpAddr,
) -> (Vec<IpNetwork>, Vec<u32>) {
    let mut stale_entries: Vec<(K, IpNetwork)> = Vec::new();
    for (key, route) in table.iter() {
        if route
            .paths
            .iter()
            .any(|p| is_path_from_peer(p, peer_ip) && p.stale)
        {
            stale_entries.push((*key, route.prefix));
        }
    }

    let mut freed_path_ids = Vec::new();
    let mut changed_prefixes = Vec::new();

    for (key, prefix) in stale_entries {
        let old_best = table
            .get(&key)
            .and_then(|r| r.paths.first())
            .map(Arc::clone);

        let freed = remove_paths(table, &key, |p| is_path_from_peer(p, peer_ip) && p.stale);
        freed_path_ids.extend(freed);

        let new_best = table.get(&key).and_then(|r| r.paths.first());

        let best_changed = match (old_best.as_ref(), new_best) {
            (Some(old), Some(new)) => !Arc::ptr_eq(old, new),
            (None, None) => false,
            _ => true,
        };
        if best_changed {
            changed_prefixes.push(prefix);
        }
    }
    (changed_prefixes, freed_path_ids)
}

impl<A: PathIdAllocator> LocRib<A> {
    fn upsert_path(&mut self, prefix: IpNetwork, path: Arc<Path>) {
        match prefix {
            IpNetwork::V4(v4_prefix) => upsert_path(
                &mut self.ipv4_unicast,
                v4_prefix,
                prefix,
                path,
                &mut self.path_ids,
            ),
            IpNetwork::V6(v6_prefix) => upsert_path(
                &mut self.ipv6_unicast,
                v6_prefix,
                prefix,
                path,
                &mut self.path_ids,
            ),
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
        self.path_ids
            .free_all(remove_all_peer_paths(&mut self.ipv4_unicast, peer_ip));
        self.path_ids
            .free_all(remove_all_peer_paths(&mut self.ipv6_unicast, peer_ip));
    }

    /// Remove paths from a specific peer for a given prefix.
    /// Returns true if a path was actually removed.
    fn remove_peer_path(&mut self, prefix: IpNetwork, peer_ip: IpAddr) -> bool {
        let freed_path_ids = match prefix {
            IpNetwork::V4(v4_prefix) => remove_paths(&mut self.ipv4_unicast, &v4_prefix, |p| {
                is_path_from_peer(p, peer_ip)
            }),
            IpNetwork::V6(v6_prefix) => remove_paths(&mut self.ipv6_unicast, &v6_prefix, |p| {
                is_path_from_peer(p, peer_ip)
            }),
        };
        let had_path = !freed_path_ids.is_empty();
        self.path_ids.free_all(freed_path_ids);
        had_path
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
    pub fn apply_peer_update<F>(
        &mut self,
        peer_ip: IpAddr,
        withdrawn: Vec<IpNetwork>,
        announced: Vec<PrefixPath>,
        import_policy: F,
    ) -> RouteDelta
    where
        F: Fn(&IpNetwork, &mut Path) -> bool,
    {
        // Collect affected prefixes and snapshot old best BEFORE mutations
        let mut affected_set: HashSet<IpNetwork> = HashSet::new();
        affected_set.extend(withdrawn.iter().copied());
        affected_set.extend(announced.iter().map(|(prefix, _)| *prefix));
        let affected: Vec<IpNetwork> = affected_set.into_iter().collect();
        let old_best: HashMap<IpNetwork, Arc<Path>> = affected
            .iter()
            .filter_map(|p| self.get_best_path(p).map(|best| (*p, Arc::clone(best))))
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
                self.upsert_path(prefix, Arc::new(path));
            } else {
                debug!(prefix = ?prefix, peer_ip = %peer_ip, "route rejected by import policy");
                self.remove_peer_path(prefix, peer_ip);
            }
        }

        let best_changed = affected
            .iter()
            .filter(|p| self.best_path_changed(p, old_best.get(p)))
            .cloned()
            .collect();
        RouteDelta {
            best_changed,
            changed: affected,
        }
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
            path_ids: BitmapPathIdAllocator::new(),
        }
    }
}

impl<A: PathIdAllocator> LocRib<A> {
    pub fn with_path_ids(path_ids: A) -> Self {
        LocRib {
            ipv4_unicast: HashMap::new(),
            ipv6_unicast: HashMap::new(),
            path_ids,
        }
    }

    /// Add a locally originated route
    pub fn add_local_route(&mut self, prefix: IpNetwork, path_attrs: PathAttrs) {
        let path = Arc::new(Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            attrs: PathAttrs {
                source: RouteSource::Local,
                local_pref: path_attrs.local_pref.or(Some(100)),
                ..path_attrs
            },
        });
        self.upsert_path(prefix, path);
    }

    /// Remove a locally originated route
    /// Returns true if a route was actually removed.
    pub fn remove_local_route(&mut self, prefix: IpNetwork) -> bool {
        info!(prefix = ?prefix, "removing local route from Loc-RIB");

        let freed_path_ids = match prefix {
            IpNetwork::V4(v4_prefix) => remove_paths(&mut self.ipv4_unicast, &v4_prefix, |p| {
                p.attrs.source == RouteSource::Local
            }),
            IpNetwork::V6(v6_prefix) => remove_paths(&mut self.ipv6_unicast, &v6_prefix, |p| {
                p.attrs.source == RouteSource::Local
            }),
        };
        let removed = !freed_path_ids.is_empty();
        self.path_ids.free_all(freed_path_ids);
        removed
    }

    /// Remove all routes from a peer. Returns a RouteDelta with best_changed
    /// (prefixes where best path changed) and changed (all affected prefixes).
    pub fn remove_routes_from_peer(&mut self, peer_ip: IpAddr) -> RouteDelta {
        let changed = self.get_prefixes_from_peer(peer_ip);

        let old_best: HashMap<IpNetwork, Arc<Path>> = changed
            .iter()
            .filter_map(|p| self.get_best_path(p).map(|best| (*p, Arc::clone(best))))
            .collect();

        self.clear_peer_paths(peer_ip);

        let best_changed = changed
            .iter()
            .filter(|p| self.best_path_changed(p, old_best.get(p)))
            .cloned()
            .collect();

        RouteDelta {
            best_changed,
            changed,
        }
    }

    pub fn routes_len(&self) -> usize {
        self.ipv4_unicast.len() + self.ipv6_unicast.len()
    }

    /// Returns true if the best path for a prefix differs from the old snapshot.
    fn best_path_changed(&self, prefix: &IpNetwork, old: Option<&Arc<Path>>) -> bool {
        match (old, self.get_best_path(prefix)) {
            (Some(old), Some(new)) => !Arc::ptr_eq(old, new),
            (None, None) => false,
            _ => true,
        }
    }

    fn get_route(&self, prefix: &IpNetwork) -> Option<&Route> {
        match prefix {
            IpNetwork::V4(v4) => self.ipv4_unicast.get(v4),
            IpNetwork::V6(v6) => self.ipv6_unicast.get(v6),
        }
    }

    /// Get the best path for a specific prefix, if any
    pub fn get_best_path(&self, prefix: &IpNetwork) -> Option<&Arc<Path>> {
        self.get_route(prefix).and_then(|r| r.paths.first())
    }

    /// Get all paths for a specific prefix (for ADD-PATH propagation)
    pub fn get_all_paths(&self, prefix: &IpNetwork) -> Vec<Arc<Path>> {
        self.get_route(prefix)
            .map(|r| r.paths.clone())
            .unwrap_or_default()
    }

    /// Check if a prefix exists in Loc-RIB
    pub fn has_prefix(&self, prefix: &IpNetwork) -> bool {
        self.get_route(prefix).is_some()
    }

    /// Get paths for an AFI. If `all_paths` is true, returns every path
    /// (ADD-PATH); otherwise returns only the best path per prefix.
    pub fn get_paths(&self, afi: Afi, all_paths: bool) -> Vec<PrefixPath> {
        let routes: Box<dyn Iterator<Item = &Route>> = match afi {
            Afi::Ipv4 => Box::new(self.ipv4_unicast.values()),
            Afi::Ipv6 => Box::new(self.ipv6_unicast.values()),
        };
        if all_paths {
            routes
                .flat_map(|route| {
                    route
                        .paths
                        .iter()
                        .map(move |path| (route.prefix, Arc::clone(path)))
                })
                .collect()
        } else {
            routes
                .filter_map(|route| {
                    route
                        .paths
                        .first()
                        .map(|path| (route.prefix, Arc::clone(path)))
                })
                .collect()
        }
    }

    /// Mark all paths from a peer for a specific AFI/SAFI as stale (RFC 4724 Graceful Restart).
    /// Sets `stale = true` on each matching path. New/replacement paths arrive with
    /// `stale = false`, so upsert_path naturally clears staleness.
    /// Returns the count of paths marked as stale.
    pub fn mark_peer_routes_stale(&mut self, peer_ip: IpAddr, afi_safi: AfiSafi) -> usize {
        let count = match (afi_safi.afi, afi_safi.safi) {
            (Afi::Ipv4, Safi::Unicast) => mark_stale_in_table(&mut self.ipv4_unicast, peer_ip),
            (Afi::Ipv6, Safi::Unicast) => mark_stale_in_table(&mut self.ipv6_unicast, peer_ip),
            _ => 0,
        };

        if count > 0 {
            info!(peer_ip = %peer_ip, afi_safi = %afi_safi, count = count,
                  "marked paths as stale for Graceful Restart");
        }
        count
    }

    /// Remove all stale paths from a peer for a specific AFI/SAFI.
    /// Removes paths where `is_path_from_peer && path.stale`.
    /// Returns prefixes where the best path changed.
    pub fn remove_peer_routes_stale(
        &mut self,
        peer_ip: IpAddr,
        afi_safi: AfiSafi,
    ) -> Vec<IpNetwork> {
        let (changed_prefixes, freed_path_ids) = match (afi_safi.afi, afi_safi.safi) {
            (Afi::Ipv4, Safi::Unicast) => sweep_stale_in_table(&mut self.ipv4_unicast, peer_ip),
            (Afi::Ipv6, Safi::Unicast) => sweep_stale_in_table(&mut self.ipv6_unicast, peer_ip),
            _ => (Vec::new(), Vec::new()),
        };

        if !freed_path_ids.is_empty() {
            info!(peer_ip = %peer_ip, afi_safi = %afi_safi, count = freed_path_ids.len(),
                  "removed stale paths after GR timer expiry/EOR");
            self.path_ids.free_all(freed_path_ids);
        }

        changed_prefixes
    }

    /// Get all AFI/SAFIs that have stale paths for a peer
    pub fn stale_afi_safis(&self, peer_ip: IpAddr) -> Vec<AfiSafi> {
        let has_stale = |route: &Route| {
            route
                .paths
                .iter()
                .any(|p| is_path_from_peer(p, peer_ip) && p.stale)
        };
        let mut result = Vec::new();
        if self.ipv4_unicast.values().any(has_stale) {
            result.push(AfiSafi {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            });
        }
        if self.ipv6_unicast.values().any(has_stale) {
            result.push(AfiSafi {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
            });
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, NextHopAddr, Origin};
    use crate::net::{Ipv4Net, Ipv6Net};
    use crate::test_helpers::*;
    use std::cmp::Ordering;
    use std::net::Ipv6Addr;

    fn test_peer_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    }

    fn test_bgp_id() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn test_peer_ip2() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))
    }

    fn test_bgp_id2() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 2)
    }

    #[test]
    fn test_new_loc_rib() {
        let loc_rib = LocRib::new();
        assert!(loc_rib.get_all_routes().is_empty());
        assert_eq!(loc_rib.routes_len(), 0);
    }

    #[test]
    fn test_upsert_path() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let peer_ip = test_peer_ip();
        let prefix = create_test_prefix();
        let path = create_test_path(peer_ip, test_bgp_id());

        loc_rib.upsert_path(prefix, path.clone());

        let routes = loc_rib.get_all_routes();
        assert_eq!(routes.len(), 1);
        let expected_path = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.local_path_id = Some(1);
        });
        assert_eq!(
            routes[0],
            Route {
                prefix,
                paths: vec![expected_path]
            }
        );
    }

    #[test]
    fn test_add_multiple_routes_different_prefixes() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let peer_ip = test_peer_ip();

        let prefix1 = create_test_prefix();
        let prefix2 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 24,
        });

        loc_rib.upsert_path(prefix1, create_test_path(peer_ip, test_bgp_id()));
        loc_rib.upsert_path(prefix2, create_test_path(peer_ip, test_bgp_id()));

        let mut routes = loc_rib.get_all_routes();
        routes.sort_by_key(|r| format!("{:?}", r.prefix));

        let expected_path1 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.local_path_id = Some(1);
        });
        let expected_path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.local_path_id = Some(2);
        });
        let mut expected = [
            Route {
                prefix: prefix1,
                paths: vec![expected_path1],
            },
            Route {
                prefix: prefix2,
                paths: vec![expected_path2],
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

        let path1 = create_test_path(peer1, test_bgp_id());
        let path2 = create_test_path(peer2, test_bgp_id2());

        loc_rib.upsert_path(prefix, path1.clone());
        loc_rib.upsert_path(prefix, path2.clone());

        let routes = loc_rib.get_all_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, prefix);

        let mut paths = routes[0].paths.clone();
        paths.sort_by_key(|p| format!("{:?}", p.source()));

        let mut expected_paths = [path1, path2];
        expected_paths.sort_by_key(|p| format!("{:?}", p.source()));

        assert_eq!(paths.len(), expected_paths.len());
        for (path, exp) in paths.iter().zip(expected_paths.iter()) {
            assert_eq!(path.attrs, exp.attrs);
        }
    }

    #[test]
    fn test_upsert_path_same_peer_updates_path() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let peer_ip = test_peer_ip();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer_ip, test_bgp_id());
        let path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.attrs.as_path = vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 2,
                asn_list: vec![300, 400],
            }];
        });

        loc_rib.upsert_path(prefix, path1);
        loc_rib.upsert_path(prefix, Arc::clone(&path2));

        let routes = loc_rib.get_all_routes();
        assert_eq!(routes.len(), 1);
        let expected_path = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.local_path_id = Some(1);
            p.attrs.as_path = path2.attrs.as_path.clone();
        });
        assert_eq!(
            routes[0],
            Route {
                prefix,
                paths: vec![expected_path]
            }
        );
    }

    #[test]
    fn test_remove_routes_from_peer() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let peer1 = test_peer_ip();
        let peer2 = test_peer_ip2();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer1, test_bgp_id());
        let path2 = create_test_path(peer2, test_bgp_id2());

        loc_rib.upsert_path(prefix, path1);
        loc_rib.upsert_path(prefix, path2.clone());

        loc_rib.remove_routes_from_peer(peer1);

        let routes = loc_rib.get_all_routes();
        assert_eq!(routes.len(), 1);
        let expected_path = create_test_path_with(peer2, test_bgp_id2(), |p| {
            p.local_path_id = Some(2);
        });
        assert_eq!(
            routes[0],
            Route {
                prefix,
                paths: vec![expected_path]
            }
        );
    }

    #[test]
    fn test_remove_routes_from_peer_removes_empty_routes() {
        let mut loc_rib = LocRib::new();
        let peer_ip = test_peer_ip();
        let prefix = create_test_prefix();
        let path = create_test_path(peer_ip, test_bgp_id());

        loc_rib.upsert_path(prefix, path);
        loc_rib.remove_routes_from_peer(peer_ip);

        assert!(loc_rib.get_all_routes().is_empty());
        assert_eq!(loc_rib.routes_len(), 0);
    }

    #[test]
    fn test_add_and_remove_local_route() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();
        let next_hop = Ipv4Addr::new(192, 0, 2, 1);

        loc_rib.add_local_route(
            prefix,
            PathAttrs {
                next_hop: NextHopAddr::Ipv4(next_hop),
                origin: Origin::IGP,
                as_path: vec![],
                source: RouteSource::Local,
                local_pref: None,
                med: None,
                atomic_aggregate: false,
                aggregator: None,
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
            },
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
            PathAttrs {
                next_hop: NextHopAddr::Ipv4(next_hop),
                origin: Origin::IGP,
                as_path: vec![],
                source: RouteSource::Local,
                local_pref: Some(200),
                med: None,
                atomic_aggregate: false,
                aggregator: None,
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
            },
        );

        let path = loc_rib.get_best_path(&prefix).unwrap();
        assert_eq!(path.local_pref(), Some(200));
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

        loc_rib.upsert_path(prefix_v4, create_test_path(peer_ip, test_bgp_id()));
        loc_rib.upsert_path(prefix_v6, create_test_path(peer_ip, test_bgp_id()));

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

        loc_rib.upsert_path(prefix_v4, create_test_path(peer_ip, test_bgp_id()));
        loc_rib.upsert_path(prefix_v6, create_test_path(peer_ip, test_bgp_id()));

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

        loc_rib.upsert_path(prefix_v4, create_test_path(peer_ip, test_bgp_id()));
        loc_rib.upsert_path(prefix_v6, create_test_path(peer_ip, test_bgp_id()));

        let ipv4_routes = loc_rib.get_paths(Afi::Ipv4, false);
        assert_eq!(ipv4_routes.len(), 1);
        assert_eq!(ipv4_routes[0].0, prefix_v4);

        let ipv6_routes = loc_rib.get_paths(Afi::Ipv6, false);
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

        loc_rib.upsert_path(prefix_v4, create_test_path(peer1, test_bgp_id()));
        loc_rib.upsert_path(prefix_v6, create_test_path(peer2, test_bgp_id2()));

        let delta = loc_rib.remove_routes_from_peer(peer1);

        assert_eq!(delta.best_changed.len(), 1);
        assert_eq!(delta.best_changed[0], prefix_v4);
        assert_eq!(delta.changed.len(), 1);
        assert_eq!(delta.changed[0], prefix_v4);
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

    // --- Path ID allocation tests ---

    #[test]
    fn test_path_id_allocated_on_add() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();
        let path = create_test_path(test_peer_ip(), test_bgp_id());

        loc_rib.upsert_path(prefix, path);

        let stored = loc_rib.get_best_path(&prefix).unwrap();
        assert!(
            stored.local_path_id.is_some(),
            "loc-rib path should have allocated ID"
        );
    }

    #[test]
    fn test_path_id_reused_on_replace() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();
        let peer_ip = test_peer_ip();

        // Add initial path
        loc_rib.upsert_path(prefix, create_test_path(peer_ip, test_bgp_id()));
        let id1 = loc_rib.get_best_path(&prefix).unwrap().local_path_id;

        let before = Arc::clone(loc_rib.get_best_path(&prefix).unwrap());

        // Replace with updated path (same source, same remote_path_id=None)
        let path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.attrs.med = Some(50);
        });
        loc_rib.upsert_path(prefix, path2);
        let after = loc_rib.get_best_path(&prefix).unwrap();

        assert_eq!(
            id1, after.local_path_id,
            "replaced path should inherit local_path_id"
        );
        assert!(
            !Arc::ptr_eq(&before, after),
            "path should be replaced, not reused"
        );
    }

    #[test]
    fn test_identical_path_is_noop() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();
        let path = create_test_path(test_peer_ip(), test_bgp_id());

        loc_rib.upsert_path(prefix, Arc::clone(&path));
        let stored = loc_rib.get_best_path(&prefix).unwrap();
        let ptr_before = Arc::as_ptr(stored);

        // Re-add identical path — should not replace the Arc
        loc_rib.upsert_path(prefix, Arc::clone(&path));
        let stored = loc_rib.get_best_path(&prefix).unwrap();
        assert!(
            std::ptr::eq(ptr_before, Arc::as_ptr(stored)),
            "identical path should keep existing Arc"
        );
    }

    #[test]
    fn test_path_id_different_sources_get_unique_ids() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();

        loc_rib.upsert_path(prefix, create_test_path(test_peer_ip(), test_bgp_id()));
        loc_rib.upsert_path(prefix, create_test_path(test_peer_ip2(), test_bgp_id2()));

        let routes = loc_rib.get_all_routes();
        let ids: Vec<Option<u32>> = routes[0].paths.iter().map(|p| p.local_path_id).collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1], "different sources should get different IDs");
    }

    #[test]
    fn test_path_id_different_remote_path_id_coexist() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();
        let peer_ip = test_peer_ip();

        // Add two paths from same peer with different remote path IDs
        let path1 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
        });
        loc_rib.upsert_path(prefix, path1);

        let path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.remote_path_id = Some(2);
        });
        loc_rib.upsert_path(prefix, path2);

        let routes = loc_rib.get_all_routes();
        assert_eq!(
            routes[0].paths.len(),
            2,
            "different remote_path_ids should coexist"
        );

        let ids: Vec<Option<u32>> = routes[0].paths.iter().map(|p| p.local_path_id).collect();
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn test_path_id_freed_on_peer_removal() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let prefix = create_test_prefix();
        let peer_ip = test_peer_ip();

        loc_rib.upsert_path(prefix, create_test_path(peer_ip, test_bgp_id()));
        loc_rib.remove_routes_from_peer(peer_ip);

        assert_eq!(loc_rib.path_ids.freed, vec![1]);
    }

    #[test]
    fn test_path_id_freed_on_local_route_removal() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let prefix = create_test_prefix();

        loc_rib.add_local_route(
            prefix,
            PathAttrs {
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                origin: Origin::IGP,
                as_path: vec![],
                source: RouteSource::Local,
                local_pref: None,
                med: None,
                atomic_aggregate: false,
                aggregator: None,
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
            },
        );
        loc_rib.remove_local_route(prefix);

        assert_eq!(loc_rib.path_ids.freed, vec![1]);
    }

    #[test]
    fn test_path_id_freed_on_remove_all_peer_paths() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let peer_ip = test_peer_ip();

        loc_rib.upsert_path(
            create_test_prefix_n(0),
            create_test_path(peer_ip, test_bgp_id()),
        );
        loc_rib.upsert_path(
            create_test_prefix_n(1),
            create_test_path(peer_ip, test_bgp_id()),
        );
        loc_rib.remove_routes_from_peer(peer_ip);

        let mut freed = loc_rib.path_ids.freed.clone();
        freed.sort();
        assert_eq!(freed, vec![1, 2]);
    }

    #[test]
    fn test_get_all_paths() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();

        // Empty prefix -> empty vec
        assert!(loc_rib.get_all_paths(&prefix).is_empty());

        // One path
        loc_rib.upsert_path(prefix, create_test_path(test_peer_ip(), test_bgp_id()));
        assert_eq!(loc_rib.get_all_paths(&prefix).len(), 1);

        // Two paths from different peers
        loc_rib.upsert_path(prefix, create_test_path(test_peer_ip2(), test_bgp_id2()));
        let paths = loc_rib.get_all_paths(&prefix);
        assert_eq!(paths.len(), 2);
        // Paths should be sorted (best first)
        assert_eq!(paths[0].best_path_cmp(&paths[1]), Ordering::Greater);
    }

    #[test]
    fn test_apply_peer_update_returns_changed() {
        let mut loc_rib = LocRib::new();
        let peer1 = test_peer_ip();
        let peer2 = test_peer_ip2();
        let prefix = create_test_prefix();

        // Add a route from peer1 (the best)
        loc_rib.upsert_path(prefix, create_test_path(peer1, test_bgp_id()));

        // Now announce from peer2 with a worse path (longer AS path)
        let worse_path = create_test_path_with(peer2, test_bgp_id2(), |p| {
            p.attrs.as_path = vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 3,
                asn_list: vec![100, 200, 300],
            }];
        });

        let delta =
            loc_rib.apply_peer_update(peer2, vec![], vec![(prefix, worse_path)], |_, _| true);

        // Best didn't change (peer1's path is still best)
        assert!(
            delta.best_changed.is_empty(),
            "best should not have changed"
        );
        // But the prefix IS affected (new path added)
        assert_eq!(delta.changed, vec![prefix], "prefix should be in changed");
        // Both paths should exist
        assert_eq!(loc_rib.get_all_paths(&prefix).len(), 2);
    }

    #[test]
    fn test_stale_cleared_on_replacement() {
        let mut loc_rib = LocRib::new();
        let peer_ip = test_peer_ip();
        let prefix = create_test_prefix();
        let ipv4_uni = AfiSafi {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        };

        // Add a route, then mark it stale (simulating GR)
        loc_rib.upsert_path(prefix, create_test_path(peer_ip, test_bgp_id()));
        loc_rib.mark_peer_routes_stale(peer_ip, ipv4_uni);
        assert!(!loc_rib.stale_afi_safis(peer_ip).is_empty());

        // Verify the path is marked stale
        assert!(loc_rib.get_best_path(&prefix).unwrap().stale);

        // Peer reconnects and re-sends the same route (new path has stale=false)
        let refreshed_path = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.attrs.med = Some(50);
        });
        loc_rib.apply_peer_update(peer_ip, vec![], vec![(prefix, refreshed_path)], |_, _| true);

        // Replacement path should not be stale
        assert!(!loc_rib.get_best_path(&prefix).unwrap().stale);

        // EOR sweep should NOT remove the refreshed path
        let changed = loc_rib.remove_peer_routes_stale(peer_ip, ipv4_uni);
        assert!(changed.is_empty(), "no paths should be removed");
        assert!(
            loc_rib.get_best_path(&prefix).is_some(),
            "refreshed path should survive EOR sweep"
        );
    }

    #[test]
    fn test_stale_addpath_partial_resend() {
        // Two paths from same peer via ADD-PATH. Peer restarts, only re-sends one.
        // Sweep should remove the stale path but keep the refreshed one.
        let mut loc_rib = LocRib::new();
        let peer_ip = test_peer_ip();
        let prefix = create_test_prefix();
        let ipv4_uni = AfiSafi {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        };

        // Two paths from same peer with different remote_path_ids
        let path1 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
        });
        let path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.remote_path_id = Some(2);
            p.attrs.med = Some(50);
        });
        loc_rib.upsert_path(prefix, path1);
        loc_rib.upsert_path(prefix, path2);
        assert_eq!(loc_rib.get_all_paths(&prefix).len(), 2);

        // Peer disconnects with GR -> mark both stale
        let stale_count = loc_rib.mark_peer_routes_stale(peer_ip, ipv4_uni);
        assert_eq!(stale_count, 2);

        // Peer reconnects and only re-sends path_id=1
        let refreshed = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
            p.attrs.med = Some(99);
        });
        loc_rib.apply_peer_update(peer_ip, vec![], vec![(prefix, refreshed)], |_, _| true);

        // path_id=1 should be fresh, path_id=2 should still be stale
        let paths = loc_rib.get_all_paths(&prefix);
        assert_eq!(paths.len(), 2);
        let fresh_count = paths.iter().filter(|p| !p.stale).count();
        let stale_count = paths.iter().filter(|p| p.stale).count();
        assert_eq!(fresh_count, 1);
        assert_eq!(stale_count, 1);

        // EOR sweep: removes stale path_id=2, keeps path_id=1
        let changed = loc_rib.remove_peer_routes_stale(peer_ip, ipv4_uni);

        let remaining = loc_rib.get_all_paths(&prefix);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].remote_path_id, Some(1));
        assert!(!remaining[0].stale);
        // Best path changed (stale best was removed)
        assert!(!changed.is_empty());
    }
}
