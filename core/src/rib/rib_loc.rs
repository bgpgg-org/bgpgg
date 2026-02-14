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
use crate::rib::path_id::PathIdAllocator;
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
    /// Key: (peer_ip, afi_safi), Value: set of stale local_path_ids
    /// Routes are marked stale when peer disconnects with GR enabled.
    /// Per-path tracking: new/replaced paths get fresh IDs and are never stale.
    /// At EOR sweep, stale IDs that were already replaced are freed no-ops.
    stale_routes: HashMap<(IpAddr, crate::bgp::multiprotocol::AfiSafi), HashSet<u32>>,

    /// ADD-PATH local path ID allocator (RFC 7911)
    path_ids: PathIdAllocator,
}

// Helper functions to avoid code duplication

fn add_route<K: Eq + Hash>(
    table: &mut HashMap<K, Route>,
    key: K,
    prefix: IpNetwork,
    mut path: Arc<Path>,
    path_ids: &mut PathIdAllocator,
) {
    if let Some(route) = table.get_mut(&key) {
        if let Some(existing) = route
            .paths
            .iter_mut()
            .find(|p| p.source == path.source && p.remote_path_id == path.remote_path_id)
        {
            // Replacement: inherit existing path's local_path_id
            Arc::make_mut(&mut path).local_path_id = existing.local_path_id;
            *existing = path;
        } else {
            // New path: allocate fresh ID
            Arc::make_mut(&mut path).local_path_id = path_ids.alloc();
            route.paths.push(path);
        }
        route.paths.sort_by(|a, b| b.cmp(a));
    } else {
        // First path for prefix: allocate fresh ID
        Arc::make_mut(&mut path).local_path_id = path_ids.alloc();
        table.insert(
            key,
            Route {
                prefix,
                paths: vec![path],
            },
        );
    }
}

/// Remove paths from a peer and return their local_path_ids for freeing.
fn remove_peer_paths<K: Eq + Hash>(
    table: &mut HashMap<K, Route>,
    key: &K,
    peer_ip: IpAddr,
) -> Vec<u32> {
    if let Some(route) = table.get_mut(key) {
        let freed_ids: Vec<u32> = route
            .paths
            .iter()
            .filter(|p| p.source.peer_ip() == Some(peer_ip))
            .map(|p| p.local_path_id)
            .collect();
        route.paths.retain(|p| p.source.peer_ip() != Some(peer_ip));
        if route.paths.is_empty() {
            table.remove(key);
        }
        freed_ids
    } else {
        Vec::new()
    }
}

/// Remove local paths and return their local_path_ids for freeing.
fn remove_local_paths<K: Eq + Hash>(table: &mut HashMap<K, Route>, key: &K) -> Vec<u32> {
    if let Some(route) = table.get_mut(key) {
        let freed_ids: Vec<u32> = route
            .paths
            .iter()
            .filter(|p| p.source == RouteSource::Local)
            .map(|p| p.local_path_id)
            .collect();
        route.paths.retain(|p| p.source != RouteSource::Local);
        if route.paths.is_empty() {
            table.remove(key);
        }
        freed_ids
    } else {
        Vec::new()
    }
}

fn is_path_from_peer(path: &Path, peer_ip: IpAddr) -> bool {
    path.source.peer_ip() == Some(peer_ip)
}

/// Collect local_path_ids for all paths from a peer in a table.
fn collect_peer_path_ids<K: Eq + Hash>(table: &HashMap<K, Route>, peer_ip: IpAddr) -> Vec<u32> {
    table
        .values()
        .flat_map(|route| {
            route
                .paths
                .iter()
                .filter(move |p| is_path_from_peer(p, peer_ip))
                .map(|p| p.local_path_id)
        })
        .collect()
}

/// Remove paths matching a set of local_path_ids from a table.
/// Returns (freed_ids, changed_prefixes) where changed_prefixes are those whose best path changed.
fn remove_paths_by_ids<K: Eq + Hash + Copy>(
    table: &mut HashMap<K, Route>,
    stale_ids: &HashSet<u32>,
) -> (Vec<u32>, Vec<IpNetwork>) {
    let mut freed_ids = Vec::new();
    let mut changed = Vec::new();

    for route in table.values_mut() {
        let old_best = route.paths.first().map(Arc::clone);
        let before = route.paths.len();
        let removed: Vec<u32> = route
            .paths
            .iter()
            .filter(|p| stale_ids.contains(&p.local_path_id))
            .map(|p| p.local_path_id)
            .collect();
        if removed.is_empty() {
            continue;
        }
        route
            .paths
            .retain(|p| !stale_ids.contains(&p.local_path_id));
        freed_ids.extend(removed);
        if before != route.paths.len() {
            let new_best = route.paths.first();
            if old_best.as_ref() != new_best {
                changed.push(route.prefix);
            }
        }
    }
    table.retain(|_, route| !route.paths.is_empty());

    (freed_ids, changed)
}

/// Remove all paths from a peer and return their local_path_ids for freeing.
fn remove_all_peer_paths<K: Eq + Hash>(table: &mut HashMap<K, Route>, peer_ip: IpAddr) -> Vec<u32> {
    let mut freed_ids = Vec::new();
    for route in table.values_mut() {
        for path in route.paths.iter() {
            if is_path_from_peer(path, peer_ip) {
                freed_ids.push(path.local_path_id);
            }
        }
        route.paths.retain(|p| !is_path_from_peer(p, peer_ip));
    }
    table.retain(|_, route| !route.paths.is_empty());
    freed_ids
}

impl LocRib {
    fn add_route(&mut self, prefix: IpNetwork, path: Arc<Path>) {
        match prefix {
            IpNetwork::V4(v4_prefix) => add_route(
                &mut self.ipv4_unicast,
                v4_prefix,
                prefix,
                path,
                &mut self.path_ids,
            ),
            IpNetwork::V6(v6_prefix) => add_route(
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
        let freed = remove_all_peer_paths(&mut self.ipv4_unicast, peer_ip);
        for id in freed {
            self.path_ids.free(id);
        }
        let freed = remove_all_peer_paths(&mut self.ipv6_unicast, peer_ip);
        for id in freed {
            self.path_ids.free(id);
        }
    }

    /// Remove paths from a specific peer for a given prefix.
    /// Returns true if a path was actually removed.
    fn remove_peer_path(&mut self, prefix: IpNetwork, peer_ip: IpAddr) -> bool {
        let freed_ids = match prefix {
            IpNetwork::V4(v4_prefix) => {
                remove_peer_paths(&mut self.ipv4_unicast, &v4_prefix, peer_ip)
            }
            IpNetwork::V6(v6_prefix) => {
                remove_peer_paths(&mut self.ipv6_unicast, &v6_prefix, peer_ip)
            }
        };
        let had_path = !freed_ids.is_empty();
        for id in freed_ids {
            self.path_ids.free(id);
        }
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
    /// Returns (best_changed, all_affected):
    /// - best_changed: prefixes where the best path changed (for non-ADD-PATH peers)
    /// - all_affected: all prefixes touched by this update (for ADD-PATH peers)
    pub fn update_from_peer<F>(
        &mut self,
        peer_ip: IpAddr,
        withdrawn: Vec<IpNetwork>,
        announced: Vec<(IpNetwork, Arc<Path>)>,
        import_policy: F,
    ) -> (Vec<IpNetwork>, Vec<IpNetwork>)
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

        let best_changed = affected
            .iter()
            .filter(|p| old_best.get(p).unwrap() != &self.get_best_path(p).map(Arc::clone))
            .cloned()
            .collect();
        (best_changed, affected)
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
            path_ids: PathIdAllocator::new(),
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
        originator_id: Option<std::net::Ipv4Addr>,
        cluster_list: Vec<std::net::Ipv4Addr>,
    ) {
        // RFC 4271 Section 5.1.2: when originating a route (as_path is empty),
        // AS_PATH is empty when sent to iBGP peers, or [local_asn] when sent to eBGP peers.
        // We store it as provided and add local_asn during export based on peer type.
        // If as_path is not empty, it's used as-is (for testing or route injection).
        let path = Arc::new(Path {
            local_path_id: 0,
            remote_path_id: None,
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
            originator_id,
            cluster_list,
        });

        self.add_route(prefix, path);
    }

    /// Remove a locally originated route
    /// Returns true if a route was actually removed.
    pub fn remove_local_route(&mut self, prefix: IpNetwork) -> bool {
        info!(prefix = ?prefix, "removing local route from Loc-RIB");

        let freed_ids = match prefix {
            IpNetwork::V4(v4_prefix) => remove_local_paths(&mut self.ipv4_unicast, &v4_prefix),
            IpNetwork::V6(v6_prefix) => remove_local_paths(&mut self.ipv6_unicast, &v6_prefix),
        };
        let removed = !freed_ids.is_empty();
        for id in freed_ids {
            self.path_ids.free(id);
        }
        removed
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

    /// Get all paths for a specific prefix (for ADD-PATH propagation)
    pub fn get_all_paths(&self, prefix: &IpNetwork) -> Vec<Arc<Path>> {
        match prefix {
            IpNetwork::V4(v4_prefix) => self
                .ipv4_unicast
                .get(v4_prefix)
                .map(|r| r.paths.clone())
                .unwrap_or_default(),
            IpNetwork::V6(v6_prefix) => self
                .ipv6_unicast
                .get(v6_prefix)
                .map(|r| r.paths.clone())
                .unwrap_or_default(),
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
    /// Tracks stale local_path_ids. New/replaced paths get fresh IDs, so they're never stale.
    /// Returns the count of path IDs marked as stale.
    pub fn mark_peer_routes_stale(
        &mut self,
        peer_ip: IpAddr,
        afi_safi: crate::bgp::multiprotocol::AfiSafi,
    ) -> usize {
        use crate::bgp::multiprotocol::{Afi, Safi};

        let path_ids: Vec<u32> = match (afi_safi.afi, afi_safi.safi) {
            (Afi::Ipv4, Safi::Unicast) => collect_peer_path_ids(&self.ipv4_unicast, peer_ip),
            (Afi::Ipv6, Safi::Unicast) => collect_peer_path_ids(&self.ipv6_unicast, peer_ip),
            _ => Vec::new(),
        };

        let count = path_ids.len();
        if count > 0 {
            self.stale_routes
                .entry((peer_ip, afi_safi))
                .or_default()
                .extend(path_ids);
            info!(peer_ip = %peer_ip, afi_safi = %afi_safi, count = count,
                  "marked routes as stale for Graceful Restart");
        }
        count
    }

    /// Remove all stale routes from a peer for a specific AFI/SAFI.
    /// Removes paths whose local_path_ids are in the stale set.
    /// Returns prefixes where the best path changed.
    pub fn remove_peer_routes_stale(
        &mut self,
        peer_ip: IpAddr,
        afi_safi: crate::bgp::multiprotocol::AfiSafi,
    ) -> Vec<IpNetwork> {
        let stale_ids = self
            .stale_routes
            .remove(&(peer_ip, afi_safi))
            .unwrap_or_default();
        if stale_ids.is_empty() {
            return Vec::new();
        }

        info!(peer_ip = %peer_ip, afi_safi = %afi_safi, count = stale_ids.len(),
              "removing stale routes after GR timer expiry/EOR");

        let mut changed_prefixes = Vec::new();

        use crate::bgp::multiprotocol::{Afi, Safi};
        match (afi_safi.afi, afi_safi.safi) {
            (Afi::Ipv4, Safi::Unicast) => {
                let (freed, changed) = remove_paths_by_ids(&mut self.ipv4_unicast, &stale_ids);
                for id in freed {
                    self.path_ids.free(id);
                }
                changed_prefixes.extend(changed);
            }
            (Afi::Ipv6, Safi::Unicast) => {
                let (freed, changed) = remove_paths_by_ids(&mut self.ipv6_unicast, &stale_ids);
                for id in freed {
                    self.path_ids.free(id);
                }
                changed_prefixes.extend(changed);
            }
            _ => {}
        }

        changed_prefixes
    }

    /// Check if a peer has any stale routes (is in GR restart mode)
    pub fn has_stale_routes_for_peer(&self, peer_ip: IpAddr) -> bool {
        self.stale_routes.keys().any(|(ip, _)| *ip == peer_ip)
    }

    /// Get all AFI/SAFIs that have stale routes for a peer
    pub fn stale_afi_safis(&self, peer_ip: IpAddr) -> Vec<crate::bgp::multiprotocol::AfiSafi> {
        self.stale_routes
            .keys()
            .filter_map(|(ip, afi_safi)| {
                if *ip == peer_ip {
                    Some(*afi_safi)
                } else {
                    None
                }
            })
            .collect()
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
        assert_eq!(loc_rib.get_all_routes(), vec![]);
        assert_eq!(loc_rib.routes_len(), 0);
    }

    #[test]
    fn test_add_route() {
        let mut loc_rib = LocRib::new();
        let peer_ip = test_peer_ip();
        let prefix = create_test_prefix();
        let path = create_test_path(peer_ip, test_bgp_id());

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

        let path1 = create_test_path(peer_ip, test_bgp_id());
        let path2 = create_test_path(peer_ip, test_bgp_id());

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

        let path1 = create_test_path(peer1, test_bgp_id());
        let path2 = create_test_path(peer2, test_bgp_id2());

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

        let path1 = create_test_path(peer_ip, test_bgp_id());
        let path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
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

        let path1 = create_test_path(peer1, test_bgp_id());
        let path2 = create_test_path(peer2, test_bgp_id2());

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
        let path = create_test_path(peer_ip, test_bgp_id());

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
            None,
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
            None,
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

        loc_rib.add_route(prefix_v4, create_test_path(peer_ip, test_bgp_id()));
        loc_rib.add_route(prefix_v6, create_test_path(peer_ip, test_bgp_id()));

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

        loc_rib.add_route(prefix_v4, create_test_path(peer_ip, test_bgp_id()));
        loc_rib.add_route(prefix_v6, create_test_path(peer_ip, test_bgp_id()));

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

        loc_rib.add_route(prefix_v4, create_test_path(peer_ip, test_bgp_id()));
        loc_rib.add_route(prefix_v6, create_test_path(peer_ip, test_bgp_id()));

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

        loc_rib.add_route(prefix_v4, create_test_path(peer1, test_bgp_id()));
        loc_rib.add_route(prefix_v6, create_test_path(peer2, test_bgp_id2()));

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

    // --- Path ID allocation tests ---

    #[test]
    fn test_path_id_allocated_on_add() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();
        let path = create_test_path(test_peer_ip(), test_bgp_id());

        loc_rib.add_route(prefix, path);

        let stored = loc_rib.get_best_path(&prefix).unwrap();
        assert!(
            stored.local_path_id > 0,
            "loc-rib path should have allocated ID"
        );
    }

    #[test]
    fn test_path_id_reused_on_replace() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();
        let peer_ip = test_peer_ip();

        // Add initial path
        loc_rib.add_route(prefix, create_test_path(peer_ip, test_bgp_id()));
        let id1 = loc_rib.get_best_path(&prefix).unwrap().local_path_id;

        // Replace with updated path (same source, same remote_path_id=None)
        let path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.med = Some(50);
        });
        loc_rib.add_route(prefix, path2);
        let id2 = loc_rib.get_best_path(&prefix).unwrap().local_path_id;

        assert_eq!(id1, id2, "replaced path should inherit local_path_id");
    }

    #[test]
    fn test_path_id_different_sources_get_unique_ids() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();

        loc_rib.add_route(prefix, create_test_path(test_peer_ip(), test_bgp_id()));
        loc_rib.add_route(prefix, create_test_path(test_peer_ip2(), test_bgp_id2()));

        let routes = loc_rib.get_all_routes();
        let ids: Vec<u32> = routes[0].paths.iter().map(|p| p.local_path_id).collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1], "different sources should get different IDs");
        assert!(ids[0] > 0 && ids[1] > 0);
    }

    #[test]
    fn test_path_id_different_remote_path_id_coexist() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();
        let peer_ip = test_peer_ip();

        // Add path with remote_path_id=None (no ADD-PATH)
        let path1 = create_test_path(peer_ip, test_bgp_id());
        loc_rib.add_route(prefix, path1);

        // Add path from same source with remote_path_id=Some(42) (ADD-PATH)
        let path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.remote_path_id = Some(42);
        });
        loc_rib.add_route(prefix, path2);

        let routes = loc_rib.get_all_routes();
        assert_eq!(
            routes[0].paths.len(),
            2,
            "different remote_path_ids should coexist"
        );

        let ids: Vec<u32> = routes[0].paths.iter().map(|p| p.local_path_id).collect();
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn test_path_id_freed_on_peer_removal() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();
        let peer_ip = test_peer_ip();

        loc_rib.add_route(prefix, create_test_path(peer_ip, test_bgp_id()));
        let id1 = loc_rib.get_best_path(&prefix).unwrap().local_path_id;

        // Remove peer path -> frees the ID
        loc_rib.remove_routes_from_peer(peer_ip);

        // Add a new path -> should reuse the freed ID
        loc_rib.add_route(prefix, create_test_path(test_peer_ip2(), test_bgp_id2()));
        let id2 = loc_rib.get_best_path(&prefix).unwrap().local_path_id;

        assert_eq!(id1, id2, "freed ID should be reused");
    }

    #[test]
    fn test_path_id_freed_on_local_route_removal() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();

        loc_rib.add_local_route(
            prefix,
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            Origin::IGP,
            vec![],
            None,
            None,
            false,
            vec![],
            vec![],
            vec![],
            None,
            vec![],
        );
        let id1 = loc_rib.get_best_path(&prefix).unwrap().local_path_id;

        loc_rib.remove_local_route(prefix);

        // Add another route -> should reuse the freed ID
        loc_rib.add_route(prefix, create_test_path(test_peer_ip(), test_bgp_id()));
        let id2 = loc_rib.get_best_path(&prefix).unwrap().local_path_id;

        assert_eq!(id1, id2, "freed local route ID should be reused");
    }

    #[test]
    fn test_path_id_freed_on_remove_all_peer_paths() {
        let mut loc_rib = LocRib::new();
        let peer_ip = test_peer_ip();

        // Add paths to two different prefixes
        loc_rib.add_route(
            create_test_prefix_n(0),
            create_test_path(peer_ip, test_bgp_id()),
        );
        loc_rib.add_route(
            create_test_prefix_n(1),
            create_test_path(peer_ip, test_bgp_id()),
        );

        // Remove all -> frees both IDs (1 and 2)
        loc_rib.remove_routes_from_peer(peer_ip);

        // Add two new paths -> should reuse IDs 1 and 2
        loc_rib.add_route(
            create_test_prefix_n(2),
            create_test_path(test_peer_ip2(), test_bgp_id2()),
        );
        loc_rib.add_route(
            create_test_prefix_n(3),
            create_test_path(test_peer_ip2(), test_bgp_id2()),
        );

        let routes = loc_rib.get_all_routes();
        let mut ids: Vec<u32> = routes.iter().map(|r| r.paths[0].local_path_id).collect();
        ids.sort();
        assert_eq!(ids, vec![1, 2], "freed IDs should be reused");
    }

    #[test]
    fn test_get_all_paths() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();

        // Empty prefix -> empty vec
        assert!(loc_rib.get_all_paths(&prefix).is_empty());

        // One path
        loc_rib.add_route(prefix, create_test_path(test_peer_ip(), test_bgp_id()));
        assert_eq!(loc_rib.get_all_paths(&prefix).len(), 1);

        // Two paths from different peers
        loc_rib.add_route(prefix, create_test_path(test_peer_ip2(), test_bgp_id2()));
        let paths = loc_rib.get_all_paths(&prefix);
        assert_eq!(paths.len(), 2);
        // Paths should be sorted (best first)
        assert!(paths[0] >= paths[1]);
    }

    #[test]
    fn test_update_from_peer_returns_all_affected() {
        let mut loc_rib = LocRib::new();
        let peer1 = test_peer_ip();
        let peer2 = test_peer_ip2();
        let prefix = create_test_prefix();

        // Add a route from peer1 (the best)
        loc_rib.add_route(prefix, create_test_path(peer1, test_bgp_id()));

        // Now announce from peer2 with a worse path (longer AS path)
        let worse_path = create_test_path_with(peer2, test_bgp_id2(), |p| {
            p.as_path = vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 3,
                asn_list: vec![100, 200, 300],
            }];
        });

        let (best_changed, all_affected) =
            loc_rib.update_from_peer(peer2, vec![], vec![(prefix, worse_path)], |_, _| true);

        // Best didn't change (peer1's path is still best)
        assert!(best_changed.is_empty(), "best should not have changed");
        // But the prefix IS affected (new path added)
        assert_eq!(
            all_affected,
            vec![prefix],
            "prefix should be in all_affected"
        );
        // Both paths should exist
        assert_eq!(loc_rib.get_all_paths(&prefix).len(), 2);
    }
}
