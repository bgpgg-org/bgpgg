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

use crate::bgp::bgpls_nlri::LsNlri;
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::log::{debug, info};
use crate::net::{IpNetwork, Ipv4Net, Ipv6Net};
use crate::peer::PendingRoute;
use crate::rib::path_id::{BitmapPathIdAllocator, PathIdAllocator};
use crate::rib::stale::{apply_stale_to_route, mark_stale, StaleStrategy};
use crate::rib::types::RouteKey;
use crate::rib::{Path, PathAttrs, Route, RoutePath, RouteSource};
use crate::rpki::vrp::RpkiValidation;
use crate::table::PrefixMap;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

/// Result of applying a peer update to the Loc-RIB.
pub struct RouteDelta {
    /// Routes where the best path changed (for non-ADD-PATH peers)
    pub best_changed: Vec<RouteKey>,
    /// All routes with any path added or removed (for ADD-PATH peers)
    pub changed: Vec<RouteKey>,
}

impl Default for RouteDelta {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteDelta {
    pub fn new() -> Self {
        Self {
            best_changed: Vec::new(),
            changed: Vec::new(),
        }
    }

    pub fn has_changes(&self) -> bool {
        !self.best_changed.is_empty() || !self.changed.is_empty()
    }

    pub fn extend(&mut self, other: RouteDelta) {
        self.best_changed.extend(other.best_changed);
        self.changed.extend(other.changed);
    }
}

#[cfg(test)]
use std::net::Ipv4Addr;

/// Loc-RIB: Local routing table
///
/// Contains the best paths selected after applying import policies
/// and the BGP best path selection algorithm.
pub struct LocRib<A: PathIdAllocator = BitmapPathIdAllocator> {
    // Per-AFI/SAFI tables (HashMap + trie for subtree/covering queries)
    ipv4_unicast: PrefixMap<Ipv4Net, Route>,
    ipv6_unicast: PrefixMap<Ipv6Net, Route>,
    // BGP-LS table (RFC 9552): all LS NLRI types in one table
    link_state: HashMap<LsNlri, Route>,

    /// ADD-PATH local path ID allocator (RFC 7911)
    path_ids: A,
}

// Path manipulation helpers — operate on Route, independent of container type.

/// Insert or update a path in a route's path list.
/// - If a matching path exists and attrs differ, replace it (inheriting local_path_id).
/// - If attrs match but local metadata differs (rpki_state, stale), update in place
///   to preserve Arc identity (ADD-PATH propagation relies on ptr_eq).
/// - If no match, allocate a fresh local_path_id and append.
fn upsert_path_in_route<A: PathIdAllocator>(
    route: &mut Route,
    mut path: Arc<Path>,
    path_ids: &mut A,
) {
    match route.paths.iter_mut().find(|p| p.matches_remote(&path)) {
        Some(existing) => {
            if existing.attrs != path.attrs {
                Arc::make_mut(&mut path).local_path_id = existing.local_path_id;
                *existing = path;
            } else {
                // Attrs unchanged — update local metadata in place to preserve
                // Arc identity (ADD-PATH relies on ptr_eq for propagation).
                if existing.rpki_state != path.rpki_state {
                    Arc::make_mut(existing).rpki_state = path.rpki_state;
                }
                if existing.stale {
                    Arc::make_mut(existing).stale = false;
                }
            }
        }
        None => {
            Arc::make_mut(&mut path).local_path_id = Some(path_ids.alloc());
            route.paths.push(path);
        }
    }

    route.paths.sort_by(|a, b| b.best_path_cmp(a));
}

/// Remove paths matching a predicate from a route. Returns freed local_path_ids.
fn remove_paths_from_route(route: &mut Route, should_remove: impl Fn(&Path) -> bool) -> Vec<u32> {
    let freed_path_ids: Vec<u32> = route
        .paths
        .iter()
        .filter(|p| should_remove(p))
        .filter_map(|p| p.local_path_id)
        .collect();
    route.paths.retain(|p| !should_remove(p));
    freed_path_ids
}

/// Collect freed path IDs from all routes owned by a peer, removing those paths.
fn collect_peer_path_ids<'a>(
    routes: impl Iterator<Item = &'a mut Route>,
    peer_ip: IpAddr,
) -> Vec<u32> {
    let mut freed_path_ids = Vec::new();
    for route in routes {
        freed_path_ids.extend(
            route
                .paths
                .iter()
                .filter(|p| p.is_from_peer(peer_ip))
                .filter_map(|p| p.local_path_id),
        );
        route.paths.retain(|p| !p.is_from_peer(peer_ip));
    }
    freed_path_ids
}

impl<A: PathIdAllocator> LocRib<A> {
    fn get_route_mut(&mut self, key: &RouteKey) -> Option<&mut Route> {
        match key {
            RouteKey::Prefix(IpNetwork::V4(net)) => self.ipv4_unicast.get_mut(net),
            RouteKey::Prefix(IpNetwork::V6(net)) => self.ipv6_unicast.get_mut(net),
            RouteKey::LinkState(nlri) => self.link_state.get_mut(nlri),
        }
    }

    /// Remove paths matching a predicate and clean up empty entries.
    fn remove_paths(&mut self, key: &RouteKey, should_remove: impl Fn(&Path) -> bool) -> Vec<u32> {
        let Some(route) = self.get_route_mut(key) else {
            return Vec::new();
        };
        let freed = remove_paths_from_route(route, should_remove);
        if route.paths.is_empty() {
            self.remove_route_entry(key);
        }
        freed
    }

    fn remove_route_entry(&mut self, key: &RouteKey) {
        match key {
            RouteKey::Prefix(IpNetwork::V4(net)) => {
                self.ipv4_unicast.remove(net);
            }
            RouteKey::Prefix(IpNetwork::V6(net)) => {
                self.ipv6_unicast.remove(net);
            }
            RouteKey::LinkState(nlri) => {
                self.link_state.remove(nlri);
            }
        }
    }

    fn upsert_path(&mut self, key: RouteKey, path: Arc<Path>) {
        let route = match &key {
            RouteKey::Prefix(IpNetwork::V4(net)) => self
                .ipv4_unicast
                .get_or_insert(*net, Route { key, paths: vec![] }),
            RouteKey::Prefix(IpNetwork::V6(net)) => self
                .ipv6_unicast
                .get_or_insert(*net, Route { key, paths: vec![] }),
            RouteKey::LinkState(nlri) => {
                let nlri_clone = nlri.clone();
                self.link_state
                    .entry(nlri_clone)
                    .or_insert_with(|| Route { key, paths: vec![] })
            }
        };
        upsert_path_in_route(route, path, &mut self.path_ids);
    }

    fn get_peer_route_keys(&self, peer_ip: IpAddr) -> Vec<RouteKey> {
        let has_peer = |route: &Route| route.paths.iter().any(|p| p.is_from_peer(peer_ip));
        let mut keys = Vec::new();

        for (prefix, route) in self.ipv4_unicast.iter() {
            if has_peer(route) {
                keys.push(RouteKey::Prefix(IpNetwork::V4(*prefix)));
            }
        }
        for (prefix, route) in self.ipv6_unicast.iter() {
            if has_peer(route) {
                keys.push(RouteKey::Prefix(IpNetwork::V6(*prefix)));
            }
        }
        for (nlri, route) in self.link_state.iter() {
            if has_peer(route) {
                keys.push(RouteKey::LinkState(nlri.clone()));
            }
        }

        keys
    }

    fn clear_peer_paths(&mut self, peer_ip: IpAddr) {
        let freed = collect_peer_path_ids(self.ipv4_unicast.values_mut(), peer_ip);
        self.path_ids.free_all(freed);
        self.ipv4_unicast.retain(|_, route| !route.paths.is_empty());

        let freed = collect_peer_path_ids(self.ipv6_unicast.values_mut(), peer_ip);
        self.path_ids.free_all(freed);
        self.ipv6_unicast.retain(|_, route| !route.paths.is_empty());

        let freed = collect_peer_path_ids(self.link_state.values_mut(), peer_ip);
        self.path_ids.free_all(freed);
        self.link_state.retain(|_, route| !route.paths.is_empty());
    }

    /// Remove paths from a specific peer for a given route key.
    /// When `remote_path_id` is Some, only the path with that remote_path_id is removed.
    /// When None, all paths from that peer are removed (non-ADD-PATH behavior).
    /// Returns true if a path was actually removed.
    fn remove_peer_path(
        &mut self,
        key: &RouteKey,
        peer_ip: IpAddr,
        remote_path_id: Option<u32>,
    ) -> bool {
        let freed = self.remove_paths(key, |p| {
            p.is_from_peer(peer_ip) && remote_path_id.is_none_or(|id| p.remote_path_id == Some(id))
        });
        let had_path = !freed.is_empty();
        self.path_ids.free_all(freed);
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

    /// Update Loc-RIB from ordered pending routes.
    /// Routes are processed in order to preserve causality across coalesced updates.
    pub fn apply_peer_update<F>(
        &mut self,
        peer_ip: IpAddr,
        pending_routes: &[PendingRoute],
        import_policy: F,
    ) -> RouteDelta
    where
        F: Fn(&RouteKey, &mut Path) -> bool,
    {
        let affected: Vec<RouteKey> = pending_routes
            .iter()
            .map(|route| route.route_key())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let old_best: HashMap<RouteKey, Arc<Path>> = affected
            .iter()
            .filter_map(|key| {
                self.get_best_path(key)
                    .map(|best| (key.clone(), Arc::clone(best)))
            })
            .collect();

        for pending_route in pending_routes {
            match pending_route {
                PendingRoute::Withdraw((key, remote_path_id)) => {
                    info!(route_key = ?key, peer_ip = %peer_ip, "withdrawing route from Loc-RIB");
                    self.remove_peer_path(key, peer_ip, *remote_path_id);
                }
                PendingRoute::Announce(RoutePath {
                    key,
                    path: path_arc,
                }) => {
                    let mut path = (**path_arc).clone();
                    if import_policy(key, &mut path) {
                        info!(route_key = ?key, peer_ip = %peer_ip, "adding route to Loc-RIB");
                        self.upsert_path(key.clone(), Arc::new(path));
                    } else {
                        debug!(route_key = ?key, peer_ip = %peer_ip, "route rejected by import policy");
                        self.remove_peer_path(key, peer_ip, path_arc.remote_path_id);
                    }
                }
            }
        }

        let best_changed = affected
            .iter()
            .filter(|key| self.best_path_changed(key, old_best.get(*key)))
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
            ipv4_unicast: PrefixMap::new(),
            ipv6_unicast: PrefixMap::new(),
            link_state: HashMap::new(),
            path_ids: BitmapPathIdAllocator::new(),
        }
    }
}

impl<A: PathIdAllocator> LocRib<A> {
    pub fn with_path_ids(path_ids: A) -> Self {
        LocRib {
            ipv4_unicast: PrefixMap::new(),
            ipv6_unicast: PrefixMap::new(),
            link_state: HashMap::new(),
            path_ids,
        }
    }

    /// Add a locally originated route
    pub fn add_local_route(&mut self, prefix: IpNetwork, path_attrs: PathAttrs) -> RouteDelta {
        let key = RouteKey::Prefix(prefix);
        let old_best = self.get_best_path(&key).map(Arc::clone);
        let path = Arc::new(Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            rpki_state: RpkiValidation::NotFound,
            attrs: PathAttrs {
                source: RouteSource::Local,
                local_pref: path_attrs.local_pref.or(Some(100)),
                ..path_attrs
            },
        });
        self.upsert_path(key.clone(), path);
        let best_changed = if self.best_path_changed(&key, old_best.as_ref()) {
            vec![key.clone()]
        } else {
            vec![]
        };
        RouteDelta {
            best_changed,
            changed: vec![key],
        }
    }

    /// Remove a locally originated route
    pub fn remove_local_route(&mut self, prefix: IpNetwork) -> RouteDelta {
        info!(prefix = ?prefix, "removing local route from Loc-RIB");

        let key = RouteKey::Prefix(prefix);
        let old_best = self.get_best_path(&key).map(Arc::clone);
        let freed = self.remove_paths(&key, |p| p.attrs.source == RouteSource::Local);
        if freed.is_empty() {
            return RouteDelta::new();
        }
        self.path_ids.free_all(freed);
        let best_changed = if self.best_path_changed(&key, old_best.as_ref()) {
            vec![key.clone()]
        } else {
            vec![]
        };
        RouteDelta {
            best_changed,
            changed: vec![key],
        }
    }

    /// Remove all routes from a peer. Returns a RouteDelta with best_changed
    /// (prefixes where best path changed) and changed (all affected prefixes).
    pub fn remove_routes_from_peer(&mut self, peer_ip: IpAddr) -> RouteDelta {
        let changed = self.get_peer_route_keys(peer_ip);

        let old_best: HashMap<RouteKey, Arc<Path>> = changed
            .iter()
            .filter_map(|key| {
                self.get_best_path(key)
                    .map(|best| (key.clone(), Arc::clone(best)))
            })
            .collect();

        self.clear_peer_paths(peer_ip);

        let best_changed = changed
            .iter()
            .filter(|key| self.best_path_changed(key, old_best.get(key)))
            .cloned()
            .collect();

        RouteDelta {
            best_changed,
            changed,
        }
    }

    pub fn routes_len(&self) -> usize {
        self.ipv4_unicast.len() + self.ipv6_unicast.len() + self.link_state.len()
    }

    /// Returns true if the best path for a route key differs from the old snapshot.
    fn best_path_changed(&self, key: &RouteKey, old: Option<&Arc<Path>>) -> bool {
        match (old, self.get_best_path(key)) {
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

    pub fn get_best_path(&self, key: &RouteKey) -> Option<&Arc<Path>> {
        match key {
            RouteKey::Prefix(prefix) => self.get_route(prefix).and_then(|r| r.paths.first()),
            RouteKey::LinkState(nlri) => self.link_state.get(nlri).and_then(|r| r.paths.first()),
        }
    }

    pub fn get_all_paths(&self, key: &RouteKey) -> Vec<Arc<Path>> {
        match key {
            RouteKey::Prefix(prefix) => self
                .get_route(prefix)
                .map(|r| r.paths.clone())
                .unwrap_or_default(),
            RouteKey::LinkState(nlri) => self
                .link_state
                .get(nlri)
                .map(|r| r.paths.clone())
                .unwrap_or_default(),
        }
    }

    pub fn has_route(&self, key: &RouteKey) -> bool {
        match key {
            RouteKey::Prefix(prefix) => self.get_route(prefix).is_some(),
            RouteKey::LinkState(nlri) => self.link_state.contains_key(nlri),
        }
    }

    /// Get all routes for a given AFI.
    pub fn get_routes_afi(&self, afi: Afi) -> Vec<&Route> {
        match afi {
            Afi::Ipv4 => self.ipv4_unicast.values().collect(),
            Afi::Ipv6 => self.ipv6_unicast.values().collect(),
            Afi::LinkState => self.link_state.values().collect(),
        }
    }

    /// Get paths for an AFI. If `all_paths` is true, returns every path
    /// (ADD-PATH); otherwise returns only the best path per route key.
    pub fn get_paths(&self, afi: Afi, all_paths: bool) -> Vec<RoutePath> {
        let routes: Box<dyn Iterator<Item = &Route>> = match afi {
            Afi::Ipv4 => Box::new(self.ipv4_unicast.values()),
            Afi::Ipv6 => Box::new(self.ipv6_unicast.values()),
            Afi::LinkState => Box::new(self.link_state.values()),
        };
        if all_paths {
            routes
                .flat_map(|route| {
                    let key = route.key.clone();
                    route.paths.iter().map(move |path| RoutePath {
                        key: key.clone(),
                        path: Arc::clone(path),
                    })
                })
                .collect()
        } else {
            routes
                .filter_map(|route| {
                    route.paths.first().map(|path| RoutePath {
                        key: route.key.clone(),
                        path: Arc::clone(path),
                    })
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
            (Afi::Ipv4, Safi::Unicast) => mark_stale(self.ipv4_unicast.values_mut(), peer_ip),
            (Afi::Ipv6, Safi::Unicast) => mark_stale(self.ipv6_unicast.values_mut(), peer_ip),
            (Afi::LinkState, Safi::LinkState) => mark_stale(self.link_state.values_mut(), peer_ip),
            _ => 0,
        };

        if count > 0 {
            info!(peer_ip = %peer_ip, afi_safi = %afi_safi, count = count,
                  "marked paths as stale");
        }
        count
    }

    /// Handle stale routes for the given AFI/SAFIs using the specified strategy.
    /// Used by both LLGR transition and GR sweep.
    fn handle_stale(
        &mut self,
        peer_ip: IpAddr,
        afi_safis: &[AfiSafi],
        strategy: &StaleStrategy,
    ) -> RouteDelta {
        let mut delta = RouteDelta::new();

        for afi_safi in afi_safis {
            let routes_afi = match (afi_safi.afi, afi_safi.safi) {
                (Afi::Ipv4, Safi::Unicast) => Afi::Ipv4,
                (Afi::Ipv6, Safi::Unicast) => Afi::Ipv6,
                (Afi::LinkState, Safi::LinkState) => Afi::LinkState,
                _ => continue,
            };

            let keys: Vec<RouteKey> = self
                .get_routes_afi(routes_afi)
                .iter()
                .filter(|r| r.paths.iter().any(|p| p.is_from_peer(peer_ip) && p.stale))
                .map(|r| r.key.clone())
                .collect();

            for key in keys {
                let route = match &key {
                    RouteKey::Prefix(IpNetwork::V4(net)) => self.ipv4_unicast.get_mut(net),
                    RouteKey::Prefix(IpNetwork::V6(net)) => self.ipv6_unicast.get_mut(net),
                    RouteKey::LinkState(nlri) => self.link_state.get_mut(nlri),
                };
                let Some(route) = route else {
                    continue;
                };
                let old_best = apply_stale_to_route(route, peer_ip, &mut self.path_ids, strategy);
                let Some(old_best) = old_best else {
                    continue;
                };
                let is_empty = self.get_route_mut(&key).is_none_or(|r| r.paths.is_empty());
                if is_empty {
                    self.remove_route_entry(&key);
                }
                delta.changed.push(key.clone());
                if self.best_path_changed(&key, Some(&old_best)) {
                    delta.best_changed.push(key);
                }
            }
        }

        delta
    }

    /// RFC 9494: Transition stale paths from GR to LLGR phase for the given AFI/SAFIs.
    /// - Removes paths carrying NO_LLGR community (not retained during LLGR)
    /// - Adds LLGR_STALE community to remaining stale paths
    /// - Recomputes best path (LLGR_STALE routes are deprioritized)
    pub fn apply_llgr(&mut self, peer_ip: IpAddr, afi_safis: &[AfiSafi]) -> RouteDelta {
        self.handle_stale(peer_ip, afi_safis, &StaleStrategy::TransitionToLlgr)
    }

    /// Remove all stale paths from a peer for the given AFI/SAFIs.
    /// Removes paths where `path.is_from_peer(peer_ip) && path.stale`.
    pub fn remove_peer_routes_stale(
        &mut self,
        peer_ip: IpAddr,
        afi_safis: &[AfiSafi],
    ) -> RouteDelta {
        self.handle_stale(peer_ip, afi_safis, &StaleStrategy::Sweep)
    }

    /// Get all AFI/SAFIs that have stale paths for a peer
    pub fn stale_afi_safis(&self, peer_ip: IpAddr) -> Vec<AfiSafi> {
        let has_stale = |route: &Route| {
            route
                .paths
                .iter()
                .any(|p| p.is_from_peer(peer_ip) && p.stale)
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
        if self.link_state.values().any(has_stale) {
            result.push(AfiSafi {
                afi: Afi::LinkState,
                safi: Safi::LinkState,
            });
        }
        result
    }

    /// Find all route prefixes in the RIB affected by VRP additions and removals.
    pub fn affected_prefixes(
        &self,
        added: &[crate::rpki::vrp::Vrp],
        removed: &[crate::rpki::vrp::Vrp],
    ) -> HashSet<IpNetwork> {
        let mut affected = HashSet::new();
        for vrp in added.iter().chain(removed) {
            for prefix in self.subtree_prefixes(&vrp.prefix) {
                affected.insert(prefix);
            }
        }
        affected
    }

    /// Find all prefixes in the RIB that are subnets of (or equal to) the given prefix.
    pub fn subtree_prefixes(&self, prefix: &IpNetwork) -> Vec<IpNetwork> {
        match prefix {
            IpNetwork::V4(v4) => self
                .ipv4_unicast
                .subtree(v4)
                .into_iter()
                .map(|k| IpNetwork::V4(*k))
                .collect(),
            IpNetwork::V6(v6) => self
                .ipv6_unicast
                .subtree(v6)
                .into_iter()
                .map(|k| IpNetwork::V6(*k))
                .collect(),
        }
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

        loc_rib.upsert_path(RouteKey::Prefix(prefix), path.clone());

        let routes = loc_rib.get_all_routes();
        assert_eq!(routes.len(), 1);
        let expected_path = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.local_path_id = Some(1);
        });
        assert_eq!(
            routes[0],
            Route {
                key: RouteKey::Prefix(prefix),
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

        loc_rib.upsert_path(
            RouteKey::Prefix(prefix1),
            create_test_path(peer_ip, test_bgp_id()),
        );
        loc_rib.upsert_path(
            RouteKey::Prefix(prefix2),
            create_test_path(peer_ip, test_bgp_id()),
        );

        let mut routes = loc_rib.get_all_routes();
        routes.sort_by_key(|r| format!("{:?}", r.key));

        let expected_path1 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.local_path_id = Some(1);
        });
        let expected_path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.local_path_id = Some(2);
        });
        let mut expected = [
            Route {
                key: RouteKey::Prefix(prefix1),
                paths: vec![expected_path1],
            },
            Route {
                key: RouteKey::Prefix(prefix2),
                paths: vec![expected_path2],
            },
        ];
        expected.sort_by_key(|r| format!("{:?}", r.key));

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

        loc_rib.upsert_path(RouteKey::Prefix(prefix), path1.clone());
        loc_rib.upsert_path(RouteKey::Prefix(prefix), path2.clone());

        let routes = loc_rib.get_all_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].key, RouteKey::Prefix(prefix));

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

        loc_rib.upsert_path(RouteKey::Prefix(prefix), path1);
        loc_rib.upsert_path(RouteKey::Prefix(prefix), Arc::clone(&path2));

        let routes = loc_rib.get_all_routes();
        assert_eq!(routes.len(), 1);
        let expected_path = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.local_path_id = Some(1);
            p.attrs.as_path = path2.attrs.as_path.clone();
        });
        assert_eq!(
            routes[0],
            Route {
                key: RouteKey::Prefix(prefix),
                paths: vec![expected_path]
            }
        );
    }

    #[test]
    fn test_upsert_path_updates_rpki_state_in_place() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let peer_ip = test_peer_ip();
        let prefix = create_test_prefix();

        let path = create_test_path(peer_ip, test_bgp_id());
        loc_rib.upsert_path(RouteKey::Prefix(prefix), path);

        let ptr_before = Arc::as_ptr(&loc_rib.get_all_routes()[0].paths[0]);

        // Same attrs, different rpki_state — should update in place, same Arc.
        let path_valid = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.rpki_state = RpkiValidation::Valid;
        });
        loc_rib.upsert_path(RouteKey::Prefix(prefix), path_valid);

        let routes = loc_rib.get_all_routes();
        assert_eq!(routes[0].paths[0].rpki_state, RpkiValidation::Valid);
        // Arc identity preserved — no replacement, just in-place mutation.
        assert_eq!(ptr_before, Arc::as_ptr(&routes[0].paths[0]));
    }

    #[test]
    fn test_remove_routes_from_peer() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let peer1 = test_peer_ip();
        let peer2 = test_peer_ip2();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer1, test_bgp_id());
        let path2 = create_test_path(peer2, test_bgp_id2());

        loc_rib.upsert_path(RouteKey::Prefix(prefix), path1);
        loc_rib.upsert_path(RouteKey::Prefix(prefix), path2.clone());

        loc_rib.remove_routes_from_peer(peer1);

        let routes = loc_rib.get_all_routes();
        assert_eq!(routes.len(), 1);
        let expected_path = create_test_path_with(peer2, test_bgp_id2(), |p| {
            p.local_path_id = Some(2);
        });
        assert_eq!(
            routes[0],
            Route {
                key: RouteKey::Prefix(prefix),
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

        loc_rib.upsert_path(RouteKey::Prefix(prefix), path);
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
                ls_attr: None,
            },
        );
        assert_eq!(loc_rib.routes_len(), 1);
        assert!(loc_rib.has_route(&RouteKey::Prefix(prefix)));

        assert!(loc_rib.remove_local_route(prefix).has_changes());
        assert_eq!(loc_rib.routes_len(), 0);
        assert!(!loc_rib.has_route(&RouteKey::Prefix(prefix)));

        // Removing again should return no changes
        assert!(!loc_rib.remove_local_route(prefix).has_changes());
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
                ls_attr: None,
            },
        );

        let path = loc_rib.get_best_path(&RouteKey::Prefix(prefix)).unwrap();
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

        loc_rib.upsert_path(
            RouteKey::Prefix(prefix_v4),
            create_test_path(peer_ip, test_bgp_id()),
        );
        loc_rib.upsert_path(
            RouteKey::Prefix(prefix_v6),
            create_test_path(peer_ip, test_bgp_id()),
        );

        assert_eq!(loc_rib.routes_len(), 2);
        assert!(loc_rib.has_route(&RouteKey::Prefix(prefix_v4)));
        assert!(loc_rib.has_route(&RouteKey::Prefix(prefix_v6)));

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

        loc_rib.upsert_path(
            RouteKey::Prefix(prefix_v4),
            create_test_path(peer_ip, test_bgp_id()),
        );
        loc_rib.upsert_path(
            RouteKey::Prefix(prefix_v6),
            create_test_path(peer_ip, test_bgp_id()),
        );

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

        loc_rib.upsert_path(
            RouteKey::Prefix(prefix_v4),
            create_test_path(peer_ip, test_bgp_id()),
        );
        loc_rib.upsert_path(
            RouteKey::Prefix(prefix_v6),
            create_test_path(peer_ip, test_bgp_id()),
        );

        let ipv4_routes = loc_rib.get_paths(Afi::Ipv4, false);
        assert_eq!(ipv4_routes.len(), 1);
        assert_eq!(ipv4_routes[0].key, RouteKey::Prefix(prefix_v4));

        let ipv6_routes = loc_rib.get_paths(Afi::Ipv6, false);
        assert_eq!(ipv6_routes.len(), 1);
        assert_eq!(ipv6_routes[0].key, RouteKey::Prefix(prefix_v6));
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

        loc_rib.upsert_path(
            RouteKey::Prefix(prefix_v4),
            create_test_path(peer1, test_bgp_id()),
        );
        loc_rib.upsert_path(
            RouteKey::Prefix(prefix_v6),
            create_test_path(peer2, test_bgp_id2()),
        );

        let delta = loc_rib.remove_routes_from_peer(peer1);

        assert_eq!(delta.best_changed.len(), 1);
        assert_eq!(delta.best_changed[0], RouteKey::Prefix(prefix_v4));
        assert_eq!(delta.changed.len(), 1);
        assert_eq!(delta.changed[0], RouteKey::Prefix(prefix_v4));
        assert!(!loc_rib.has_route(&RouteKey::Prefix(prefix_v4)));
        assert!(loc_rib.has_route(&RouteKey::Prefix(prefix_v6)));
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

        loc_rib.upsert_path(RouteKey::Prefix(prefix), path);

        let stored = loc_rib.get_best_path(&RouteKey::Prefix(prefix)).unwrap();
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
        loc_rib.upsert_path(
            RouteKey::Prefix(prefix),
            create_test_path(peer_ip, test_bgp_id()),
        );
        let id1 = loc_rib
            .get_best_path(&RouteKey::Prefix(prefix))
            .unwrap()
            .local_path_id;

        let before = Arc::clone(loc_rib.get_best_path(&RouteKey::Prefix(prefix)).unwrap());

        // Replace with updated path (same source, same remote_path_id=None)
        let path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.attrs.med = Some(50);
        });
        loc_rib.upsert_path(RouteKey::Prefix(prefix), path2);
        let after = loc_rib.get_best_path(&RouteKey::Prefix(prefix)).unwrap();

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

        loc_rib.upsert_path(RouteKey::Prefix(prefix), Arc::clone(&path));
        let stored = loc_rib.get_best_path(&RouteKey::Prefix(prefix)).unwrap();
        let ptr_before = Arc::as_ptr(stored);

        // Re-add identical path — should not replace the Arc
        loc_rib.upsert_path(RouteKey::Prefix(prefix), Arc::clone(&path));
        let stored = loc_rib.get_best_path(&RouteKey::Prefix(prefix)).unwrap();
        assert!(
            std::ptr::eq(ptr_before, Arc::as_ptr(stored)),
            "identical path should keep existing Arc"
        );
    }

    #[test]
    fn test_path_id_different_sources_get_unique_ids() {
        let mut loc_rib = LocRib::new();
        let prefix = create_test_prefix();

        loc_rib.upsert_path(
            RouteKey::Prefix(prefix),
            create_test_path(test_peer_ip(), test_bgp_id()),
        );
        loc_rib.upsert_path(
            RouteKey::Prefix(prefix),
            create_test_path(test_peer_ip2(), test_bgp_id2()),
        );

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
        loc_rib.upsert_path(RouteKey::Prefix(prefix), path1);

        let path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.remote_path_id = Some(2);
        });
        loc_rib.upsert_path(RouteKey::Prefix(prefix), path2);

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

        loc_rib.upsert_path(
            RouteKey::Prefix(prefix),
            create_test_path(peer_ip, test_bgp_id()),
        );
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
                ls_attr: None,
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
            RouteKey::Prefix(create_test_prefix_n(0)),
            create_test_path(peer_ip, test_bgp_id()),
        );
        loc_rib.upsert_path(
            RouteKey::Prefix(create_test_prefix_n(1)),
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
        assert!(loc_rib.get_all_paths(&RouteKey::Prefix(prefix)).is_empty());

        // One path
        loc_rib.upsert_path(
            RouteKey::Prefix(prefix),
            create_test_path(test_peer_ip(), test_bgp_id()),
        );
        assert_eq!(loc_rib.get_all_paths(&RouteKey::Prefix(prefix)).len(), 1);

        // Two paths from different peers
        loc_rib.upsert_path(
            RouteKey::Prefix(prefix),
            create_test_path(test_peer_ip2(), test_bgp_id2()),
        );
        let paths = loc_rib.get_all_paths(&RouteKey::Prefix(prefix));
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
        loc_rib.upsert_path(
            RouteKey::Prefix(prefix),
            create_test_path(peer1, test_bgp_id()),
        );

        // Now announce from peer2 with a worse path (longer AS path)
        let worse_path = create_test_path_with(peer2, test_bgp_id2(), |p| {
            p.attrs.as_path = vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 3,
                asn_list: vec![100, 200, 300],
            }];
        });

        let delta = loc_rib.apply_peer_update(
            peer2,
            &[PendingRoute::Announce(RoutePath {
                key: RouteKey::Prefix(prefix),
                path: worse_path,
            })],
            |_, _| true,
        );

        // Best didn't change (peer1's path is still best)
        assert!(
            delta.best_changed.is_empty(),
            "best should not have changed"
        );
        // But the prefix IS affected (new path added)
        assert_eq!(
            delta.changed,
            vec![RouteKey::Prefix(prefix)],
            "prefix should be in changed"
        );
        // Both paths should exist
        assert_eq!(loc_rib.get_all_paths(&RouteKey::Prefix(prefix)).len(), 2);
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
        loc_rib.upsert_path(
            RouteKey::Prefix(prefix),
            create_test_path(peer_ip, test_bgp_id()),
        );
        loc_rib.mark_peer_routes_stale(peer_ip, ipv4_uni);
        assert!(!loc_rib.stale_afi_safis(peer_ip).is_empty());

        // Verify the path is marked stale
        assert!(
            loc_rib
                .get_best_path(&RouteKey::Prefix(prefix))
                .unwrap()
                .stale
        );

        // Peer reconnects and re-sends the same route (new path has stale=false)
        let refreshed_path = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.attrs.med = Some(50);
        });
        loc_rib.apply_peer_update(
            peer_ip,
            &[PendingRoute::Announce(RoutePath {
                key: RouteKey::Prefix(prefix),
                path: refreshed_path,
            })],
            |_, _| true,
        );

        // Replacement path should not be stale
        assert!(
            !loc_rib
                .get_best_path(&RouteKey::Prefix(prefix))
                .unwrap()
                .stale
        );

        // EOR sweep should NOT remove the refreshed path
        let delta = loc_rib.remove_peer_routes_stale(peer_ip, &[ipv4_uni]);
        assert!(!delta.has_changes(), "no paths should be removed");
        assert!(
            loc_rib.get_best_path(&RouteKey::Prefix(prefix)).is_some(),
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
        loc_rib.upsert_path(RouteKey::Prefix(prefix), path1);
        loc_rib.upsert_path(RouteKey::Prefix(prefix), path2);
        assert_eq!(loc_rib.get_all_paths(&RouteKey::Prefix(prefix)).len(), 2);

        // Peer disconnects with GR -> mark both stale
        let stale_count = loc_rib.mark_peer_routes_stale(peer_ip, ipv4_uni);
        assert_eq!(stale_count, 2);

        // Peer reconnects and only re-sends path_id=1
        let refreshed = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
            p.attrs.med = Some(99);
        });
        loc_rib.apply_peer_update(
            peer_ip,
            &[PendingRoute::Announce(RoutePath {
                key: RouteKey::Prefix(prefix),
                path: refreshed,
            })],
            |_, _| true,
        );

        // path_id=1 should be fresh, path_id=2 should still be stale
        let paths = loc_rib.get_all_paths(&RouteKey::Prefix(prefix));
        assert_eq!(paths.len(), 2);
        let fresh_count = paths.iter().filter(|p| !p.stale).count();
        let stale_count = paths.iter().filter(|p| p.stale).count();
        assert_eq!(fresh_count, 1);
        assert_eq!(stale_count, 1);

        // EOR sweep: removes stale path_id=2, keeps path_id=1
        let delta = loc_rib.remove_peer_routes_stale(peer_ip, &[ipv4_uni]);

        let remaining = loc_rib.get_all_paths(&RouteKey::Prefix(prefix));
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].remote_path_id, Some(1));
        assert!(!remaining[0].stale);
        // Best path changed (stale best was removed)
        assert!(!delta.best_changed.is_empty());
        // The prefix was also affected
        assert!(!delta.changed.is_empty());
    }

    #[test]
    fn test_route_delta_has_changes() {
        let prefix_key = RouteKey::Prefix(create_test_prefix());
        let cases = vec![
            ("empty", vec![], vec![], false),
            ("best_changed only", vec![prefix_key.clone()], vec![], true),
            ("changed only", vec![], vec![prefix_key.clone()], true),
            (
                "both",
                vec![prefix_key.clone()],
                vec![prefix_key.clone()],
                true,
            ),
        ];
        for (desc, best_changed, changed, expected) in cases {
            let delta = RouteDelta {
                best_changed,
                changed,
            };
            assert_eq!(delta.has_changes(), expected, "{desc}");
        }
    }

    /// Regression test: when a better path (lower bgp_id) arrives after a worse one,
    /// best_changed must include the prefix so adj-rib-out gets updated.
    #[test]
    fn test_best_changed_detects_better_path_from_second_peer() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let prefix = create_test_prefix();

        // Peer with higher bgp_id (worse) sends first
        let peer_high = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        let bgp_id_high = Ipv4Addr::new(127, 0, 0, 4);
        let path_high = create_test_path(peer_high, bgp_id_high);

        let delta1 = loc_rib.apply_peer_update(
            peer_high,
            &[PendingRoute::Announce(RoutePath {
                key: RouteKey::Prefix(prefix),
                path: path_high,
            })],
            |_prefix, _path| true,
        );
        assert!(
            delta1.best_changed.contains(&RouteKey::Prefix(prefix)),
            "first path should trigger best_changed"
        );

        // Peer with lower bgp_id (better) sends second
        let peer_low = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let bgp_id_low = Ipv4Addr::new(127, 0, 0, 1);
        let path_low = create_test_path(peer_low, bgp_id_low);

        let delta2 = loc_rib.apply_peer_update(
            peer_low,
            &[PendingRoute::Announce(RoutePath {
                key: RouteKey::Prefix(prefix),
                path: path_low,
            })],
            |_prefix, _path| true,
        );
        assert!(
            delta2.best_changed.contains(&RouteKey::Prefix(prefix)),
            "better path from second peer must trigger best_changed"
        );

        // Verify the best path is from the lower bgp_id peer
        let best = loc_rib.get_best_path(&RouteKey::Prefix(prefix)).unwrap();
        assert_eq!(
            best.source().peer_ip(),
            Some(peer_low),
            "best path should be from peer with lower bgp_id"
        );
    }

    #[test]
    fn test_apply_llgr() {
        use crate::bgp::community;

        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let peer_ip = test_peer_ip();
        let prefix = create_test_prefix_n(1);
        let prefix_no_llgr = create_test_prefix_n(2);
        let afi_safi = AfiSafi::new(Afi::Ipv4, Safi::Unicast);

        loc_rib.upsert_path(
            RouteKey::Prefix(prefix),
            create_test_path(peer_ip, test_bgp_id()),
        );
        loc_rib.upsert_path(
            RouteKey::Prefix(prefix_no_llgr),
            create_test_path_with(peer_ip, test_bgp_id(), |p| {
                p.attrs.communities.push(community::NO_LLGR);
            }),
        );
        loc_rib.mark_peer_routes_stale(peer_ip, afi_safi);

        let delta = loc_rib.apply_llgr(peer_ip, &[afi_safi]);
        assert!(delta.has_changes());

        // Clean route tagged with LLGR_STALE
        let path = loc_rib.get_best_path(&RouteKey::Prefix(prefix)).unwrap();
        assert!(path.attrs.communities.contains(&community::LLGR_STALE));

        // NO_LLGR route removed
        assert!(loc_rib
            .get_best_path(&RouteKey::Prefix(prefix_no_llgr))
            .is_none());
    }

    #[test]
    fn test_announce_then_withdraw_same_path() {
        let mut loc_rib = LocRib::new();
        let peer_ip = test_peer_ip();
        let prefix = create_test_prefix();
        let path = create_test_path(peer_ip, test_bgp_id());
        let remote_path_id = path.remote_path_id;

        let routes = vec![
            PendingRoute::Announce(RoutePath {
                key: RouteKey::Prefix(prefix),
                path: path.clone(),
            }),
            PendingRoute::Withdraw((RouteKey::Prefix(prefix), remote_path_id)),
        ];

        loc_rib.apply_peer_update(peer_ip, &routes, |_, _| true);

        assert!(
            loc_rib.get_best_path(&RouteKey::Prefix(prefix)).is_none(),
            "path should be gone: withdraw after announce must win"
        );
    }

    #[test]
    fn test_route_delta_extend() {
        let net1 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        });
        let net2 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 1, 0),
            prefix_length: 24,
        });

        let key1 = RouteKey::Prefix(net1);
        let key2 = RouteKey::Prefix(net2);

        let mut delta1 = RouteDelta {
            best_changed: vec![key1.clone()],
            changed: vec![key1.clone()],
        };
        let delta2 = RouteDelta {
            best_changed: vec![key2.clone()],
            changed: vec![key2.clone()],
        };

        delta1.extend(delta2);

        assert_eq!(delta1.best_changed, vec![key1.clone(), key2.clone()]);
        assert_eq!(delta1.changed, vec![key1, key2]);
    }

    fn test_ls_nlri(router_id: u8) -> LsNlri {
        use crate::bgp::bgpls_nlri::{
            build_ls_nlri, LsDescriptors, LsNlriType, LsProtocolId, NodeDescriptor,
        };

        build_ls_nlri(
            LsNlriType::Node,
            LsProtocolId::IsIsL1,
            0,
            LsDescriptors::Node {
                local_node: NodeDescriptor {
                    igp_router_id: Some(vec![router_id]),
                    ..NodeDescriptor::default()
                },
            },
        )
    }

    fn ls_key(nlri: LsNlri) -> RouteKey {
        RouteKey::LinkState(nlri)
    }

    #[test]
    fn test_upsert_ls_path() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let nlri = test_ls_nlri(1);
        let key = ls_key(nlri.clone());
        let path = create_test_path(test_peer_ip(), test_bgp_id());

        loc_rib.upsert_path(key.clone(), path);

        assert_eq!(loc_rib.get_routes_afi(Afi::LinkState).len(), 1);
        let best = loc_rib.get_best_path(&key);
        assert!(best.is_some());
        assert_eq!(best.unwrap().local_path_id, Some(1));
    }

    #[test]
    fn test_ls_best_path_selection() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let key = ls_key(test_ls_nlri(1));

        let path_low = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.attrs.local_pref = Some(50);
        });
        let path_high = create_test_path_with(test_peer_ip2(), test_bgp_id2(), |p| {
            p.attrs.local_pref = Some(200);
        });

        loc_rib.upsert_path(key.clone(), path_low);
        loc_rib.upsert_path(key.clone(), path_high);

        let best = loc_rib.get_best_path(&key).unwrap();
        assert_eq!(best.local_pref(), Some(200));
        assert_eq!(loc_rib.get_all_paths(&key).len(), 2);
    }

    #[test]
    fn test_withdraw_ls_route() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let key = ls_key(test_ls_nlri(1));
        let path = create_test_path(test_peer_ip(), test_bgp_id());

        loc_rib.upsert_path(key.clone(), path);
        assert_eq!(loc_rib.get_routes_afi(Afi::LinkState).len(), 1);

        let removed = loc_rib.remove_peer_path(&key, test_peer_ip(), None);
        assert!(removed);
        assert_eq!(loc_rib.get_routes_afi(Afi::LinkState).len(), 0);
        assert!(loc_rib.get_best_path(&key).is_none());
    }

    #[test]
    fn test_replace_ls_route() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let key = ls_key(test_ls_nlri(1));

        let path1 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.attrs.med = Some(10);
        });
        loc_rib.upsert_path(key.clone(), path1);

        let path2 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.attrs.med = Some(20);
        });
        loc_rib.upsert_path(key.clone(), path2);

        assert_eq!(loc_rib.get_routes_afi(Afi::LinkState).len(), 1);
        let best = loc_rib.get_best_path(&key).unwrap();
        assert_eq!(best.med(), Some(20));
    }

    #[test]
    fn test_remove_ls_routes_from_peer() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let key1 = ls_key(test_ls_nlri(1));
        let key2 = ls_key(test_ls_nlri(2));

        loc_rib.upsert_path(
            key1.clone(),
            create_test_path(test_peer_ip(), test_bgp_id()),
        );
        loc_rib.upsert_path(
            key2.clone(),
            create_test_path(test_peer_ip2(), test_bgp_id2()),
        );

        let delta = loc_rib.remove_routes_from_peer(test_peer_ip());

        assert_eq!(loc_rib.get_routes_afi(Afi::LinkState).len(), 1);
        assert!(loc_rib.get_best_path(&key1).is_none());
        assert!(loc_rib.get_best_path(&key2).is_some());
        assert!(delta.best_changed.contains(&key1));
        assert!(delta.changed.contains(&key1));
    }

    #[test]
    fn test_ls_different_nlri_key() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let key1 = ls_key(test_ls_nlri(1));
        let key2 = ls_key(test_ls_nlri(2));

        loc_rib.upsert_path(
            key1.clone(),
            create_test_path(test_peer_ip(), test_bgp_id()),
        );
        loc_rib.upsert_path(
            key2.clone(),
            create_test_path(test_peer_ip(), test_bgp_id()),
        );

        assert_eq!(loc_rib.get_routes_afi(Afi::LinkState).len(), 2);
        assert!(loc_rib.get_best_path(&key1).is_some());
        assert!(loc_rib.get_best_path(&key2).is_some());
    }

    #[test]
    fn test_apply_peer_update_ls_route() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let key = ls_key(test_ls_nlri(1));
        let path = create_test_path(test_peer_ip(), test_bgp_id());

        let routes = vec![PendingRoute::Announce(RoutePath {
            key: key.clone(),
            path,
        })];
        let delta = loc_rib.apply_peer_update(test_peer_ip(), &routes, |_key, _path| true);

        assert!(loc_rib.get_best_path(&key).is_some());
        assert!(delta.best_changed.contains(&key));
        assert!(delta.changed.contains(&key));
    }

    #[test]
    fn test_apply_peer_update_ls_withdrawal() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let key = ls_key(test_ls_nlri(1));
        let path = create_test_path(test_peer_ip(), test_bgp_id());

        // Insert first
        let routes = vec![PendingRoute::Announce(RoutePath {
            key: key.clone(),
            path,
        })];
        loc_rib.apply_peer_update(test_peer_ip(), &routes, |_key, _path| true);
        assert!(loc_rib.get_best_path(&key).is_some());

        // Withdraw
        let routes = vec![PendingRoute::Withdraw((key.clone(), None))];
        let delta = loc_rib.apply_peer_update(test_peer_ip(), &routes, |_key, _path| true);

        assert!(loc_rib.get_best_path(&key).is_none());
        assert!(delta.best_changed.contains(&key));
    }

    #[test]
    fn test_get_paths_ls() {
        let mut loc_rib = LocRib::with_path_ids(FakeAllocator::new());
        let key1 = ls_key(test_ls_nlri(1));
        let key2 = ls_key(test_ls_nlri(2));

        loc_rib.upsert_path(
            key1.clone(),
            create_test_path(test_peer_ip(), test_bgp_id()),
        );
        loc_rib.upsert_path(
            key2.clone(),
            create_test_path(test_peer_ip(), test_bgp_id()),
        );

        let paths = loc_rib.get_paths(Afi::LinkState, false);
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().any(|rp| rp.key == key1));
        assert!(paths.iter().any(|rp| rp.key == key2));
    }
}
