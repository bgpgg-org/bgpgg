// Copyright 2026 bgpgg Authors
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

use crate::bgp::community;
use crate::rib::path_id::PathIdAllocator;
use crate::rib::{Path, Route, RouteDelta};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;

/// Defines how stale routes should be processed.
pub(crate) enum StaleStrategy {
    /// GR sweep: remove all stale paths from the peer.
    Sweep,
    /// LLGR transition: remove NO_LLGR paths, tag rest with LLGR_STALE.
    TransitionToLlgr,
}

impl StaleStrategy {
    /// Apply the strategy to a stale path. Returns true if the path is retained.
    fn apply(&self, path: &mut Arc<Path>) -> bool {
        match self {
            StaleStrategy::Sweep => false,
            StaleStrategy::TransitionToLlgr => {
                if path.attrs.communities.contains(&community::NO_LLGR) {
                    return false;
                }
                let mutable = Arc::make_mut(path);
                if !mutable.attrs.communities.contains(&community::LLGR_STALE) {
                    mutable.attrs.communities.push(community::LLGR_STALE);
                }
                true
            }
        }
    }
}

pub(crate) fn mark_stale_in_table<K: Eq + Hash>(
    table: &mut HashMap<K, Route>,
    peer_ip: IpAddr,
) -> usize {
    let mut count = 0;
    for route in table.values_mut() {
        for path in &mut route.paths {
            if path.is_from_peer(peer_ip) {
                Arc::make_mut(path).stale = true;
                count += 1;
            }
        }
    }
    count
}

fn peer_stale_keys<K: Eq + Hash + Copy>(table: &HashMap<K, Route>, peer_ip: IpAddr) -> Vec<K> {
    table
        .iter()
        .filter(|(_, r)| r.paths.iter().any(|p| p.is_from_peer(peer_ip) && p.stale))
        .map(|(k, _)| *k)
        .collect()
}

fn best_path_changed(old: Option<&Arc<Path>>, new: Option<&Arc<Path>>) -> bool {
    match (old, new) {
        (Some(old), Some(new)) => !Arc::ptr_eq(old, new),
        (None, None) => false,
        _ => true,
    }
}

pub(crate) fn handle_stale_routes<K: Eq + Hash + Copy, A: PathIdAllocator>(
    table: &mut HashMap<K, Route>,
    peer_ip: IpAddr,
    path_ids: &mut A,
    strategy: &StaleStrategy,
) -> RouteDelta {
    let keys = peer_stale_keys(table, peer_ip);
    let mut delta = RouteDelta::new();

    for key in keys {
        let Some(route) = table.get_mut(&key) else {
            continue;
        };
        let old_best = route.paths.first().map(Arc::clone);
        let prefix = route.prefix;

        let mut kept = Vec::with_capacity(route.paths.len());
        for mut path in route.paths.drain(..) {
            if path.is_from_peer(peer_ip) && path.stale && !strategy.apply(&mut path) {
                if let Some(id) = path.local_path_id {
                    path_ids.free(id);
                }
                continue;
            }
            kept.push(path);
        }
        route.paths = kept;
        route.paths.sort_by(|a, b| b.best_path_cmp(a));

        if route.paths.is_empty() {
            table.remove(&key);
        }

        delta.changed.push(prefix);
        if best_path_changed(
            old_best.as_ref(),
            table.get(&key).and_then(|r| r.paths.first()),
        ) {
            delta.best_changed.push(prefix);
        }
    }

    delta
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::community;
    use crate::net::{IpNetwork, Ipv4Net};
    use crate::test_helpers::*;
    use std::net::Ipv4Addr;

    fn peer_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    }

    fn bgp_id() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn other_peer_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))
    }

    fn other_bgp_id() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 2)
    }

    fn prefix(last: u8) -> (Ipv4Net, IpNetwork) {
        let net = Ipv4Net {
            address: Ipv4Addr::new(10, 0, last, 0),
            prefix_length: 24,
        };
        (net, IpNetwork::V4(net))
    }

    fn make_table(entries: Vec<(Ipv4Net, IpNetwork, Vec<Arc<Path>>)>) -> HashMap<Ipv4Net, Route> {
        let mut table = HashMap::new();
        for (key, ip_prefix, paths) in entries {
            table.insert(
                key,
                Route {
                    prefix: ip_prefix,
                    paths,
                },
            );
        }
        table
    }

    #[test]
    fn test_mark_stale() {
        let (key, ip_prefix) = prefix(1);
        let mut table = make_table(vec![(
            key,
            ip_prefix,
            vec![
                create_test_path(peer_ip(), bgp_id()),
                create_test_path(other_peer_ip(), other_bgp_id()),
            ],
        )]);

        let count = mark_stale_in_table(&mut table, peer_ip());
        assert_eq!(count, 1);
        assert!(table[&key].paths[0].stale);
        assert!(!table[&key].paths[1].stale);
    }

    #[test]
    fn test_sweep() {
        let (key_mixed, prefix_mixed) = prefix(1);
        let (key_only_stale, prefix_only_stale) = prefix(2);
        let (key_not_stale, prefix_not_stale) = prefix(3);
        let mut alloc = FakeAllocator::new();
        let mut table = make_table(vec![
            // Stale + non-stale path -> stale removed, other peer's path kept
            (
                key_mixed,
                prefix_mixed,
                vec![
                    create_test_path_with(peer_ip(), bgp_id(), |p| {
                        p.stale = true;
                        p.local_path_id = Some(42);
                    }),
                    create_test_path(other_peer_ip(), other_bgp_id()),
                ],
            ),
            // Only stale path -> route removed entirely
            (
                key_only_stale,
                prefix_only_stale,
                vec![create_test_path_with(peer_ip(), bgp_id(), |p| {
                    p.stale = true;
                    p.local_path_id = Some(43);
                })],
            ),
            // Non-stale path -> untouched
            (
                key_not_stale,
                prefix_not_stale,
                vec![create_test_path(peer_ip(), bgp_id())],
            ),
        ]);

        let delta = handle_stale_routes(&mut table, peer_ip(), &mut alloc, &StaleStrategy::Sweep);

        // Mixed: stale path removed, other peer's path kept
        assert_eq!(table[&key_mixed].paths.len(), 1);
        assert!(table[&key_mixed].paths[0].is_from_peer(other_peer_ip()));
        assert!(alloc.freed.contains(&42));

        // Only stale: route removed entirely
        assert!(!table.contains_key(&key_only_stale));
        assert!(alloc.freed.contains(&43));

        // Non-stale: untouched
        assert_eq!(table[&key_not_stale].paths.len(), 1);

        assert!(delta.changed.contains(&prefix_mixed));
        assert!(delta.changed.contains(&prefix_only_stale));
        assert!(!delta.changed.contains(&prefix_not_stale));
    }

    #[test]
    fn test_llgr_transition() {
        let (key_clean, prefix_clean) = prefix(1);
        let (key_no_llgr, prefix_no_llgr) = prefix(2);
        let (key_already_tagged, prefix_already_tagged) = prefix(3);
        let mut alloc = FakeAllocator::new();
        let mut table = make_table(vec![
            // Stale path -> should be tagged with LLGR_STALE
            (
                key_clean,
                prefix_clean,
                vec![create_test_path_with(peer_ip(), bgp_id(), |p| {
                    p.stale = true;
                    p.local_path_id = Some(1);
                })],
            ),
            // Stale path with NO_LLGR -> should be removed
            (
                key_no_llgr,
                prefix_no_llgr,
                vec![create_test_path_with(peer_ip(), bgp_id(), |p| {
                    p.stale = true;
                    p.local_path_id = Some(2);
                    p.attrs.communities.push(community::NO_LLGR);
                })],
            ),
            // Already tagged with LLGR_STALE -> should not double-tag
            (
                key_already_tagged,
                prefix_already_tagged,
                vec![create_test_path_with(peer_ip(), bgp_id(), |p| {
                    p.stale = true;
                    p.local_path_id = Some(3);
                    p.attrs.communities.push(community::LLGR_STALE);
                })],
            ),
        ]);

        let delta = handle_stale_routes(
            &mut table,
            peer_ip(),
            &mut alloc,
            &StaleStrategy::TransitionToLlgr,
        );

        // Clean path tagged with LLGR_STALE
        assert!(table[&key_clean].paths[0]
            .attrs
            .communities
            .contains(&community::LLGR_STALE));

        // NO_LLGR path removed, id freed
        assert!(!table.contains_key(&key_no_llgr));
        assert!(alloc.freed.contains(&2));

        // Already-tagged path: exactly one LLGR_STALE, not doubled
        let communities = &table[&key_already_tagged].paths[0].attrs.communities;
        assert_eq!(
            communities
                .iter()
                .filter(|c| **c == community::LLGR_STALE)
                .count(),
            1
        );

        // All prefixes in changed
        assert!(delta.changed.contains(&prefix_clean));
        assert!(delta.changed.contains(&prefix_no_llgr));
        assert!(delta.changed.contains(&prefix_already_tagged));
    }
}
