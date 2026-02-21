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

use crate::bgp::multiprotocol::Afi;
use crate::net::IpNetwork;
use crate::rib::{Path, Route};
use std::collections::HashMap;
use std::sync::Arc;

/// Adj-RIB-Out: Per-peer output routing table
///
/// Tracks routes actually exported to a specific BGP peer.
/// Keyed by prefix, then by local_path_id within each prefix.
pub struct AdjRibOut {
    routes: HashMap<IpNetwork, HashMap<u32, Arc<Path>>>,
}

impl AdjRibOut {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Insert a route into the adj-rib-out.
    /// The path must have a local_path_id assigned.
    pub fn insert(&mut self, prefix: IpNetwork, path: Arc<Path>) {
        let path_id = path.local_path_id.expect("loc-rib path must have ID");
        self.routes.entry(prefix).or_default().insert(path_id, path);
    }

    /// Remove all routes for a given prefix (used for non-ADD-PATH withdrawals).
    pub fn remove_prefix(&mut self, prefix: &IpNetwork) {
        self.routes.remove(prefix);
    }

    /// Replace all paths for a prefix with a single path. Used for non-ADD-PATH
    /// peers where only one path per prefix is allowed.
    pub fn replace(&mut self, prefix: IpNetwork, path: Arc<Path>) {
        self.remove_prefix(&prefix);
        self.insert(prefix, path);
    }

    /// Remove a specific path by prefix and path_id (used for ADD-PATH withdrawals).
    pub fn remove_path(&mut self, prefix: &IpNetwork, path_id: u32) {
        if let Some(paths) = self.routes.get_mut(prefix) {
            paths.remove(&path_id);
            if paths.is_empty() {
                self.routes.remove(prefix);
            }
        }
    }

    /// Remove all entries for a given AFI.
    pub fn clear_afi(&mut self, afi: Afi) {
        self.routes.retain(|prefix, _| match afi {
            Afi::Ipv4 => !matches!(prefix, IpNetwork::V4(_)),
            Afi::Ipv6 => !matches!(prefix, IpNetwork::V6(_)),
        });
    }

    /// Clear all routes (used on peer disconnect).
    pub fn clear(&mut self) {
        self.routes.clear();
    }

    /// Get all path_ids for a given prefix.
    pub fn path_ids_for_prefix(&self, prefix: &IpNetwork) -> Vec<u32> {
        self.routes
            .get(prefix)
            .map(|paths| paths.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Check if any route exists for the given prefix.
    pub fn has_prefix(&self, prefix: &IpNetwork) -> bool {
        self.routes.contains_key(prefix)
    }

    /// Get all routes grouped by prefix, suitable for gRPC responses.
    pub fn get_routes(&self) -> Vec<Route> {
        self.routes
            .iter()
            .map(|(prefix, paths)| Route {
                prefix: *prefix,
                paths: paths.values().cloned().collect(),
            })
            .collect()
    }
}

impl Default for AdjRibOut {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::create_test_path_with;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_path(path_id: u32) -> Arc<Path> {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let bgp_id = Ipv4Addr::new(1, 1, 1, 1);
        create_test_path_with(peer_ip, bgp_id, |path| {
            path.local_path_id = Some(path_id);
        })
    }

    fn prefix_v4(s: &str) -> IpNetwork {
        s.parse().unwrap()
    }

    #[test]
    fn test_insert_and_get_routes() {
        let mut rib = AdjRibOut::new();
        let prefix = prefix_v4("10.0.0.0/24");
        let path = make_path(1);

        rib.insert(prefix, path.clone());

        let routes = rib.get_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, prefix);
        assert_eq!(routes[0].paths.len(), 1);
    }

    #[test]
    fn test_remove_prefix() {
        let mut rib = AdjRibOut::new();
        let prefix = prefix_v4("10.0.0.0/24");
        rib.insert(prefix, make_path(1));
        rib.insert(prefix, make_path(2));

        assert!(rib.has_prefix(&prefix));
        rib.remove_prefix(&prefix);
        assert!(!rib.has_prefix(&prefix));
    }

    #[test]
    fn test_replace_clears_old_path_ids() {
        let mut rib = AdjRibOut::new();
        let prefix = prefix_v4("10.0.0.0/24");
        rib.insert(prefix, make_path(1));
        rib.insert(prefix, make_path(2));

        rib.replace(prefix, make_path(3));
        assert_eq!(rib.path_ids_for_prefix(&prefix), vec![3]);
    }

    #[test]
    fn test_remove_path() {
        let mut rib = AdjRibOut::new();
        let prefix = prefix_v4("10.0.0.0/24");
        rib.insert(prefix, make_path(1));
        rib.insert(prefix, make_path(2));

        rib.remove_path(&prefix, 1);
        let ids = rib.path_ids_for_prefix(&prefix);
        assert_eq!(ids, vec![2]);
    }

    #[test]
    fn test_path_ids_for_prefix() {
        let mut rib = AdjRibOut::new();
        let prefix_a = prefix_v4("10.0.0.0/24");
        let prefix_b = prefix_v4("10.0.1.0/24");
        rib.insert(prefix_a, make_path(1));
        rib.insert(prefix_a, make_path(2));
        rib.insert(prefix_b, make_path(3));

        let mut ids = rib.path_ids_for_prefix(&prefix_a);
        ids.sort();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn test_clear() {
        let mut rib = AdjRibOut::new();
        rib.insert(prefix_v4("10.0.0.0/24"), make_path(1));
        rib.insert(prefix_v4("10.0.1.0/24"), make_path(2));

        rib.clear();
        assert_eq!(rib.get_routes().len(), 0);
    }

    #[test]
    fn test_clear_afi() {
        let mut rib = AdjRibOut::new();
        let prefix_v4_a = prefix_v4("10.0.0.0/24");
        let prefix_v4_b = prefix_v4("10.0.1.0/24");
        rib.insert(prefix_v4_a, make_path(1));
        rib.insert(prefix_v4_b, make_path(2));

        rib.clear_afi(Afi::Ipv4);

        assert!(!rib.has_prefix(&prefix_v4_a));
        assert!(!rib.has_prefix(&prefix_v4_b));

        // Insert new route after clear
        let new_prefix = prefix_v4("192.168.0.0/24");
        rib.insert(new_prefix, make_path(3));
        assert!(rib.has_prefix(&new_prefix));
    }
}
