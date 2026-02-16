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
use crate::rib::{Path, PrefixPath, Route};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Deferred adj-rib-out mutations collected during immutable peer iteration.
pub struct PendingRibUpdate {
    pub peer_addr: IpAddr,
    /// Routes successfully sent (post-policy).
    pub sent: Vec<PrefixPath>,
    /// Prefixes fully withdrawn (non-ADD-PATH).
    pub withdrawn_prefixes: Vec<IpNetwork>,
    /// Per-path-id withdrawals (ADD-PATH).
    pub withdrawn_path_ids: Vec<(IpNetwork, u32)>,
}

/// Adj-RIB-Out: Per-peer output routing table
///
/// Tracks routes actually exported to a specific BGP peer.
/// Key: (prefix, local_path_id), Value: the exported path (post-policy).
pub struct AdjRibOut {
    routes: HashMap<(IpNetwork, u32), Arc<Path>>,
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
        self.routes.insert((prefix, path_id), path);
    }

    /// Remove all routes for a given prefix (used for non-ADD-PATH withdrawals).
    pub fn remove_prefix(&mut self, prefix: &IpNetwork) {
        self.routes.retain(|(p, _), _| p != prefix);
    }

    /// Remove a specific path by prefix and path_id (used for ADD-PATH withdrawals).
    pub fn remove_path(&mut self, prefix: &IpNetwork, path_id: u32) {
        self.routes.remove(&(*prefix, path_id));
    }

    /// Replace all entries for a given AFI with newly sent routes.
    /// Removes existing entries matching the AFI, then inserts the new ones.
    pub fn replace_afi(&mut self, afi: Afi, sent: Vec<PrefixPath>) {
        let is_target_afi = |prefix: &IpNetwork| match afi {
            Afi::Ipv4 => matches!(prefix, IpNetwork::V4(_)),
            Afi::Ipv6 => matches!(prefix, IpNetwork::V6(_)),
        };
        self.routes.retain(|(prefix, _), _| !is_target_afi(prefix));
        for (prefix, path) in sent {
            self.insert(prefix, path);
        }
    }

    /// Clear all routes (used on peer disconnect).
    pub fn clear(&mut self) {
        self.routes.clear();
    }

    /// Get all path_ids for a given prefix.
    pub fn path_ids_for_prefix(&self, prefix: &IpNetwork) -> Vec<u32> {
        self.routes
            .keys()
            .filter(|(p, _)| p == prefix)
            .map(|(_, pid)| *pid)
            .collect()
    }

    /// Check if any route exists for the given prefix.
    pub fn has_prefix(&self, prefix: &IpNetwork) -> bool {
        self.routes.keys().any(|(p, _)| p == prefix)
    }

    /// Apply a batch of deferred updates: withdrawals then announcements.
    pub fn apply_pending(&mut self, update: PendingRibUpdate) {
        for prefix in &update.withdrawn_prefixes {
            self.remove_prefix(prefix);
        }
        for (prefix, pid) in &update.withdrawn_path_ids {
            self.remove_path(prefix, *pid);
        }
        for (prefix, path) in update.sent {
            self.insert(prefix, path);
        }
    }

    /// Get all routes grouped by prefix, suitable for gRPC responses.
    pub fn get_routes(&self) -> Vec<Route> {
        let mut routes_map: HashMap<IpNetwork, Vec<Arc<Path>>> = HashMap::new();
        for ((prefix, _path_id), path) in &self.routes {
            routes_map
                .entry(*prefix)
                .or_default()
                .push(Arc::clone(path));
        }
        routes_map
            .into_iter()
            .map(|(prefix, paths)| Route { prefix, paths })
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
    fn test_replace_afi() {
        let mut rib = AdjRibOut::new();
        let prefix_v4_a = prefix_v4("10.0.0.0/24");
        let prefix_v4_b = prefix_v4("10.0.1.0/24");
        rib.insert(prefix_v4_a, make_path(1));
        rib.insert(prefix_v4_b, make_path(2));

        // Replace with a single new route
        let new_path = make_path(3);
        let new_prefix = prefix_v4("192.168.0.0/24");
        rib.replace_afi(Afi::Ipv4, vec![(new_prefix, new_path)]);

        assert!(!rib.has_prefix(&prefix_v4_a));
        assert!(!rib.has_prefix(&prefix_v4_b));
        assert!(rib.has_prefix(&new_prefix));
    }
}
