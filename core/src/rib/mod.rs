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

//! Routing Information Base (RIB) module
//!
//! This module implements BGP's RIB components:
//! - Adj-RIB-In: Per-peer input tables storing routes received from peers (owned by Peer)
//! - Loc-RIB: Local routing table containing best paths (owned by BgpServer)
//! - Adj-RIB-Out: Computed dynamically on-demand (not stored)

mod path;
pub mod rib_in;
pub mod rib_loc;
mod types;

// Re-exports
pub use path::Path;
pub use types::{Route, RouteSource};

#[cfg(test)]
mod test_helpers {
    use super::*;
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin};
    use crate::bgp::utils::IpNetwork;
    use std::net::Ipv4Addr;

    pub(super) fn create_test_path(peer_ip: String) -> Path {
        Path {
            origin: Origin::IGP,
            as_path: vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 2,
                asn_list: vec![100, 200],
            }],
            next_hop: Ipv4Addr::new(192, 0, 2, 1),
            source: RouteSource::Ebgp(peer_ip),
            local_pref: Some(100),
            med: Some(0),
        }
    }

    pub(super) fn create_test_prefix() -> IpNetwork {
        IpNetwork::V4(crate::bgp::utils::Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        })
    }
}
