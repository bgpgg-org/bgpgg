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

pub mod bgp;
pub mod bmp;
pub mod config;
pub mod grpc;
pub mod log;
pub mod net;
pub mod peer;
pub mod policy;
pub mod rib;
pub mod server;
pub mod server_ops;
pub mod types;

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, NextHopAddr, Origin};
    use crate::net::{IpNetwork, Ipv4Net};
    use crate::rib::path_id::PathIdAllocator;
    use crate::rib::{Path, PathAttrs, RouteSource};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    /// Simple sequential path ID allocator for tests. Starts at 1, increments.
    /// Free is a no-op — tests don't need ID reuse.
    pub struct SeqPathIdAllocator {
        next: u32,
    }

    impl SeqPathIdAllocator {
        pub fn new() -> Self {
            Self { next: 1 }
        }
    }

    impl PathIdAllocator for SeqPathIdAllocator {
        fn alloc(&mut self) -> u32 {
            let id = self.next;
            self.next += 1;
            id
        }
        fn free(&mut self, _id: u32) {}
        fn free_all(&mut self, _ids: Vec<u32>) {}
    }

    pub fn create_test_path(peer_ip: IpAddr, bgp_id: Ipv4Addr) -> Arc<Path> {
        Arc::new(Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            attrs: PathAttrs {
                origin: Origin::IGP,
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![100, 200],
                }],
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                source: RouteSource::Ebgp { peer_ip, bgp_id },
                local_pref: Some(100),
                med: Some(0),
                atomic_aggregate: false,
                aggregator: None,
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
            },
        })
    }

    pub fn create_test_path_with(
        peer_ip: IpAddr,
        bgp_id: Ipv4Addr,
        f: impl FnOnce(&mut Path),
    ) -> Arc<Path> {
        let mut path = Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            attrs: PathAttrs {
                origin: Origin::IGP,
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![100, 200],
                }],
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                source: RouteSource::Ebgp { peer_ip, bgp_id },
                local_pref: Some(100),
                med: Some(0),
                atomic_aggregate: false,
                aggregator: None,
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
            },
        };
        f(&mut path);
        Arc::new(path)
    }

    pub fn create_test_prefix() -> IpNetwork {
        IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        })
    }

    pub fn create_test_prefix_n(i: u8) -> IpNetwork {
        IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, i, 0),
            prefix_length: 24,
        })
    }
}
