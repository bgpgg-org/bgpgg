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
pub mod config;
pub mod events;
pub mod fsm;
pub mod grpc;
pub mod log;
pub mod net;
pub mod peer;
pub mod policy;
pub mod propagate;
pub mod rib;
pub mod server;

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin};
    use crate::bgp::utils::{IpNetwork, Ipv4Net};
    use crate::rib::{Path, RouteSource};
    use std::net::{IpAddr, Ipv4Addr};

    pub fn create_test_path(peer_ip: IpAddr) -> Path {
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
            atomic_aggregate: false,
            unknown_attrs: vec![],
        }
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
