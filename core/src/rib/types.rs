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

use crate::bgp::msg_update::Origin;
use crate::bgp::utils::IpNetwork;
use std::net::{Ipv4Addr, SocketAddr};

/// Source of a route
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RouteSource {
    /// Route learned from a BGP peer
    Peer(SocketAddr),
    /// Route originated locally by this router
    Local,
}

/// Represents a BGP path with all its attributes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Path {
    pub origin: Origin,
    pub as_path: Vec<u16>,
    pub next_hop: Ipv4Addr,
    pub source: RouteSource,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
}

/// Represents a route with one or more paths to a prefix
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Route {
    pub prefix: IpNetwork,
    pub paths: Vec<Path>,
}
