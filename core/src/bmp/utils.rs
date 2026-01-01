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

use std::net::IpAddr;

/// Encode IP address to 16-byte format (IPv4-mapped for IPv4)
pub(super) fn encode_ip_address(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(ipv4) => {
            let mut bytes = [0u8; 16];
            bytes[12..16].copy_from_slice(&ipv4.octets());
            bytes
        }
        IpAddr::V6(ipv6) => ipv6.octets(),
    }
}
