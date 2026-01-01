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

/// Initiation message Information TLV types
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub(super) enum InitiationType {
    String = 0,
    SysDescr = 1,
    SysName = 2,
}

/// Termination message Information TLV types
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub(super) enum TerminationType {
    String = 0,
    Reason = 1,
}

/// Peer Up message Information TLV types (RFC 7854 Section 4.10)
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub(super) enum PeerUpInfoType {
    String = 0, // Only type defined for Peer Up messages
}

/// Information TLV used in Initiation and Termination messages (internal)
#[derive(Clone, Debug)]
pub(super) struct InformationTlv {
    info_type: u16,
    info_value: Vec<u8>,
}

impl InformationTlv {
    pub(super) fn new(info_type: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            info_type,
            info_value: value.into(),
        }
    }

    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.info_type.to_be_bytes());
        bytes.extend_from_slice(&(self.info_value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.info_value);
        bytes
    }
}

/// Per-Peer Header used in most BMP messages (internal encoding detail)
#[derive(Clone, Debug)]
pub(super) struct PeerHeader {
    pub peer_type: u8,
    pub peer_flags: u8,
    pub peer_distinguisher: u64,
    pub peer_address: IpAddr,
    pub peer_as: u32,
    pub peer_bgp_id: u32,
    pub timestamp_seconds: u32,
    pub timestamp_microseconds: u32,
}

impl PeerHeader {
    const PEER_TYPE_GLOBAL: u8 = 0;
    const FLAG_V6: u8 = 0b10000000;

    pub(super) fn new(peer_address: IpAddr, peer_as: u32, peer_bgp_id: u32) -> Self {
        let peer_flags = match peer_address {
            IpAddr::V6(_) => Self::FLAG_V6,
            IpAddr::V4(_) => 0,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        Self {
            peer_type: Self::PEER_TYPE_GLOBAL,
            peer_flags,
            peer_distinguisher: 0,
            peer_address,
            peer_as,
            peer_bgp_id,
            timestamp_seconds: now.as_secs() as u32,
            timestamp_microseconds: now.subsec_micros(),
        }
    }

    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Peer Type (1 byte)
        bytes.push(self.peer_type);

        // Peer Flags (1 byte)
        bytes.push(self.peer_flags);

        // Peer Distinguisher (8 bytes)
        bytes.extend_from_slice(&self.peer_distinguisher.to_be_bytes());

        // Peer Address (16 bytes, IPv4-mapped if IPv4)
        match self.peer_address {
            IpAddr::V4(addr) => {
                bytes.extend_from_slice(&[0u8; 12]); // 12 zeros
                bytes.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                bytes.extend_from_slice(&addr.octets());
            }
        }

        // Peer AS (4 bytes)
        bytes.extend_from_slice(&self.peer_as.to_be_bytes());

        // Peer BGP ID (4 bytes)
        bytes.extend_from_slice(&self.peer_bgp_id.to_be_bytes());

        // Timestamp (4 + 4 bytes)
        bytes.extend_from_slice(&self.timestamp_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp_microseconds.to_be_bytes());

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_peer_header_ipv4() {
        let header = PeerHeader::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 65001, 0x01010101);
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), 42); // Per-Peer Header is 42 bytes
        assert_eq!(bytes[0], 0); // PEER_TYPE_GLOBAL
        assert_eq!(bytes[1] & 0b10000000, 0); // Not IPv6
    }

    #[test]
    fn test_peer_header_ipv6() {
        let header = PeerHeader::new(
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            65001,
            0x01010101,
        );
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), 42);
        assert_eq!(bytes[1] & 0b10000000, 0b10000000); // Is IPv6
    }
}
