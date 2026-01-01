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

use super::msg::{Message, MessageType};
use super::types::PeerHeader;
use std::net::IpAddr;

/// Route Monitoring message - carries BGP UPDATE messages
#[derive(Clone, Debug)]
pub struct RouteMonitoringMessage {
    peer_header: PeerHeader,
    bgp_update: Vec<u8>, // Serialized BGP UPDATE message
}

impl RouteMonitoringMessage {
    pub fn new(peer_address: IpAddr, peer_as: u32, peer_bgp_id: u32, bgp_update: Vec<u8>) -> Self {
        Self {
            peer_header: PeerHeader::new(peer_address, peer_as, peer_bgp_id),
            bgp_update,
        }
    }
}

impl Message for RouteMonitoringMessage {
    fn message_type(&self) -> MessageType {
        MessageType::RouteMonitoring
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Per-Peer Header (42 bytes)
        bytes.extend_from_slice(&self.peer_header.to_bytes());

        // BGP UPDATE Message
        bytes.extend_from_slice(&self.bgp_update);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_route_monitoring_message() {
        let msg = RouteMonitoringMessage::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            vec![0xff; 23], // Mock UPDATE
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::RouteMonitoring.as_u8());
    }
}
