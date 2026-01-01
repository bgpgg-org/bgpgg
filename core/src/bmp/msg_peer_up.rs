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
use super::types::{InformationTlv, PeerHeader, PeerUpInfoType};
use crate::bgp::msg::Message as BgpMessage;
use crate::bgp::msg_open::OpenMessage;
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct PeerUpMessage {
    peer_header: PeerHeader,
    local_address: IpAddr,
    local_port: u16,
    remote_port: u16,
    sent_open_message: OpenMessage,
    received_open_message: OpenMessage,
    information: Vec<InformationTlv>, // Optional string TLVs (RFC 7854 Section 4.10)
}

impl PeerUpMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer_address: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        local_address: IpAddr,
        local_port: u16,
        remote_port: u16,
        sent_open: OpenMessage,
        received_open: OpenMessage,
        info_strings: &[&str],
    ) -> Self {
        let information = info_strings
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| InformationTlv::new(PeerUpInfoType::String as u16, s.as_bytes().to_vec()))
            .collect();

        Self {
            peer_header: PeerHeader::new(peer_address, peer_as, peer_bgp_id),
            local_address,
            local_port,
            remote_port,
            sent_open_message: sent_open,
            received_open_message: received_open,
            information,
        }
    }
}

impl Message for PeerUpMessage {
    fn message_type(&self) -> MessageType {
        MessageType::PeerUpNotification
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Per-Peer Header (42 bytes)
        bytes.extend_from_slice(&self.peer_header.to_bytes());

        // Local Address (16 bytes, IPv4-mapped if IPv4)
        match self.local_address {
            IpAddr::V4(addr) => {
                bytes.extend_from_slice(&[0u8; 12]);
                bytes.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                bytes.extend_from_slice(&addr.octets());
            }
        }

        // Local Port (2 bytes)
        bytes.extend_from_slice(&self.local_port.to_be_bytes());

        // Remote Port (2 bytes)
        bytes.extend_from_slice(&self.remote_port.to_be_bytes());

        // Sent OPEN Message
        bytes.extend_from_slice(&self.sent_open_message.serialize());

        // Received OPEN Message
        bytes.extend_from_slice(&self.received_open_message.serialize());

        // Information (optional TLVs)
        for tlv in &self.information {
            bytes.extend_from_slice(&tlv.to_bytes());
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_peer_up_message() {
        use crate::bgp::msg_open::OpenMessage;

        let sent_open = OpenMessage::new(65000, 180, 0x0a000001);
        let received_open = OpenMessage::new(65001, 180, 0x01010101);

        let msg = PeerUpMessage::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            179,
            12345,
            sent_open,
            received_open,
            &[], // No info strings
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::PeerUpNotification.as_u8());
    }

    #[test]
    fn test_peer_up_message_with_info() {
        use crate::bgp::msg_open::OpenMessage;

        let sent_open = OpenMessage::new(65000, 180, 0x0a000001);
        let received_open = OpenMessage::new(65001, 180, 0x01010101);

        let msg = PeerUpMessage::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            179,
            12345,
            sent_open,
            received_open,
            &["peer info", "extra context"],
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::PeerUpNotification.as_u8());
    }
}
