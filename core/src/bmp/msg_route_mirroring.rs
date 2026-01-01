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
use super::utils::{PeerDistinguisher, PeerHeader};
use std::net::IpAddr;
use std::time::SystemTime;

/// Route Mirroring TLV
#[derive(Clone, Debug)]
pub struct MirroringTlv {
    pub info_code: u16,
    pub info_value: Vec<u8>,
}

impl MirroringTlv {
    pub const BGP_MESSAGE: u16 = 0;
    pub const INFORMATION: u16 = 1;

    pub fn new_bgp_message(bgp_pdu: Vec<u8>) -> Self {
        Self {
            info_code: Self::BGP_MESSAGE,
            info_value: bgp_pdu,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.info_code.to_be_bytes());
        bytes.extend_from_slice(&(self.info_value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.info_value);
        bytes
    }
}

/// Route Mirroring message - for debugging/monitoring rejected or policy-filtered messages
#[derive(Clone, Debug)]
pub struct RouteMirroringMessage {
    peer_header: PeerHeader,
    tlvs: Vec<MirroringTlv>,
}

impl RouteMirroringMessage {
    pub fn new(
        peer_distinguisher: PeerDistinguisher,
        peer_address: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        timestamp: SystemTime,
        tlvs: Vec<MirroringTlv>,
    ) -> Self {
        Self {
            peer_header: PeerHeader::new(
                peer_distinguisher,
                peer_address,
                peer_as,
                peer_bgp_id,
                false,
                false,
                timestamp,
            ),
            tlvs,
        }
    }
}

impl Message for RouteMirroringMessage {
    fn message_type(&self) -> MessageType {
        MessageType::RouteMirroring
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Per-Peer Header (42 bytes)
        bytes.extend_from_slice(&self.peer_header.to_bytes());

        // TLVs
        for tlv in &self.tlvs {
            bytes.extend_from_slice(&tlv.to_bytes());
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_route_mirroring_message() {
        use crate::bmp::utils::PeerDistinguisher;

        let tlv = MirroringTlv::new_bgp_message(vec![0xff; 23]);
        let msg = RouteMirroringMessage::new(
            PeerDistinguisher::Global,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            SystemTime::now(),
            vec![tlv],
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::RouteMirroring.as_u8());
    }
}
