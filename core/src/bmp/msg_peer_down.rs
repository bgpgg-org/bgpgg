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

use super::msg::{BmpMessage, MessageType};
use super::peer_header::PeerHeader;

#[derive(Clone, Debug)]
pub enum PeerDownReason {
    LocalNotification(Vec<u8>),   // reason 1: local system sent NOTIFICATION
    LocalNoNotification,           // reason 2: local system closed, no NOTIFICATION
    RemoteNotification(Vec<u8>),   // reason 3: remote system sent NOTIFICATION
    RemoteNoNotification,          // reason 4: remote closed, no NOTIFICATION
    PeerDeConfigured,              // reason 5: peer de-configured
    LocalTlv(Vec<u8>),             // reason 6: local system closed with TLV
}

impl PeerDownReason {
    fn reason_code(&self) -> u8 {
        match self {
            PeerDownReason::LocalNotification(_) => 1,
            PeerDownReason::LocalNoNotification => 2,
            PeerDownReason::RemoteNotification(_) => 3,
            PeerDownReason::RemoteNoNotification => 4,
            PeerDownReason::PeerDeConfigured => 5,
            PeerDownReason::LocalTlv(_) => 6,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.reason_code()];
        match self {
            PeerDownReason::LocalNotification(notif)
            | PeerDownReason::RemoteNotification(notif)
            | PeerDownReason::LocalTlv(notif) => {
                bytes.extend_from_slice(notif);
            }
            _ => {}
        }
        bytes
    }
}

#[derive(Clone, Debug)]
pub struct PeerDownMessage {
    pub peer_header: PeerHeader,
    pub reason: PeerDownReason,
}

impl PeerDownMessage {
    pub fn new(peer_header: PeerHeader, reason: PeerDownReason) -> Self {
        Self {
            peer_header,
            reason,
        }
    }
}

impl BmpMessage for PeerDownMessage {
    fn message_type(&self) -> MessageType {
        MessageType::PeerDownNotification
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Per-Peer Header (42 bytes)
        bytes.extend_from_slice(&self.peer_header.to_bytes());

        // Reason
        bytes.extend_from_slice(&self.reason.to_bytes());

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_peer_down_message() {
        let peer_header = PeerHeader::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
        );

        let msg = PeerDownMessage::new(peer_header, PeerDownReason::LocalNoNotification);

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::PeerDownNotification.as_u8());
    }
}
