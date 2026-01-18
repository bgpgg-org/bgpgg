// Copyright 2026 bgpgg Authors
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
use super::msg_notification::{BgpError, MessageHeaderError};
use super::multiprotocol::{Afi, Safi};
use super::utils::ParserError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRefreshMessage {
    pub afi: Afi,
    pub safi: Safi,
}

impl RouteRefreshMessage {
    pub fn new(afi: Afi, safi: Safi) -> Self {
        RouteRefreshMessage { afi, safi }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ParserError> {
        if bytes.len() != 4 {
            return Err(ParserError::BgpError {
                error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
                data: (bytes.len() as u16).to_be_bytes().to_vec(),
            });
        }

        let afi_val = u16::from_be_bytes([bytes[0], bytes[1]]);
        let reserved = bytes[2];
        let safi_val = bytes[3];

        // RFC 2918: Reserved field must be 0
        if reserved != 0 {
            return Err(ParserError::BgpError {
                error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageType),
                data: vec![reserved],
            });
        }

        let afi = Afi::try_from(afi_val)?;
        let safi = Safi::try_from(safi_val)?;

        Ok(RouteRefreshMessage { afi, safi })
    }
}

impl Message for RouteRefreshMessage {
    fn kind(&self) -> MessageType {
        MessageType::RouteRefresh
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.afi as u16).to_be_bytes());
        bytes.push(0); // Reserved
        bytes.push(self.safi as u8);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg::Message;
    use crate::bgp::multiprotocol::{Afi, Safi};

    #[test]
    fn test_route_refresh_serialize() {
        let msg = RouteRefreshMessage::new(Afi::Ipv4, Safi::Unicast);
        let serialized = msg.serialize();

        assert_eq!(&serialized[0..16], &[0xff; 16]); // Marker
        assert_eq!(serialized[16..18], [0x00, 0x17]); // Length: 23
        assert_eq!(serialized[18], 5); // Type: ROUTE_REFRESH
        assert_eq!(serialized[19..21], [0x00, 0x01]); // AFI: IPv4
        assert_eq!(serialized[21], 0x00); // Reserved
        assert_eq!(serialized[22], 0x01); // SAFI: Unicast
    }

    #[test]
    fn test_route_refresh_parse() {
        let cases = vec![
            (vec![0x00, 0x01, 0x00, 0x01], Afi::Ipv4, Safi::Unicast),
            (vec![0x00, 0x02, 0x00, 0x01], Afi::Ipv6, Safi::Unicast),
            (vec![0x00, 0x01, 0x00, 0x02], Afi::Ipv4, Safi::Multicast),
            (vec![0x00, 0x02, 0x00, 0x02], Afi::Ipv6, Safi::Multicast),
            (vec![0x00, 0x01, 0x00, 0x04], Afi::Ipv4, Safi::MplsLabel),
        ];

        for (body, expected_afi, expected_safi) in cases {
            let msg = RouteRefreshMessage::from_bytes(body).unwrap();
            assert_eq!(msg.afi, expected_afi);
            assert_eq!(msg.safi, expected_safi);
        }
    }

    #[test]
    fn test_route_refresh_invalid_reserved() {
        let body = vec![0x00, 0x01, 0xFF, 0x01]; // Non-zero reserved
        assert!(RouteRefreshMessage::from_bytes(body).is_err());
    }

    #[test]
    fn test_route_refresh_round_trip() {
        let msg = RouteRefreshMessage::new(Afi::Ipv6, Safi::Unicast);
        let body = msg.to_bytes();
        let parsed = RouteRefreshMessage::from_bytes(body).unwrap();
        assert_eq!(parsed, msg);
    }
}
