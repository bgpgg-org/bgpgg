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

use crate::bgp::msg_notification::{BgpError, UpdateMessageError};
use crate::bgp::utils::ParserError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Address Family Identifier per IANA registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2,
    LinkState = 16388,
}

impl Serialize for Afi {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(*self as u16)
    }
}

impl<'de> Deserialize<'de> for Afi {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u16::deserialize(deserializer)?;
        Afi::try_from(value).map_err(|_| serde::de::Error::custom(format!("unknown AFI: {value}")))
    }
}

impl fmt::Display for Afi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Afi::Ipv4 => write!(f, "IPv4"),
            Afi::Ipv6 => write!(f, "IPv6"),
            Afi::LinkState => write!(f, "LinkState"),
        }
    }
}

impl TryFrom<u16> for Afi {
    type Error = ParserError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Afi::Ipv4),
            2 => Ok(Afi::Ipv6),
            16388 => Ok(Afi::LinkState),
            _ => Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
                data: Vec::new(),
            }),
        }
    }
}

/// Subsequent Address Family Identifier per IANA registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Safi {
    Unicast = 1,
    Multicast = 2,
    MplsLabel = 4,
    LinkState = 71,
    LinkStateVpn = 72,
}

impl From<Safi> for u8 {
    fn from(safi: Safi) -> u8 {
        safi as u8
    }
}

impl Serialize for Safi {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for Safi {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u8::deserialize(deserializer)?;
        Safi::try_from(value)
            .map_err(|_| serde::de::Error::custom(format!("unknown SAFI: {value}")))
    }
}

impl fmt::Display for Safi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Safi::Unicast => write!(f, "Unicast"),
            Safi::Multicast => write!(f, "Multicast"),
            Safi::MplsLabel => write!(f, "MPLS-labeled"),
            Safi::LinkState => write!(f, "LinkState"),
            Safi::LinkStateVpn => write!(f, "LinkState-VPN"),
        }
    }
}

impl TryFrom<u8> for Safi {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Safi::Unicast),
            2 => Ok(Safi::Multicast),
            4 => Ok(Safi::MplsLabel),
            71 => Ok(Safi::LinkState),
            72 => Ok(Safi::LinkStateVpn),
            _ => Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
                data: Vec::new(),
            }),
        }
    }
}

/// Combined AFI/SAFI for capability tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AfiSafi {
    pub afi: Afi,
    pub safi: Safi,
}

impl AfiSafi {
    pub fn new(afi: Afi, safi: Safi) -> Self {
        AfiSafi { afi, safi }
    }

    /// Try to construct from optional raw numeric AFI/SAFI values.
    /// Returns None if either is absent or unrecognized.
    pub fn from_raw(afi: Option<u32>, safi: Option<u32>) -> Option<Self> {
        let afi = Afi::try_from(afi? as u16).ok()?;
        // Default to unicast when SAFI is not specified.
        let safi_val = safi.unwrap_or(1);
        let safi = Safi::try_from(safi_val as u8).ok()?;
        Some(AfiSafi { afi, safi })
    }

    /// Parse AFI/SAFI from BGP OPEN message multiprotocol capability
    /// Format: [AFI_HIGH, AFI_LOW, RESERVED, SAFI]
    pub fn from_capability_bytes(val: &[u8]) -> Result<Self, ParserError> {
        if val.len() < 4 {
            return Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
                data: Vec::new(),
            });
        }

        let afi_bytes = [val[0], val[1]];
        let afi = Afi::try_from(u16::from_be_bytes(afi_bytes))?;
        let safi = Safi::try_from(val[3])?;

        Ok(AfiSafi::new(afi, safi))
    }
}

impl fmt::Display for AfiSafi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.afi, self.safi)
    }
}

/// Default AFI/SAFIs: IPv4 Unicast + IPv6 Unicast
pub fn default_afi_safis() -> Vec<AfiSafi> {
    vec![
        AfiSafi::new(Afi::Ipv4, Safi::Unicast),
        AfiSafi::new(Afi::Ipv6, Safi::Unicast),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afi_try_from() {
        assert_eq!(Afi::try_from(1).unwrap(), Afi::Ipv4);
        assert_eq!(Afi::try_from(2).unwrap(), Afi::Ipv6);
        assert_eq!(Afi::try_from(16388).unwrap(), Afi::LinkState);
        assert!(Afi::try_from(99).is_err());
    }

    #[test]
    fn test_safi_try_from() {
        assert_eq!(Safi::try_from(1).unwrap(), Safi::Unicast);
        assert_eq!(Safi::try_from(2).unwrap(), Safi::Multicast);
        assert_eq!(Safi::try_from(4).unwrap(), Safi::MplsLabel);
        assert_eq!(Safi::try_from(71).unwrap(), Safi::LinkState);
        assert_eq!(Safi::try_from(72).unwrap(), Safi::LinkStateVpn);
        assert!(Safi::try_from(99).is_err());
    }

    #[test]
    fn test_afi_safi_from_capability_bytes() {
        // IPv4 Unicast: AFI=1, SAFI=1
        let bytes = [0x00, 0x01, 0x00, 0x01];
        let afi_safi = AfiSafi::from_capability_bytes(&bytes).unwrap();
        assert_eq!(afi_safi.afi, Afi::Ipv4);
        assert_eq!(afi_safi.safi, Safi::Unicast);

        // IPv6 Unicast: AFI=2, SAFI=1
        let bytes = [0x00, 0x02, 0x00, 0x01];
        let afi_safi = AfiSafi::from_capability_bytes(&bytes).unwrap();
        assert_eq!(afi_safi.afi, Afi::Ipv6);
        assert_eq!(afi_safi.safi, Safi::Unicast);

        // Too short
        let bytes = [0x00, 0x01, 0x00];
        assert!(AfiSafi::from_capability_bytes(&bytes).is_err());

        // Unknown AFI
        let bytes = [0x00, 0x99, 0x00, 0x01];
        assert!(AfiSafi::from_capability_bytes(&bytes).is_err());

        // Unknown SAFI
        let bytes = [0x00, 0x01, 0x00, 0x99];
        assert!(AfiSafi::from_capability_bytes(&bytes).is_err());

        // BGP-LS: AFI=16388 (0x4004), SAFI=71 (0x47)
        let bytes = [0x40, 0x04, 0x00, 0x47];
        let afi_safi = AfiSafi::from_capability_bytes(&bytes).unwrap();
        assert_eq!(afi_safi.afi, Afi::LinkState);
        assert_eq!(afi_safi.safi, Safi::LinkState);
    }

    #[test]
    fn test_afi_safi_serde_roundtrip() {
        let cases = vec![
            AfiSafi::new(Afi::Ipv4, Safi::Unicast),
            AfiSafi::new(Afi::Ipv6, Safi::Unicast),
            AfiSafi::new(Afi::Ipv4, Safi::Multicast),
            AfiSafi::new(Afi::Ipv6, Safi::Multicast),
            AfiSafi::new(Afi::LinkState, Safi::LinkState),
            AfiSafi::new(Afi::LinkState, Safi::LinkStateVpn),
        ];
        for afi_safi in cases {
            let json = serde_json::to_string(&afi_safi).unwrap();
            let parsed: AfiSafi = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, afi_safi);
        }
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Afi::Ipv4), "IPv4");
        assert_eq!(format!("{}", Afi::Ipv6), "IPv6");
        assert_eq!(format!("{}", Afi::LinkState), "LinkState");
        assert_eq!(format!("{}", Safi::Unicast), "Unicast");
        assert_eq!(format!("{}", Safi::Multicast), "Multicast");
        assert_eq!(format!("{}", Safi::MplsLabel), "MPLS-labeled");
        assert_eq!(format!("{}", Safi::LinkState), "LinkState");
        assert_eq!(format!("{}", Safi::LinkStateVpn), "LinkState-VPN");

        let afi_safi = AfiSafi::new(Afi::Ipv6, Safi::Unicast);
        assert_eq!(format!("{}", afi_safi), "IPv6/Unicast");

        let ls = AfiSafi::new(Afi::LinkState, Safi::LinkState);
        assert_eq!(format!("{}", ls), "LinkState/LinkState");
    }

    #[test]
    fn test_default_afi_safis() {
        let defaults = default_afi_safis();
        assert_eq!(defaults.len(), 2);
        assert_eq!(defaults[0], AfiSafi::new(Afi::Ipv4, Safi::Unicast));
        assert_eq!(defaults[1], AfiSafi::new(Afi::Ipv6, Safi::Unicast));
    }
}
