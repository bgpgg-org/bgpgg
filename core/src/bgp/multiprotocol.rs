use crate::bgp::msg_notification::{BgpError, UpdateMessageError};
use crate::bgp::utils::ParserError;
use std::fmt;

/// Address Family Identifier per IANA registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2,
}

impl fmt::Display for Afi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Afi::Ipv4 => write!(f, "IPv4"),
            Afi::Ipv6 => write!(f, "IPv6"),
        }
    }
}

impl TryFrom<u16> for Afi {
    type Error = ParserError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Afi::Ipv4),
            2 => Ok(Afi::Ipv6),
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
}

impl fmt::Display for Safi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Safi::Unicast => write!(f, "Unicast"),
            Safi::Multicast => write!(f, "Multicast"),
            Safi::MplsLabel => write!(f, "MPLS-labeled"),
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
            _ => Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
                data: Vec::new(),
            }),
        }
    }
}

/// Combined AFI/SAFI for capability tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AfiSafi {
    pub afi: Afi,
    pub safi: Safi,
}

impl AfiSafi {
    pub fn new(afi: Afi, safi: Safi) -> Self {
        AfiSafi { afi, safi }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afi_try_from() {
        assert_eq!(Afi::try_from(1).unwrap(), Afi::Ipv4);
        assert_eq!(Afi::try_from(2).unwrap(), Afi::Ipv6);
        assert!(Afi::try_from(99).is_err());
    }

    #[test]
    fn test_safi_try_from() {
        assert_eq!(Safi::try_from(1).unwrap(), Safi::Unicast);
        assert_eq!(Safi::try_from(2).unwrap(), Safi::Multicast);
        assert_eq!(Safi::try_from(4).unwrap(), Safi::MplsLabel);
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
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Afi::Ipv4), "IPv4");
        assert_eq!(format!("{}", Afi::Ipv6), "IPv6");
        assert_eq!(format!("{}", Safi::Unicast), "Unicast");
        assert_eq!(format!("{}", Safi::Multicast), "Multicast");
        assert_eq!(format!("{}", Safi::MplsLabel), "MPLS-labeled");

        let afi_safi = AfiSafi::new(Afi::Ipv6, Safi::Unicast);
        assert_eq!(format!("{}", afi_safi), "IPv6/Unicast");
    }
}
