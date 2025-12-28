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

use super::msg_notification::{BgpError, UpdateMessageError};
use super::utils::ParserError;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct PathAttrFlag(pub u8);

impl PathAttrFlag {
    pub const OPTIONAL: u8 = 1 << 7;
    pub const TRANSITIVE: u8 = 1 << 6;
    pub const PARTIAL: u8 = 1 << 5;
    pub const EXTENDED_LENGTH: u8 = 1 << 4;

    pub(super) fn extended_len(&self) -> bool {
        self.0 & Self::EXTENDED_LENGTH != 0
    }
}

// Public constants for use in tests
pub mod attr_flags {
    pub const OPTIONAL: u8 = 1 << 7;
    pub const TRANSITIVE: u8 = 1 << 6;
    pub const PARTIAL: u8 = 1 << 5;
    pub const EXTENDED_LENGTH: u8 = 1 << 4;
}

pub mod attr_type_code {
    pub const ORIGIN: u8 = 1;
    pub const AS_PATH: u8 = 2;
    pub const NEXT_HOP: u8 = 3;
    pub const MULTI_EXIT_DISC: u8 = 4;
    pub const LOCAL_PREF: u8 = 5;
    pub const ATOMIC_AGGREGATE: u8 = 6;
    pub const AGGREGATOR: u8 = 7;
    pub const COMMUNITIES: u8 = 8;
}

/// Helper functions for BGP community values.
/// RFC 1997: community = (ASN << 16) | value
pub mod community {
    /// Create a community value from ASN and local value (ASN:value format).
    pub const fn from_asn_value(asn: u16, value: u16) -> u32 {
        ((asn as u32) << 16) | (value as u32)
    }

    /// Extract ASN from a community value (high 16 bits).
    pub const fn asn(community: u32) -> u16 {
        (community >> 16) as u16
    }

    /// Extract local value from a community value (low 16 bits).
    pub const fn value(community: u32) -> u16 {
        community as u16
    }
}

pub mod well_known_communities {
    pub const NO_EXPORT: u32 = 0xFFFFFF01;
    pub const NO_ADVERTISE: u32 = 0xFFFFFF02;
    pub const NO_EXPORT_SUBCONFED: u32 = 0xFFFFFF03;
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum PathAttrValue {
    Origin(Origin),
    AsPath(AsPath),
    NextHop(NextHopAddr),
    MultiExtiDisc(u32),
    LocalPref(u32),
    AtomicAggregate,
    Aggregator(Aggregator),
    Communities(Vec<u32>),
    Unknown {
        type_code: u8,
        flags: u8,
        data: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct PathAttribute {
    pub(super) flags: PathAttrFlag,
    pub value: PathAttrValue,
}

impl PathAttribute {
    pub fn is_unknown_transitive(&self) -> bool {
        if let PathAttrValue::Unknown { flags, .. } = &self.value {
            flags & attr_flags::TRANSITIVE != 0
        } else {
            false
        }
    }

    pub(super) fn type_code(&self) -> u8 {
        match &self.value {
            PathAttrValue::Origin(_) => attr_type_code::ORIGIN,
            PathAttrValue::AsPath(_) => attr_type_code::AS_PATH,
            PathAttrValue::NextHop(_) => attr_type_code::NEXT_HOP,
            PathAttrValue::MultiExtiDisc(_) => attr_type_code::MULTI_EXIT_DISC,
            PathAttrValue::LocalPref(_) => attr_type_code::LOCAL_PREF,
            PathAttrValue::AtomicAggregate => attr_type_code::ATOMIC_AGGREGATE,
            PathAttrValue::Aggregator(_) => attr_type_code::AGGREGATOR,
            PathAttrValue::Communities(_) => attr_type_code::COMMUNITIES,
            PathAttrValue::Unknown { type_code, .. } => *type_code,
        }
    }
}

#[repr(u8)]
pub(crate) enum AttrType {
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    MultiExtiDisc = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
    Communities = 8,
}

impl TryFrom<u8> for AttrType {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AttrType::Origin),
            2 => Ok(AttrType::AsPath),
            3 => Ok(AttrType::NextHop),
            4 => Ok(AttrType::MultiExtiDisc),
            5 => Ok(AttrType::LocalPref),
            6 => Ok(AttrType::AtomicAggregate),
            7 => Ok(AttrType::Aggregator),
            8 => Ok(AttrType::Communities),
            _ => Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::Unknown(0)),
                data: Vec::new(),
            }),
        }
    }
}

impl AttrType {
    pub(super) fn expected_flags(&self) -> u8 {
        match self {
            AttrType::Origin => PathAttrFlag::TRANSITIVE,
            AttrType::AsPath => PathAttrFlag::TRANSITIVE,
            AttrType::NextHop => PathAttrFlag::TRANSITIVE,
            AttrType::MultiExtiDisc => PathAttrFlag::OPTIONAL,
            AttrType::LocalPref => PathAttrFlag::TRANSITIVE,
            AttrType::AtomicAggregate => PathAttrFlag::TRANSITIVE,
            AttrType::Aggregator => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::Communities => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
        }
    }

    pub(super) fn is_well_known(&self) -> bool {
        matches!(
            self,
            AttrType::Origin
                | AttrType::AsPath
                | AttrType::NextHop
                | AttrType::LocalPref
                | AttrType::AtomicAggregate
        )
    }

    pub(super) fn is_optional(&self) -> bool {
        matches!(
            self,
            AttrType::MultiExtiDisc | AttrType::Aggregator | AttrType::Communities
        )
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Origin {
    IGP = 0,
    EGP = 1,
    INCOMPLETE = 2,
}

impl TryFrom<u8> for Origin {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Origin::IGP),
            1 => Ok(Origin::EGP),
            2 => Ok(Origin::INCOMPLETE),
            _ => Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::InvalidOriginAttribute),
                data: Vec::new(),
            }),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct AsPathSegment {
    pub segment_type: AsPathSegmentType,
    pub segment_len: u8,
    pub asn_list: Vec<u16>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
}

impl TryFrom<u8> for AsPathSegmentType {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AsPathSegmentType::AsSet),
            2 => Ok(AsPathSegmentType::AsSequence),
            _ => Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
                data: Vec::new(),
            }),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum NextHopAddr {
    Ipv4(Ipv4Addr),
    // TODO: support IPv6
    #[allow(dead_code)]
    Ipv6(Ipv6Addr),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct AsPath {
    pub(super) segments: Vec<AsPathSegment>,
}

impl AsPath {
    /// Returns the leftmost AS in the AS_PATH (first AS of the first segment).
    /// Per RFC 4271, this is the AS that most recently added itself to the path.
    pub fn leftmost_as(&self) -> Option<u16> {
        self.segments
            .first()
            .and_then(|seg| seg.asn_list.first().copied())
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct Aggregator {
    pub(super) asn: u16,
    // TODO: support IPv6?
    pub(super) ip_addr: Ipv4Addr,
}

#[cfg(test)]
mod tests {
    use super::community::*;
    use super::well_known_communities::*;

    #[test]
    fn test_community_from_asn_value() {
        assert_eq!(from_asn_value(1, 100), 0x00010064);
        assert_eq!(from_asn_value(65001, 200), 0xFDE900C8);
        assert_eq!(from_asn_value(0, 1), 0x00000001);
        assert_eq!(from_asn_value(65535, 65535), 0xFFFFFFFF);
    }

    #[test]
    fn test_community_asn() {
        assert_eq!(asn(0x00010064), 1);
        assert_eq!(asn(0xFDE900C8), 65001);
        assert_eq!(asn(NO_EXPORT), 0xFFFF);
        assert_eq!(asn(NO_ADVERTISE), 0xFFFF);
    }

    #[test]
    fn test_community_value() {
        assert_eq!(value(0x00010064), 100);
        assert_eq!(value(0xFDE900C8), 200);
        assert_eq!(value(NO_EXPORT), 0xFF01);
        assert_eq!(value(NO_ADVERTISE), 0xFF02);
    }

    #[test]
    fn test_community_roundtrip() {
        let test_cases = [(1, 100), (65001, 200), (0, 1), (65535, 65535)];
        for (test_asn, test_value) in test_cases {
            let community = from_asn_value(test_asn, test_value);
            assert_eq!(asn(community), test_asn);
            assert_eq!(value(community), test_value);
        }
    }
}
