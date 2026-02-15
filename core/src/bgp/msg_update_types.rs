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
use super::multiprotocol::{Afi, Safi};
use super::utils::ParserError;
use crate::net::IpNetwork;
use std::net::{Ipv4Addr, Ipv6Addr};

// Re-export community functions and constants
pub use super::community::{asn, from_asn_value, value};
pub use super::community::{NO_ADVERTISE, NO_EXPORT, NO_EXPORT_SUBCONFED};

// Re-export extended community functions and constants
pub use super::ext_community::{
    ext_subtype, ext_type, ext_value, format_extended_community, from_four_octet_as, from_ipv4,
    from_two_octet_as, parse_extended_community,
};
pub use super::ext_community::{
    SUBTYPE_ROUTE_ORIGIN, SUBTYPE_ROUTE_TARGET, TYPE_EVPN, TYPE_FOUR_OCTET_AS, TYPE_IPV4_ADDRESS,
    TYPE_OPAQUE, TYPE_TWO_OCTET_AS,
};

// Re-export large community
pub use super::large_community::{parse_large_community, LargeCommunity};

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
    pub const ORIGINATOR_ID: u8 = 9;
    pub const CLUSTER_LIST: u8 = 10;
    pub const MP_REACH_NLRI: u8 = 14;
    pub const MP_UNREACH_NLRI: u8 = 15;
    pub const EXTENDED_COMMUNITIES: u8 = 16;
    pub const AS4_PATH: u8 = 17;
    pub const AS4_AGGREGATOR: u8 = 18;
    pub const LARGE_COMMUNITIES: u8 = 32;
}

// RFC 6793: AS_TRANS and 4-byte ASN constants
pub const AS_TRANS: u16 = 23456;
pub const MAX_2BYTE_ASN: u32 = 65535;

/// A prefix with its optional ADD-PATH path identifier (RFC 7911).
pub type Nlri = (IpNetwork, Option<u32>);

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct MpReachNlri {
    pub afi: Afi,
    pub safi: Safi,
    pub next_hop: NextHopAddr,
    pub nlri: Vec<Nlri>,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct MpUnreachNlri {
    pub afi: Afi,
    pub safi: Safi,
    pub withdrawn_routes: Vec<Nlri>,
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
    OriginatorId(Ipv4Addr),
    ClusterList(Vec<Ipv4Addr>),
    MpReachNlri(MpReachNlri),
    MpUnreachNlri(MpUnreachNlri),
    ExtendedCommunities(Vec<u64>),
    As4Path(AsPath),
    As4Aggregator(Aggregator),
    LargeCommunities(Vec<LargeCommunity>),
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
    pub fn new(flags: PathAttrFlag, value: PathAttrValue) -> Self {
        PathAttribute { flags, value }
    }

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
            PathAttrValue::OriginatorId(_) => attr_type_code::ORIGINATOR_ID,
            PathAttrValue::ClusterList(_) => attr_type_code::CLUSTER_LIST,
            PathAttrValue::MpReachNlri(_) => attr_type_code::MP_REACH_NLRI,
            PathAttrValue::MpUnreachNlri(_) => attr_type_code::MP_UNREACH_NLRI,
            PathAttrValue::ExtendedCommunities(_) => attr_type_code::EXTENDED_COMMUNITIES,
            PathAttrValue::As4Path(_) => attr_type_code::AS4_PATH,
            PathAttrValue::As4Aggregator(_) => attr_type_code::AS4_AGGREGATOR,
            PathAttrValue::LargeCommunities(_) => attr_type_code::LARGE_COMMUNITIES,
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
    OriginatorId = 9,
    ClusterList = 10,
    MpReachNlri = 14,
    MpUnreachNlri = 15,
    ExtendedCommunities = 16,
    As4Path = 17,
    As4Aggregator = 18,
    LargeCommunities = 32,
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
            9 => Ok(AttrType::OriginatorId),
            10 => Ok(AttrType::ClusterList),
            14 => Ok(AttrType::MpReachNlri),
            15 => Ok(AttrType::MpUnreachNlri),
            16 => Ok(AttrType::ExtendedCommunities),
            17 => Ok(AttrType::As4Path),
            18 => Ok(AttrType::As4Aggregator),
            32 => Ok(AttrType::LargeCommunities),
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
            // RFC 4456: ORIGINATOR_ID and CLUSTER_LIST are optional, non-transitive
            AttrType::OriginatorId => PathAttrFlag::OPTIONAL,
            AttrType::ClusterList => PathAttrFlag::OPTIONAL,
            AttrType::MpReachNlri => PathAttrFlag::OPTIONAL,
            AttrType::MpUnreachNlri => PathAttrFlag::OPTIONAL,
            AttrType::ExtendedCommunities => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::As4Path => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::As4Aggregator => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::LargeCommunities => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
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
            AttrType::MultiExtiDisc
                | AttrType::Aggregator
                | AttrType::Communities
                | AttrType::OriginatorId
                | AttrType::ClusterList
                | AttrType::MpReachNlri
                | AttrType::MpUnreachNlri
                | AttrType::ExtendedCommunities
                | AttrType::As4Path
                | AttrType::As4Aggregator
                | AttrType::LargeCommunities
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
    pub asn_list: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
    AsConfedSequence = 3,
    AsConfedSet = 4,
}

impl TryFrom<u8> for AsPathSegmentType {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AsPathSegmentType::AsSet),
            2 => Ok(AsPathSegmentType::AsSequence),
            3 => Ok(AsPathSegmentType::AsConfedSequence),
            4 => Ok(AsPathSegmentType::AsConfedSet),
            _ => Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
                data: Vec::new(),
            }),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum NextHopAddr {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

impl std::fmt::Display for NextHopAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NextHopAddr::Ipv4(addr) => write!(f, "{}", addr),
            NextHopAddr::Ipv6(addr) => write!(f, "{}", addr),
        }
    }
}

impl NextHopAddr {
    pub fn is_unspecified(&self) -> bool {
        match self {
            NextHopAddr::Ipv4(addr) => addr.is_unspecified(),
            NextHopAddr::Ipv6(addr) => addr.is_unspecified(),
        }
    }
}

impl From<std::net::IpAddr> for NextHopAddr {
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(v4) => NextHopAddr::Ipv4(v4),
            std::net::IpAddr::V6(v6) => NextHopAddr::Ipv6(v6),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct AsPath {
    pub segments: Vec<AsPathSegment>,
}

impl AsPath {
    /// Returns the leftmost AS in the AS_PATH (first AS of the first segment).
    /// Per RFC 4271, this is the AS that most recently added itself to the path.
    pub fn leftmost_as(&self) -> Option<u32> {
        self.segments
            .first()
            .and_then(|seg| seg.asn_list.first().copied())
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct Aggregator {
    pub asn: u32,
    // TODO: support IPv6?
    pub ip_addr: Ipv4Addr,
}
