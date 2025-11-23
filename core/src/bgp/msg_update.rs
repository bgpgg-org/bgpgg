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
use super::msg_notification::{BgpError, UpdateMessageError};
use super::utils::{parse_nlri_list, read_u32, IpNetwork, ParserError};
use std::net::{Ipv4Addr, Ipv6Addr};

const WITHDRAWN_ROUTES_LENGTH_SIZE: usize = 2;
const TOTAL_ATTR_LENGTH_SIZE: usize = 2;

#[derive(Debug, PartialEq)]
struct PathAttrFlag(u8);

impl PathAttrFlag {
    pub const OPTIONAL: u8 = 1 << 7;
    pub const TRANSITIVE: u8 = 1 << 6;
    pub const PARTIAL: u8 = 1 << 5;
    pub const EXTENDED_LENGTH: u8 = 1 << 4;

    fn extended_len(&self) -> bool {
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
}

#[derive(Debug, PartialEq)]
enum PathAttrValue {
    Origin(Origin),
    AsPath(AsPath),
    NextHop(NextHopAddr),
    MultiExtiDisc(u32),
    LocalPref(u32),
    AtomicAggregate,
    Aggregator(Aggregator),
}

#[derive(Debug, PartialEq)]
struct PathAttribute {
    flags: PathAttrFlag,
    value: PathAttrValue,
}

#[repr(u8)]
enum AttrType {
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    MultiExtiDisc = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
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
            _ => Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::Unknown(0)),
                data: Vec::new(),
            }),
        }
    }
}

impl AttrType {
    fn expected_flags(&self) -> u8 {
        match self {
            AttrType::Origin => PathAttrFlag::TRANSITIVE,
            AttrType::AsPath => PathAttrFlag::TRANSITIVE,
            AttrType::NextHop => PathAttrFlag::TRANSITIVE,
            AttrType::MultiExtiDisc => PathAttrFlag::OPTIONAL,
            AttrType::LocalPref => PathAttrFlag::TRANSITIVE,
            AttrType::AtomicAggregate => PathAttrFlag::TRANSITIVE,
            AttrType::Aggregator => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
        }
    }

    fn is_well_known(&self) -> bool {
        matches!(
            self,
            AttrType::Origin
                | AttrType::AsPath
                | AttrType::NextHop
                | AttrType::LocalPref
                | AttrType::AtomicAggregate
        )
    }
}

fn validate_attribute_flags(
    flags: u8,
    attr_type: &AttrType,
    attr_type_code: u8,
    attr_len: u16,
) -> Result<(), ParserError> {
    let expected = attr_type.expected_flags();
    let mask = PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE;

    // Validate Optional and Transitive bits match the attribute type
    if (flags & mask) != expected {
        let mut data = vec![flags, attr_type_code];
        if flags & PathAttrFlag::EXTENDED_LENGTH != 0 {
            data.extend_from_slice(&attr_len.to_be_bytes());
        } else {
            data.push(attr_len as u8);
        }
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError),
            data,
        });
    }

    // Partial bit must be 0 for well-known attributes
    if attr_type.is_well_known() && (flags & PathAttrFlag::PARTIAL != 0) {
        let mut data = vec![flags, attr_type_code];
        if flags & PathAttrFlag::EXTENDED_LENGTH != 0 {
            data.extend_from_slice(&attr_len.to_be_bytes());
        } else {
            data.push(attr_len as u8);
        }
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError),
            data,
        });
    }

    Ok(())
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

#[derive(Debug, PartialEq)]
enum NextHopAddr {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[derive(Debug, PartialEq)]
struct AsPath {
    segments: Vec<AsPathSegment>,
}

#[derive(Debug, PartialEq)]
struct Aggregator {
    asn: u16,
    // TODO: support IPv6?
    ip_addr: Ipv4Addr,
}

fn read_attr_as_path(bytes: &[u8]) -> Result<AsPath, ParserError> {
    let mut segments = vec![];
    let mut cursor = 0;

    while cursor < bytes.len() {
        // Calculate total bytes needed for this segment (header + ASN data)
        let segment_size = 2 + (bytes.get(cursor + 1).copied().unwrap_or(0) as usize * 2);

        if cursor + segment_size > bytes.len() {
            return Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
                data: Vec::new(),
            });
        }

        let segment_type = AsPathSegmentType::try_from(bytes[cursor])?;
        let segment_len = bytes[cursor + 1];

        let asn_list = (0..segment_len)
            .map(|i| {
                let pos = cursor + 2 + (i as usize * 2);
                u16::from_be_bytes([bytes[pos], bytes[pos + 1]])
            })
            .collect();

        segments.push(AsPathSegment {
            segment_type,
            segment_len,
            asn_list,
        });

        cursor += segment_size;
    }

    Ok(AsPath { segments })
}

fn read_attr_next_hop(bytes: &[u8]) -> Result<NextHopAddr, ParserError> {
    // RFC 4271: NEXT_HOP must be exactly 4 bytes (IPv4 address)
    // This should already be validated by validate_attribute_length, but check defensively
    if bytes.len() != 4 {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::MalformedNextHop),
            data: Vec::new(),
        });
    }

    let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    Ok(NextHopAddr::Ipv4(ip))
}

fn read_attr_aggregator(bytes: &[u8]) -> Result<Aggregator, ParserError> {
    if bytes.len() != 6 {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError),
            data: Vec::new(),
        });
    }

    let asn = u16::from_be_bytes([bytes[0], bytes[1]]);
    let ip_addr = Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]);

    Ok(Aggregator { asn, ip_addr })
}

fn validate_attribute_length(
    attr_type: &AttrType,
    attr_len: u16,
    attr_bytes: &[u8],
) -> Result<(), ParserError> {
    let valid = match attr_type {
        AttrType::Origin => attr_len == 1,
        AttrType::NextHop => attr_len == 4, // Only IPv4 per RFC 4271
        AttrType::MultiExtiDisc => attr_len == 4,
        AttrType::LocalPref => attr_len == 4,
        AttrType::AtomicAggregate => attr_len == 0,
        AttrType::Aggregator => attr_len == 6,
        AttrType::AsPath => true, // Variable length
    };

    if !valid {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError),
            data: attr_bytes.to_vec(),
        });
    }

    Ok(())
}

fn read_path_attribute(bytes: &[u8]) -> Result<(PathAttribute, u8), ParserError> {
    let attribute_flag = PathAttrFlag(bytes[0]);
    let attr_type = AttrType::try_from(bytes[1])?;

    let attr_len = match attribute_flag.extended_len() {
        true => u16::from_be_bytes([bytes[2], bytes[3]]),
        false => bytes[2] as u16,
    };

    validate_attribute_flags(bytes[0], &attr_type, bytes[1], attr_len)?;

    let mut offset = if attribute_flag.extended_len() { 4 } else { 3 };

    // Calculate the total attribute size for error reporting
    let attr_total_len = offset + attr_len as usize;
    let attr_bytes = &bytes[..attr_total_len.min(bytes.len())];

    validate_attribute_length(&attr_type, attr_len, attr_bytes)?;

    let attr_data = &bytes[offset..offset + attr_len as usize];

    let attr_val = match attr_type {
        AttrType::Origin => {
            let origin = Origin::try_from(bytes[offset])?;

            PathAttrValue::Origin(origin)
        }
        AttrType::AsPath => {
            let as_path = read_attr_as_path(&attr_data)?;

            PathAttrValue::AsPath(as_path)
        }
        AttrType::NextHop => {
            let next_hop = read_attr_next_hop(&attr_data)?;

            PathAttrValue::NextHop(next_hop)
        }
        AttrType::MultiExtiDisc => {
            let multi_exit_disc = read_u32(&attr_data)?;

            PathAttrValue::MultiExtiDisc(multi_exit_disc)
        }
        AttrType::LocalPref => {
            let local_pref = read_u32(&attr_data)?;

            PathAttrValue::LocalPref(local_pref)
        }
        AttrType::AtomicAggregate => {
            if attr_len > 0 {
                return Err(ParserError::BgpError {
                    error: BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError),
                    data: Vec::new(),
                });
            }

            PathAttrValue::AtomicAggregate
        }
        AttrType::Aggregator => {
            let aggregator = read_attr_aggregator(&attr_data)?;

            PathAttrValue::Aggregator(aggregator)
        }
    };

    offset = offset + attr_len as usize;

    let attribute = PathAttribute {
        flags: attribute_flag,
        value: attr_val,
    };

    Ok((attribute, offset as u8))
}

fn read_path_attributes(bytes: &[u8]) -> Result<Vec<PathAttribute>, ParserError> {
    let mut cursor = 0;
    let mut path_attributes: Vec<PathAttribute> = Vec::new();

    while cursor < bytes.len() {
        let (attribute, offset) = read_path_attribute(&bytes[cursor..])?;
        cursor = cursor + offset as usize;

        path_attributes.push(attribute);
    }

    return Ok(path_attributes);
}

fn write_nlri_list(nlri_list: &[IpNetwork]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for network in nlri_list {
        match network {
            IpNetwork::V4(net) => {
                bytes.push(net.prefix_length);
                let octets = net.address.octets();
                let num_octets = ((net.prefix_length + 7) / 8) as usize;
                bytes.extend_from_slice(&octets[..num_octets]);
            }
            IpNetwork::V6(net) => {
                bytes.push(net.prefix_length);
                let octets = net.address.octets();
                let num_octets = ((net.prefix_length + 7) / 8) as usize;
                bytes.extend_from_slice(&octets[..num_octets]);
            }
        }
    }
    bytes
}

fn write_path_attribute(attr: &PathAttribute) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Serialize attribute value first to determine length
    let attr_value_bytes = match &attr.value {
        PathAttrValue::Origin(origin) => {
            vec![*origin as u8]
        }
        PathAttrValue::AsPath(as_path) => {
            let mut path_bytes = Vec::new();
            for segment in &as_path.segments {
                path_bytes.push(segment.segment_type as u8);
                path_bytes.push(segment.segment_len);
                for asn in &segment.asn_list {
                    path_bytes.extend_from_slice(&asn.to_be_bytes());
                }
            }
            path_bytes
        }
        PathAttrValue::NextHop(next_hop) => match next_hop {
            NextHopAddr::Ipv4(addr) => addr.octets().to_vec(),
            NextHopAddr::Ipv6(addr) => addr.octets().to_vec(),
        },
        PathAttrValue::MultiExtiDisc(value) => value.to_be_bytes().to_vec(),
        PathAttrValue::LocalPref(value) => value.to_be_bytes().to_vec(),
        PathAttrValue::AtomicAggregate => vec![],
        PathAttrValue::Aggregator(agg) => {
            let mut agg_bytes = Vec::new();
            agg_bytes.extend_from_slice(&agg.asn.to_be_bytes());
            agg_bytes.extend_from_slice(&agg.ip_addr.octets());
            agg_bytes
        }
    };

    // Write flags
    bytes.push(attr.flags.0);

    // Write attribute type
    let attr_type = match &attr.value {
        PathAttrValue::Origin(_) => AttrType::Origin as u8,
        PathAttrValue::AsPath(_) => AttrType::AsPath as u8,
        PathAttrValue::NextHop(_) => AttrType::NextHop as u8,
        PathAttrValue::MultiExtiDisc(_) => AttrType::MultiExtiDisc as u8,
        PathAttrValue::LocalPref(_) => AttrType::LocalPref as u8,
        PathAttrValue::AtomicAggregate => AttrType::AtomicAggregate as u8,
        PathAttrValue::Aggregator(_) => AttrType::Aggregator as u8,
    };
    bytes.push(attr_type);

    // Write length
    let attr_len = attr_value_bytes.len();
    if attr.flags.extended_len() {
        bytes.extend_from_slice(&(attr_len as u16).to_be_bytes());
    } else {
        bytes.push(attr_len as u8);
    }

    // Write attribute value
    bytes.extend_from_slice(&attr_value_bytes);

    bytes
}

fn write_path_attributes(path_attributes: &[PathAttribute]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for attr in path_attributes {
        bytes.extend_from_slice(&write_path_attribute(attr));
    }
    bytes
}

fn validate_update_message_lengths(
    withdrawn_routes_len: usize,
    total_path_attributes_len: usize,
    body_length: usize,
) -> Result<(), ParserError> {
    // RFC 4271 Section 6.3: If Withdrawn Routes Length + Total Attribute Length + 23
    // exceeds the message Length, then Error Subcode MUST be set to Malformed Attribute List.
    // Since we work with body (message_length - 19), check becomes:
    // withdrawn_routes_len + total_path_attributes_len + 4 > body_length
    let length_fields_size = WITHDRAWN_ROUTES_LENGTH_SIZE + TOTAL_ATTR_LENGTH_SIZE;
    let claimed_size = withdrawn_routes_len + total_path_attributes_len + length_fields_size;

    if claimed_size > body_length {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
            data: Vec::new(),
        });
    }

    Ok(())
}

impl UpdateMessage {
    pub fn new(
        origin: Origin,
        as_path_segments: Vec<AsPathSegment>,
        next_hop: Ipv4Addr,
        nlri_list: Vec<IpNetwork>,
        local_pref: Option<u32>,
        med: Option<u32>,
        atomic_aggregate: bool,
    ) -> Self {
        let mut path_attributes = vec![
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::Origin(origin),
            },
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AsPath(AsPath {
                    segments: as_path_segments,
                }),
            },
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::NextHop(NextHopAddr::Ipv4(next_hop)),
            },
        ];

        if let Some(pref) = local_pref {
            path_attributes.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::LocalPref(pref),
            });
        }

        if let Some(metric) = med {
            path_attributes.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                value: PathAttrValue::MultiExtiDisc(metric),
            });
        }

        if atomic_aggregate {
            path_attributes.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AtomicAggregate,
            });
        }

        let path_attributes_bytes = write_path_attributes(&path_attributes);

        UpdateMessage {
            withdrawn_routes_len: 0,
            withdrawn_routes: vec![],
            total_path_attributes_len: path_attributes_bytes.len() as u16,
            path_attributes,
            nlri_list,
        }
    }

    pub fn new_withdraw(withdrawn_routes: Vec<IpNetwork>) -> Self {
        let withdrawn_routes_bytes = write_nlri_list(&withdrawn_routes);

        UpdateMessage {
            withdrawn_routes_len: withdrawn_routes_bytes.len() as u16,
            withdrawn_routes,
            total_path_attributes_len: 0,
            path_attributes: vec![],
            nlri_list: vec![],
        }
    }

    pub fn nlri_list(&self) -> &[IpNetwork] {
        &self.nlri_list
    }

    pub fn withdrawn_routes(&self) -> &[IpNetwork] {
        &self.withdrawn_routes
    }

    pub fn get_origin(&self) -> Option<Origin> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::Origin(origin) = attr.value {
                Some(origin)
            } else {
                None
            }
        })
    }

    pub fn get_as_path(&self) -> Option<Vec<AsPathSegment>> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::AsPath(ref as_path) = attr.value {
                Some(as_path.segments.clone())
            } else {
                None
            }
        })
    }

    pub fn get_next_hop(&self) -> Option<Ipv4Addr> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::NextHop(ref next_hop) = attr.value {
                match next_hop {
                    NextHopAddr::Ipv4(addr) => Some(*addr),
                    NextHopAddr::Ipv6(_) => None, // For now, only support IPv4
                }
            } else {
                None
            }
        })
    }

    pub fn get_local_pref(&self) -> Option<u32> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::LocalPref(pref) = attr.value {
                Some(pref)
            } else {
                None
            }
        })
    }

    pub fn get_med(&self) -> Option<u32> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::MultiExtiDisc(med) = attr.value {
                Some(med)
            } else {
                None
            }
        })
    }

    pub fn get_atomic_aggregate(&self) -> bool {
        self.path_attributes
            .iter()
            .any(|attr| attr.value == PathAttrValue::AtomicAggregate)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ParserError> {
        let body_length = bytes.len();
        let mut data = bytes;

        let withdrawn_routes_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        data = data[WITHDRAWN_ROUTES_LENGTH_SIZE..].to_vec();

        let withdrawn_routes = parse_nlri_list(&data[..withdrawn_routes_len]);
        data = data[withdrawn_routes_len..].to_vec();

        let total_path_attributes_len = u16::from_be_bytes([data[0], data[1]]) as usize;

        validate_update_message_lengths(
            withdrawn_routes_len,
            total_path_attributes_len,
            body_length,
        )?;

        data = data[TOTAL_ATTR_LENGTH_SIZE..].to_vec();

        let path_attributes = read_path_attributes(&data[..total_path_attributes_len])?;
        data = data[total_path_attributes_len..].to_vec();

        let nlri_list = match total_path_attributes_len {
            0 => vec![],
            _ => parse_nlri_list(&data),
        };

        Ok(UpdateMessage {
            withdrawn_routes_len: withdrawn_routes_len as u16,
            withdrawn_routes,
            total_path_attributes_len: total_path_attributes_len as u16,
            path_attributes,
            nlri_list,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct UpdateMessage {
    withdrawn_routes_len: u16,
    withdrawn_routes: Vec<IpNetwork>,
    total_path_attributes_len: u16,
    path_attributes: Vec<PathAttribute>,
    nlri_list: Vec<IpNetwork>,
}

impl Message for UpdateMessage {
    fn kind(&self) -> MessageType {
        MessageType::UPDATE
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Withdrawn routes
        let withdrawn_routes_bytes = write_nlri_list(&self.withdrawn_routes);
        bytes.extend_from_slice(&self.withdrawn_routes_len.to_be_bytes());
        bytes.extend_from_slice(&withdrawn_routes_bytes);

        // Path attributes
        let path_attributes_bytes = write_path_attributes(&self.path_attributes);
        bytes.extend_from_slice(&self.total_path_attributes_len.to_be_bytes());
        bytes.extend_from_slice(&path_attributes_bytes);

        // NLRI
        let nlri_bytes = write_nlri_list(&self.nlri_list);
        bytes.extend_from_slice(&nlri_bytes);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::utils::Ipv4Net;
    use std::str::FromStr;

    const PATH_ATTR_ORIGIN_EGP: &[u8] = &[
        PathAttrFlag::TRANSITIVE, // Attribute flags
        AttrType::Origin as u8,   // Attribute type
        0x01,                     // Attribute length
        1,                        // Origin value: EGP
    ];
    const PATH_ATTR_AS_PATH: &[u8] = &[
        PathAttrFlag::TRANSITIVE, // Attribute flags
        AttrType::AsPath as u8,   // Attribute type
        0x06,                     // Attribute length
        // AS Path attrbitue
        AsPathSegmentType::AsSet as u8,
        0x02, // Number of ASes
        0x00,
        0x10, // ASN: 16
        0x01,
        0x12, // ASN: 274
    ];
    const PATH_ATTR_NEXT_HOP_IPV4: &[u8] = &[
        PathAttrFlag::TRANSITIVE, // Attribute flags
        AttrType::NextHop as u8,  // Attribute type
        0x04,                     // Attribute length
        // IPv4
        0xc8,
        0xc9,
        0xca,
        0xcb,
    ];

    const WITHDRAWN_ROUTES_BYTES: &[u8] = &[
        0x00, 0x0c, // Withdrawn routes length (12 bytes: 3 routes * 4 bytes each)
        0x18, 0x0a, 0x0b, 0x0c, // Withdrawn route #1: /24 prefix
        0x18, 0x0a, 0x0b, 0x0d, // Withdrawn route #2: /24 prefix
        0x18, 0x0a, 0x0b, 0x0e, // Withdrawn route #3: /24 prefix
    ];

    #[test]
    fn test_read_path_attribute_origin() {
        let (attribute, offset) = read_path_attribute(PATH_ATTR_ORIGIN_EGP).unwrap();

        assert_eq!(
            attribute,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::Origin(Origin::try_from(1).unwrap()),
            }
        );
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_read_path_attribute_as_path() {
        let (as_path, offset) = read_path_attribute(PATH_ATTR_AS_PATH).unwrap();
        let segments = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSet,
            segment_len: 2,
            asn_list: vec![16, 274],
        }];

        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AsPath(AsPath { segments }),
            }
        );
        assert_eq!(offset, 9);
    }

    #[test]
    fn test_read_path_attribute_as_path_truncated_header() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::AsPath as u8,
            0x01, // Attribute length: only 1 byte
            AsPathSegmentType::AsSet as u8,
            // Missing segment_len byte
        ];

        match read_path_attribute(input) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath)
                );
                assert_eq!(data, Vec::<u8>::new());
            }
            _ => panic!("Expected MalformedASPath error"),
        }
    }

    #[test]
    fn test_read_path_attribute_as_path_truncated_asn_data() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::AsPath as u8,
            0x04, // Attribute length: 4 bytes
            AsPathSegmentType::AsSequence as u8,
            0x02, // segment_len: claims 2 ASNs (needs 4 bytes)
            0x00,
            0x10, // Only 1 ASN provided
        ];

        match read_path_attribute(input) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath)
                );
                assert_eq!(data, Vec::<u8>::new());
            }
            _ => panic!("Expected MalformedASPath error"),
        }
    }

    #[test]
    fn test_read_path_attribute_as_path_empty() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::AsPath as u8,
            0x00, // Attribute length: 0
        ];

        let (as_path, offset) = read_path_attribute(input).unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AsPath(AsPath { segments: vec![] }),
            }
        );
        assert_eq!(offset, 3);
    }

    #[test]
    fn test_read_path_attribute_as_path_multiple_segments() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::AsPath as u8,
            0x0a, // Attribute length: 10 bytes
            AsPathSegmentType::AsSequence as u8,
            0x02, // 2 ASNs
            0x00,
            0x0a, // ASN 10
            0x00,
            0x14, // ASN 20
            AsPathSegmentType::AsSet as u8,
            0x01, // 1 ASN
            0x00,
            0x1e, // ASN 30
        ];

        let (as_path, offset) = read_path_attribute(input).unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AsPath(AsPath {
                    segments: vec![
                        AsPathSegment {
                            segment_type: AsPathSegmentType::AsSequence,
                            segment_len: 2,
                            asn_list: vec![10, 20],
                        },
                        AsPathSegment {
                            segment_type: AsPathSegmentType::AsSet,
                            segment_len: 1,
                            asn_list: vec![30],
                        }
                    ]
                }),
            }
        );
        assert_eq!(offset, 13);
    }

    #[test]
    fn test_read_path_attribute_next_hop_ipv4() {
        let (as_path, offset) = read_path_attribute(PATH_ATTR_NEXT_HOP_IPV4).unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::NextHop(NextHopAddr::Ipv4(Ipv4Addr::new(200, 201, 202, 203))),
            }
        );
        assert_eq!(offset, 7);
    }

    #[test]
    fn test_read_path_attribute_next_hop_invalid_length() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE, // Attribute flags
            AttrType::NextHop as u8,  // Attribute type
            0x05,                     // Attribute length (invalid - should be 4)
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
        ];

        match read_path_attribute(input) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError)
                );
                assert_eq!(data, input.to_vec());
            }
            _ => panic!("Expected AttributeLengthError"),
        }
    }

    #[test]
    fn test_read_path_attribute_multi_exit_disc() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL,        // Attribute flags
            AttrType::MultiExtiDisc as u8, // Attribute type
            0x04,                          // Attribute length
            // Attribute value
            0x00,
            0x01,
            0x00,
            0x01,
        ];

        let (as_path, offset) = read_path_attribute(input).unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                value: PathAttrValue::MultiExtiDisc(65537),
            }
        );
        assert_eq!(offset, 7);
    }

    #[test]
    fn test_read_path_attribute_multi_exit_disc_invalid_length() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL,        // Attribute flags
            AttrType::MultiExtiDisc as u8, // Attribute type
            0x03,                          // Attribute length (invalid - should be 4)
            0x00,
            0x00,
            0x01,
        ];

        match read_path_attribute(input) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError)
                );
                assert_eq!(data, input.to_vec());
            }
            _ => panic!("Expected AttributeLengthError"),
        }
    }

    #[test]
    fn test_read_path_attribute_local_pref() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,  // Attribute flags
            AttrType::LocalPref as u8, // Attribute type
            0x04,                      // Attribute length
            // Attribute value
            0x00,
            0x00,
            0x0f,
            0x01,
        ];

        let (as_path, offset) = read_path_attribute(input).unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::LocalPref(3841),
            }
        );
        assert_eq!(offset, 7);
    }

    #[test]
    fn test_read_path_attribute_local_pref_invalid_length() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,  // Attribute flags
            AttrType::LocalPref as u8, // Attribute type
            0x03,                      // Attribute length (invalid - should be 4)
            0x00,
            0x00,
            0x0f,
        ];

        match read_path_attribute(input) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError)
                );
                assert_eq!(data, input.to_vec());
            }
            _ => panic!("Expected AttributeLengthError"),
        }
    }

    #[test]
    fn test_read_path_attribute_atomic_aggregate() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,        // Attribute flags
            AttrType::AtomicAggregate as u8, // Attribute type
            0x00,
        ];

        let (as_path, offset) = read_path_attribute(input).unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AtomicAggregate,
            }
        );
        assert_eq!(offset, 3);
    }

    #[test]
    fn test_read_path_attribute_atomic_aggregate_invalid_length() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,        // Attribute flags
            AttrType::AtomicAggregate as u8, // Attribute type
            0x01,                            // Attribute length (invalid - should be 0)
            0x00,
        ];

        match read_path_attribute(input) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError)
                );
                assert_eq!(data, input.to_vec());
            }
            _ => panic!("Expected AttributeLengthError"),
        }
    }

    #[test]
    fn test_read_path_attribute_aggregator_ipv4() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE, // Attribute flags
            AttrType::Aggregator as u8,                        // Attribute type
            0x06,                                              // Attribute length
            // Attribute value
            0x00, // ASN
            0x10,
            0x0a, // IPv4
            0x0b,
            0x0c,
            0x0d,
        ];

        let (as_path, offset) = read_path_attribute(input).unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::Aggregator(Aggregator {
                    asn: 16,
                    ip_addr: Ipv4Addr::from_str("10.11.12.13").unwrap(),
                }),
            }
        );
        assert_eq!(offset, 9);
    }

    #[test]
    fn test_read_path_attribute_aggregator_invalid_length() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE, // Attribute flags
            AttrType::Aggregator as u8,                        // Attribute type
            0x03, // Attribute length (invalid - should be 6)
            0x00, // ASN
            0x10,
            0x0a,
        ];

        match read_path_attribute(input) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError)
                );
                assert_eq!(data, input.to_vec());
            }
            _ => panic!("Expected AttributeLengthError"),
        }
    }

    macro_rules! test_message_from_bytes {
        ($name: ident, $input: expr, expected $expected:expr) => {
            #[test]
            fn $name() {
                let message = UpdateMessage::from_bytes($input).unwrap();
                assert_eq!(message, $expected)
            }
        };
    }

    test_message_from_bytes!(
        message_from_bytes,
        [
            WITHDRAWN_ROUTES_BYTES,
            &[
                0x00, 0x14, // Total path attribute length
            ],
            PATH_ATTR_ORIGIN_EGP,
            PATH_ATTR_AS_PATH,
            PATH_ATTR_NEXT_HOP_IPV4,
            &[
                0x18, 0x0a, 0x0b, 0x0f, // NLRI #1: /24 prefix
                0x18, 0x0a, 0x0b, 0x10, // NLRI #2: /24 prefix
            ]

        ].concat(),
        expected UpdateMessage{
            withdrawn_routes_len: 12,
            withdrawn_routes: vec![
                IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(10, 11, 12, 0),
                    prefix_length: 24,
                }),
                IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(10, 11, 13, 0),
                    prefix_length: 24,
                }),
                IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(10, 11, 14, 0),
                    prefix_length: 24,
                }),
            ],
            total_path_attributes_len: 20,
            path_attributes: vec![
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::Origin(Origin::try_from(1).unwrap()),
                },
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::AsPath(
                        AsPath {
                            segments: vec![
                                AsPathSegment {
                                    segment_type: AsPathSegmentType::AsSet,
                                    segment_len: 2,
                                    asn_list: vec![16, 274],
                                }
                            ]
                        }
                    ),
                },
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::NextHop(NextHopAddr::Ipv4(Ipv4Addr::new(200, 201, 202, 203))),
                }
            ],
            nlri_list: vec![
                IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(10, 11, 15, 0),
                    prefix_length: 24,
                }),
                IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(10, 11, 16, 0),
                    prefix_length: 24,
                }),
            ],
        }
    );

    test_message_from_bytes!(
        message_from_bytes_no_withdrawn_routes,
        [
            &[
                0x00, 0x00, // Withdrawn routes length
                0x00, 0x14, // Total path attribute length
            ],
            PATH_ATTR_ORIGIN_EGP,
            PATH_ATTR_AS_PATH,
            PATH_ATTR_NEXT_HOP_IPV4,
            &[
                0x18, 0x0a, 0x0b, 0x0f, // NLRI #1: /24 prefix
            ]

        ].concat(),
        expected UpdateMessage{
            withdrawn_routes_len: 0,
            withdrawn_routes: vec![],
            total_path_attributes_len: 20,
            path_attributes: vec![
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::Origin(Origin::try_from(1).unwrap()),
                },
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::AsPath(
                        AsPath {
                            segments: vec![
                                AsPathSegment {
                                    segment_type: AsPathSegmentType::AsSet,
                                    segment_len: 2,
                                    asn_list: vec![16, 274],
                                }
                            ]
                        }
                    ),
                },
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::NextHop(NextHopAddr::Ipv4(Ipv4Addr::new(200, 201, 202, 203))),
                }
            ],
            nlri_list: vec![
                IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(10, 11, 15, 0),
                    prefix_length: 24,
                }),
            ],
        }
    );

    test_message_from_bytes!(
        message_from_bytes_no_path_attributes,
        [
            WITHDRAWN_ROUTES_BYTES,
            &[
                0x00, 0x00, // Total path attribute length
            ],
        ].concat(),
        expected UpdateMessage{
            withdrawn_routes_len: 12,
            withdrawn_routes: vec![
                IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(10, 11, 12, 0),
                    prefix_length: 24,
                }),
                IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(10, 11, 13, 0),
                    prefix_length: 24,
                }),
                IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(10, 11, 14, 0),
                    prefix_length: 24,
                }),
            ],
            total_path_attributes_len: 0,
            path_attributes: vec![],
            nlri_list: vec![],
        }
    );

    const INPUT_BODY: &[u8] = &[
        0x00,
        0x0c, // Withdrawn routes length (12 bytes)
        0x18,
        0x0a,
        0x0b,
        0x0c, // Withdrawn route #1: /24 prefix
        0x18,
        0x0a,
        0x0b,
        0x0d, // Withdrawn route #2: /24 prefix
        0x18,
        0x0a,
        0x0b,
        0x0e, // Withdrawn route #3: /24 prefix
        0x00,
        0x14,                     // Total path attribute length
        PathAttrFlag::TRANSITIVE, // Attribute flags
        AttrType::Origin as u8,   // Attribute type
        0x01,                     // Attribute length
        1,                        // Origin value: EGP
        PathAttrFlag::TRANSITIVE, // Attribute flags
        AttrType::AsPath as u8,   // Attribute type
        0x06,                     // Attribute length
        AsPathSegmentType::AsSet as u8,
        0x02, // Number of ASes
        0x00,
        0x10, // ASN: 16
        0x01,
        0x12,                     // ASN: 274
        PathAttrFlag::TRANSITIVE, // Attribute flags
        AttrType::NextHop as u8,  // Attribute type
        0x04,                     // Attribute length
        0xc8,
        0xc9,
        0xca,
        0xcb,
        0x18,
        0x0a,
        0x0b,
        0x0f, // NLRI #1: /24 prefix
        0x18,
        0x0a,
        0x0b,
        0x10, // NLRI #2: /24 prefix
    ];

    #[test]
    fn test_update_message_encode_decode() {
        // Decode the message
        let message = UpdateMessage::from_bytes(INPUT_BODY.to_vec()).unwrap();

        // Encode it back
        let encoded = message.to_bytes();

        // Should match the original input
        assert_eq!(encoded, INPUT_BODY);
    }

    #[test]
    fn test_update_message_serialize() {
        // Decode the message
        let message = UpdateMessage::from_bytes(INPUT_BODY.to_vec()).unwrap();

        // Serialize it (includes BGP header)
        let serialized = message.serialize();

        // Check BGP header
        assert_eq!(&serialized[0..16], &[0xff; 16]); // Marker
        let length = u16::from_be_bytes([serialized[16], serialized[17]]);
        assert_eq!(length, 19 + INPUT_BODY.len() as u16); // Header + body
        assert_eq!(serialized[18], 2); // Message type: UPDATE

        // Check body
        assert_eq!(&serialized[19..], INPUT_BODY);
    }

    #[test]
    fn test_new_withdraw() {
        // Create a withdraw message with multiple prefixes
        let withdrawn_routes = vec![
            IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 0, 0),
                prefix_length: 24,
            }),
            IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(192, 168, 1, 0),
                prefix_length: 24,
            }),
        ];

        let message = UpdateMessage::new_withdraw(withdrawn_routes.clone());

        // Verify message structure
        assert_eq!(message.withdrawn_routes, withdrawn_routes);
        assert_eq!(message.path_attributes, vec![]);
        assert_eq!(message.nlri_list, vec![]);
        assert_eq!(message.total_path_attributes_len, 0);

        // Verify the withdrawn routes length is calculated correctly
        // 10.0.0.0/24 = 1 byte (prefix length) + 3 bytes (address) = 4 bytes
        // 192.168.1.0/24 = 1 byte (prefix length) + 3 bytes (address) = 4 bytes
        // Total = 8 bytes
        assert_eq!(message.withdrawn_routes_len, 8);
    }

    #[test]
    fn test_new_withdraw_serialization() {
        // Create a withdraw message
        let withdrawn_routes = vec![IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        })];

        let message = UpdateMessage::new_withdraw(withdrawn_routes);

        // Serialize the message
        let serialized = message.serialize();

        // Verify BGP header
        assert_eq!(&serialized[0..16], &[0xff; 16]); // Marker
        let length = u16::from_be_bytes([serialized[16], serialized[17]]);
        assert_eq!(length, serialized.len() as u16); // Length field matches actual length
        assert_eq!(serialized[18], 2); // Message type: UPDATE

        // Decode the body
        let body = &serialized[19..];

        // Withdrawn routes length
        let withdrawn_len = u16::from_be_bytes([body[0], body[1]]);
        assert_eq!(withdrawn_len, 4); // 1 byte prefix length + 3 bytes address

        // Withdrawn route data
        assert_eq!(body[2], 24); // Prefix length
        assert_eq!(&body[3..6], &[10, 0, 0]); // Address (only significant octets)

        // Total path attributes length
        let path_attr_len = u16::from_be_bytes([body[6], body[7]]);
        assert_eq!(path_attr_len, 0);

        // No NLRI
        assert_eq!(body.len(), 8);
    }

    #[test]
    fn test_get_local_pref() {
        let msg = UpdateMessage::new(
            Origin::IGP,
            vec![],
            Ipv4Addr::new(10, 0, 0, 1),
            vec![],
            Some(200),
            None,
            false,
        );
        assert_eq!(msg.get_local_pref(), Some(200));

        let msg_no_pref = UpdateMessage::new(
            Origin::IGP,
            vec![],
            Ipv4Addr::new(10, 0, 0, 1),
            vec![],
            None,
            None,
            false,
        );
        assert_eq!(msg_no_pref.get_local_pref(), None);
    }

    #[test]
    fn test_get_med() {
        let msg = UpdateMessage::new(
            Origin::IGP,
            vec![],
            Ipv4Addr::new(10, 0, 0, 1),
            vec![],
            None,
            Some(50),
            false,
        );
        assert_eq!(msg.get_med(), Some(50));

        let msg_no_med = UpdateMessage::new(
            Origin::IGP,
            vec![],
            Ipv4Addr::new(10, 0, 0, 1),
            vec![],
            None,
            None,
            false,
        );
        assert_eq!(msg_no_med.get_med(), None);
    }

    #[test]
    fn test_update_message_new_encode_decode() {
        let test_cases = vec![
            (Origin::IGP, None, None, false),
            (Origin::IGP, Some(200), None, false),
            (Origin::INCOMPLETE, None, Some(50), false),
            (Origin::IGP, None, None, true),
            (Origin::EGP, Some(150), Some(100), true),
        ];

        for (origin, local_pref, med, atomic_aggregate) in test_cases {
            let msg = UpdateMessage::new(
                origin,
                vec![],
                Ipv4Addr::new(10, 0, 0, 1),
                vec![],
                local_pref,
                med,
                atomic_aggregate,
            );

            let bytes = msg.to_bytes();
            let parsed = UpdateMessage::from_bytes(bytes).unwrap();

            assert_eq!(parsed.get_origin(), Some(origin));
            assert_eq!(parsed.get_as_path(), Some(vec![]));
            assert_eq!(parsed.get_next_hop(), Some(Ipv4Addr::new(10, 0, 0, 1)));
            assert_eq!(parsed.get_local_pref(), local_pref);
            assert_eq!(parsed.get_med(), med);
            assert_eq!(parsed.get_atomic_aggregate(), atomic_aggregate);
        }
    }

    #[test]
    fn test_malformed_attribute_list_lengths_too_large() {
        // Create a message with Withdrawn Routes Length + Total Attribute Length + 4 > body_length
        let input: &[u8] = &[
            0x00, 0x04, // Withdrawn routes length = 4
            0x18, 0x0a, 0x0b, 0x0c, // Withdrawn route data (4 bytes: /24 prefix)
            0x00,
            0x64, // Total path attribute length = 100
                  // Body ends here (8 bytes total), but we claim 100 bytes of attributes
                  // Check: 4 + 100 + 4 = 108 > 8, should error
        ];

        match UpdateMessage::from_bytes(input.to_vec()) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList)
                );
                assert_eq!(data, Vec::<u8>::new());
            }
            _ => panic!("Expected MalformedAttributeList error"),
        }
    }

    #[test]
    fn test_attribute_flags_well_known_wrong_optional_bit() {
        let test_cases = vec![
            ("origin", AttrType::Origin as u8, vec![0x01, 0x00]),
            ("as_path", AttrType::AsPath as u8, vec![0x00]),
            (
                "next_hop",
                AttrType::NextHop as u8,
                vec![0x04, 0x0a, 0x00, 0x00, 0x01],
            ),
            (
                "local_pref",
                AttrType::LocalPref as u8,
                vec![0x04, 0x00, 0x00, 0x00, 0x64],
            ),
            (
                "atomic_aggregate",
                AttrType::AtomicAggregate as u8,
                vec![0x00],
            ),
        ];

        for (name, attr_type, attr_data) in test_cases {
            let mut input = vec![PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE, attr_type];
            input.extend_from_slice(&attr_data);

            match read_path_attribute(&input) {
                Err(ParserError::BgpError { error, data }) => {
                    assert_eq!(
                        error,
                        BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError),
                        "Failed for {}",
                        name
                    );
                    assert_eq!(
                        data,
                        vec![
                            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                            attr_type,
                            attr_data[0]
                        ],
                        "Failed for {}",
                        name
                    );
                }
                _ => panic!("Expected AttributeFlagsError for {}", name),
            }
        }
    }

    #[test]
    fn test_attribute_flags_well_known_partial_bit_set() {
        let test_cases = vec![
            ("origin", AttrType::Origin as u8, vec![0x01, 0x00]),
            ("as_path", AttrType::AsPath as u8, vec![0x00]),
            (
                "next_hop",
                AttrType::NextHop as u8,
                vec![0x04, 0x0a, 0x00, 0x00, 0x01],
            ),
            (
                "local_pref",
                AttrType::LocalPref as u8,
                vec![0x04, 0x00, 0x00, 0x00, 0x64],
            ),
            (
                "atomic_aggregate",
                AttrType::AtomicAggregate as u8,
                vec![0x00],
            ),
        ];

        for (name, attr_type, attr_data) in test_cases {
            let mut input = vec![PathAttrFlag::TRANSITIVE | PathAttrFlag::PARTIAL, attr_type];
            input.extend_from_slice(&attr_data);

            match read_path_attribute(&input) {
                Err(ParserError::BgpError { error, data }) => {
                    assert_eq!(
                        error,
                        BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError),
                        "Failed for {}",
                        name
                    );
                    assert_eq!(
                        data,
                        vec![
                            PathAttrFlag::TRANSITIVE | PathAttrFlag::PARTIAL,
                            attr_type,
                            attr_data[0]
                        ],
                        "Failed for {}",
                        name
                    );
                }
                _ => panic!("Expected AttributeFlagsError for {}", name),
            }
        }
    }

    #[test]
    fn test_attribute_flags_optional_wrong_flags() {
        let test_cases = vec![
            (
                "med_missing_optional",
                AttrType::MultiExtiDisc as u8,
                PathAttrFlag::TRANSITIVE,
                vec![0x04, 0x00, 0x00, 0x00, 0x01],
            ),
            (
                "aggregator_missing_optional",
                AttrType::Aggregator as u8,
                PathAttrFlag::TRANSITIVE,
                vec![0x06, 0x00, 0x10, 0x0a, 0x0b, 0x0c, 0x0d],
            ),
        ];

        for (name, attr_type, wrong_flags, attr_data) in test_cases {
            let mut input = vec![wrong_flags, attr_type];
            input.extend_from_slice(&attr_data);

            match read_path_attribute(&input) {
                Err(ParserError::BgpError { error, data }) => {
                    assert_eq!(
                        error,
                        BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError),
                        "Failed for {}",
                        name
                    );
                    assert_eq!(
                        data,
                        vec![wrong_flags, attr_type, attr_data[0]],
                        "Failed for {}",
                        name
                    );
                }
                _ => panic!("Expected AttributeFlagsError for {}", name),
            }
        }
    }

    #[test]
    fn test_attribute_flags_extended_length_data() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::EXTENDED_LENGTH,
            AttrType::Origin as u8,
            0x00,
            0x01,
            0x00,
        ];

        match read_path_attribute(input) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError)
                );
                assert_eq!(
                    data,
                    vec![
                        PathAttrFlag::OPTIONAL | PathAttrFlag::EXTENDED_LENGTH,
                        AttrType::Origin as u8,
                        0x00,
                        0x01
                    ]
                );
            }
            _ => panic!("Expected AttributeFlagsError"),
        }
    }

    #[test]
    fn test_attribute_flags_aggregator_partial_bit_allowed() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE | PathAttrFlag::PARTIAL,
            AttrType::Aggregator as u8,
            0x06,
            0x00,
            0x10,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
        ];

        let (attr, offset) = read_path_attribute(input).unwrap();
        assert_eq!(
            attr.flags.0,
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE | PathAttrFlag::PARTIAL
        );
        assert_eq!(offset, 9);
    }

    #[test]
    fn test_attribute_flags_med_partial_bit_allowed() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::PARTIAL,
            AttrType::MultiExtiDisc as u8,
            0x04,
            0x00,
            0x00,
            0x00,
            0x01,
        ];

        let (attr, offset) = read_path_attribute(input).unwrap();
        assert_eq!(attr.flags.0, PathAttrFlag::OPTIONAL | PathAttrFlag::PARTIAL);
        assert_eq!(offset, 7);
    }
}
