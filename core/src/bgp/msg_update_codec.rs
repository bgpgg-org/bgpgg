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
use super::msg_update::{TOTAL_ATTR_LENGTH_SIZE, WITHDRAWN_ROUTES_LENGTH_SIZE};
use super::msg_update_types::{
    attr_type_code, Aggregator, AsPath, AsPathSegment, AsPathSegmentType, AttrType, NextHopAddr,
    Origin, PathAttrFlag, PathAttrValue, PathAttribute,
};
use super::utils::{is_valid_unicast_ipv4, read_u32, IpNetwork, ParserError};
use std::collections::HashSet;
use std::net::Ipv4Addr;

pub(super) fn validate_attribute_flags(
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

pub(super) fn validate_attribute_length(
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
        AttrType::Communities => attr_len.is_multiple_of(4), // Must be multiple of 4
    };

    if !valid {
        // RFC 4271 Section 6.3: for recognized optional attributes, use OptionalAttributeError
        let error = if attr_type.is_optional() {
            UpdateMessageError::OptionalAttributeError
        } else {
            UpdateMessageError::AttributeLengthError
        };
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(error),
            data: attr_bytes.to_vec(),
        });
    }

    Ok(())
}

pub(super) fn validate_update_message_lengths(
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

pub(super) fn validate_well_known_mandatory_attributes(
    path_attributes: &[PathAttribute],
    has_nlri: bool,
) -> Result<(), ParserError> {
    // RFC 4271 Section 5: well-known mandatory attributes MUST be included
    // in every UPDATE message that contains NLRI
    if !has_nlri {
        return Ok(());
    }

    let has_origin = path_attributes
        .iter()
        .any(|attr| matches!(attr.value, PathAttrValue::Origin(_)));
    let has_as_path = path_attributes
        .iter()
        .any(|attr| matches!(attr.value, PathAttrValue::AsPath(_)));
    let has_next_hop = path_attributes
        .iter()
        .any(|attr| matches!(attr.value, PathAttrValue::NextHop(_)));

    if !has_origin {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::MissingWellKnownAttribute),
            data: vec![attr_type_code::ORIGIN],
        });
    }

    if !has_as_path {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::MissingWellKnownAttribute),
            data: vec![attr_type_code::AS_PATH],
        });
    }

    if !has_next_hop {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::MissingWellKnownAttribute),
            data: vec![attr_type_code::NEXT_HOP],
        });
    }

    Ok(())
}

pub(super) fn parse_attr_type(
    bytes: &[u8],
    flags: u8,
    attr_type_code: u8,
    attr_len: u16,
) -> Result<Option<AttrType>, ParserError> {
    match AttrType::try_from(attr_type_code) {
        Ok(attr_type) => Ok(Some(attr_type)),
        Err(_) => {
            // Unrecognized well-known attribute (OPTIONAL=0)
            // RFC 4271 Section 6.3: return error with full attribute data
            if flags & PathAttrFlag::OPTIONAL == 0 {
                let extended_len = flags & PathAttrFlag::EXTENDED_LENGTH != 0;
                let header_len = if extended_len { 4 } else { 3 };
                let total_attr_len = header_len + attr_len as usize;
                let attr_data = bytes[..total_attr_len.min(bytes.len())].to_vec();

                Err(ParserError::BgpError {
                    error: BgpError::UpdateMessageError(
                        UpdateMessageError::UnrecognizedWellKnownAttribute,
                    ),
                    data: attr_data,
                })
            } else {
                // RFC 4271 Section 6.3: optional attributes (transitive or non-transitive)
                // Return None to signal this should be stored as Unknown variant
                Ok(None)
            }
        }
    }
}

pub(super) fn read_attr_as_path(bytes: &[u8]) -> Result<AsPath, ParserError> {
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

pub(super) fn read_attr_next_hop(bytes: &[u8]) -> NextHopAddr {
    // Length already validated by validate_attribute_length
    NextHopAddr::Ipv4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

pub(super) fn read_attr_aggregator(bytes: &[u8]) -> Aggregator {
    // Length already validated by validate_attribute_length
    let asn = u16::from_be_bytes([bytes[0], bytes[1]]);
    let ip_addr = Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]);

    Aggregator { asn, ip_addr }
}

pub(super) fn read_attr_communities(bytes: &[u8]) -> Result<Vec<u32>, ParserError> {
    // Length must be multiple of 4 (each community is 4 octets)
    if !bytes.len().is_multiple_of(4) {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    let mut communities = Vec::new();
    for chunk in bytes.chunks_exact(4) {
        let community = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        communities.push(community);
    }

    Ok(communities)
}

pub(super) fn read_path_attribute(bytes: &[u8]) -> Result<(PathAttribute, u8), ParserError> {
    let attribute_flag = PathAttrFlag(bytes[0]);
    let attr_type_code = bytes[1];

    let attr_len = match attribute_flag.extended_len() {
        true => u16::from_be_bytes([bytes[2], bytes[3]]),
        false => bytes[2] as u16,
    };

    let attr_type_opt = parse_attr_type(bytes, attribute_flag.0, attr_type_code, attr_len)?;

    let attr_val = match attr_type_opt {
        Some(attr_type) => {
            // Known attribute - validate and parse normally
            validate_attribute_flags(bytes[0], &attr_type, attr_type_code, attr_len)?;

            let offset = if attribute_flag.extended_len() { 4 } else { 3 };
            let attr_total_len = offset + attr_len as usize;
            let attr_bytes = &bytes[..attr_total_len.min(bytes.len())];

            validate_attribute_length(&attr_type, attr_len, attr_bytes)?;

            let attr_data = &bytes[offset..offset + attr_len as usize];

            match attr_type {
                AttrType::Origin => {
                    let value = bytes[offset];
                    let origin = match value {
                        0 => Origin::IGP,
                        1 => Origin::EGP,
                        2 => Origin::INCOMPLETE,
                        _ => {
                            return Err(ParserError::BgpError {
                                error: BgpError::UpdateMessageError(
                                    UpdateMessageError::InvalidOriginAttribute,
                                ),
                                data: attr_bytes.to_vec(),
                            });
                        }
                    };
                    PathAttrValue::Origin(origin)
                }
                AttrType::AsPath => {
                    let as_path = read_attr_as_path(attr_data)?;
                    PathAttrValue::AsPath(as_path)
                }
                AttrType::NextHop => {
                    let next_hop = read_attr_next_hop(attr_data);

                    // RFC 4271: NEXT_HOP must be a valid IP host address
                    if let NextHopAddr::Ipv4(addr) = next_hop {
                        if !is_valid_unicast_ipv4(u32::from(addr)) {
                            return Err(ParserError::BgpError {
                                error: BgpError::UpdateMessageError(
                                    UpdateMessageError::InvalidNextHopAttribute,
                                ),
                                data: attr_bytes.to_vec(),
                            });
                        }
                    }

                    PathAttrValue::NextHop(next_hop)
                }
                AttrType::MultiExtiDisc => {
                    let multi_exit_disc = read_u32(attr_data)?;
                    PathAttrValue::MultiExtiDisc(multi_exit_disc)
                }
                AttrType::LocalPref => {
                    let local_pref = read_u32(attr_data)?;
                    PathAttrValue::LocalPref(local_pref)
                }
                AttrType::AtomicAggregate => {
                    if attr_len > 0 {
                        return Err(ParserError::BgpError {
                            error: BgpError::UpdateMessageError(
                                UpdateMessageError::AttributeLengthError,
                            ),
                            data: Vec::new(),
                        });
                    }
                    PathAttrValue::AtomicAggregate
                }
                AttrType::Aggregator => {
                    let aggregator = read_attr_aggregator(attr_data);
                    PathAttrValue::Aggregator(aggregator)
                }
                AttrType::Communities => {
                    let communities = read_attr_communities(attr_data)?;
                    PathAttrValue::Communities(communities)
                }
            }
        }
        None => {
            // Unknown optional attribute
            // RFC 4271 Section 6.3: set PARTIAL bit for transitive, store raw data
            let offset = if attribute_flag.extended_len() { 4 } else { 3 };
            let data = bytes[offset..offset + attr_len as usize].to_vec();

            let mut flags = attribute_flag.0;
            if flags & PathAttrFlag::TRANSITIVE != 0 {
                flags |= PathAttrFlag::PARTIAL;
            }

            PathAttrValue::Unknown {
                type_code: attr_type_code,
                flags,
                data,
            }
        }
    };

    let offset = if attribute_flag.extended_len() { 4 } else { 3 };
    let total_offset = offset + attr_len as usize;

    // Update PathAttribute flags if PARTIAL bit was set for unknown transitive
    let final_flags = match &attr_val {
        PathAttrValue::Unknown { flags, .. } => PathAttrFlag(*flags),
        _ => attribute_flag,
    };

    let attribute = PathAttribute {
        flags: final_flags,
        value: attr_val,
    };

    Ok((attribute, total_offset as u8))
}

pub(super) fn read_path_attributes(bytes: &[u8]) -> Result<Vec<PathAttribute>, ParserError> {
    let mut cursor = 0;
    let mut path_attributes: Vec<PathAttribute> = Vec::new();
    let mut seen_type_codes: HashSet<u8> = HashSet::new();

    while cursor < bytes.len() {
        let (attribute, offset) = read_path_attribute(&bytes[cursor..])?;
        cursor += offset as usize;

        let type_code = attribute.type_code();
        if !seen_type_codes.insert(type_code) {
            return Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
                data: Vec::new(),
            });
        }

        path_attributes.push(attribute);
    }

    Ok(path_attributes)
}

pub(super) fn write_nlri_list(nlri_list: &[IpNetwork]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for network in nlri_list {
        match network {
            IpNetwork::V4(net) => {
                bytes.push(net.prefix_length);
                let octets = net.address.octets();
                let num_octets = net.prefix_length.div_ceil(8) as usize;
                bytes.extend_from_slice(&octets[..num_octets]);
            }
            IpNetwork::V6(net) => {
                bytes.push(net.prefix_length);
                let octets = net.address.octets();
                let num_octets = net.prefix_length.div_ceil(8) as usize;
                bytes.extend_from_slice(&octets[..num_octets]);
            }
        }
    }
    bytes
}

pub(super) fn write_path_attribute(attr: &PathAttribute) -> Vec<u8> {
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
        PathAttrValue::Communities(communities) => {
            let mut comm_bytes = Vec::new();
            for &community in communities {
                comm_bytes.extend_from_slice(&community.to_be_bytes());
            }
            comm_bytes
        }
        PathAttrValue::Unknown { data, .. } => data.clone(),
    };

    // Write flags (Unknown stores its own flags)
    let flags = match &attr.value {
        PathAttrValue::Unknown { flags, .. } => *flags,
        _ => attr.flags.0,
    };
    bytes.push(flags);

    // Write attribute type (Unknown stores its own type)
    let attr_type = match &attr.value {
        PathAttrValue::Origin(_) => AttrType::Origin as u8,
        PathAttrValue::AsPath(_) => AttrType::AsPath as u8,
        PathAttrValue::NextHop(_) => AttrType::NextHop as u8,
        PathAttrValue::MultiExtiDisc(_) => AttrType::MultiExtiDisc as u8,
        PathAttrValue::LocalPref(_) => AttrType::LocalPref as u8,
        PathAttrValue::AtomicAggregate => AttrType::AtomicAggregate as u8,
        PathAttrValue::Aggregator(_) => AttrType::Aggregator as u8,
        PathAttrValue::Communities(_) => AttrType::Communities as u8,
        PathAttrValue::Unknown { type_code, .. } => *type_code,
    };
    bytes.push(attr_type);

    // Write length (use extended_len from Unknown's flags if applicable)
    let attr_len = attr_value_bytes.len();
    let extended_len = flags & PathAttrFlag::EXTENDED_LENGTH != 0;
    if extended_len {
        bytes.extend_from_slice(&(attr_len as u16).to_be_bytes());
    } else {
        bytes.push(attr_len as u8);
    }

    // Write attribute value
    bytes.extend_from_slice(&attr_value_bytes);

    bytes
}

pub(super) fn write_path_attributes(path_attributes: &[PathAttribute]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for attr in path_attributes {
        bytes.extend_from_slice(&write_path_attribute(attr));
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_notification::{BgpError, UpdateMessageError};
    use crate::bgp::msg_update_types::AttrType;

    const PATH_ATTR_ORIGIN_EGP: &[u8] =
        &[PathAttrFlag::TRANSITIVE, AttrType::Origin as u8, 0x01, 1];

    const PATH_ATTR_COMMUNITIES_TWO: &[u8] = &[
        PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
        AttrType::Communities as u8,
        0x08,
        0x00,
        0x01,
        0x00,
        0x64,
        0xFF,
        0xFF,
        0xFF,
        0x01,
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
    fn test_read_path_attribute_origin_invalid_value() {
        let input: &[u8] = &[PathAttrFlag::TRANSITIVE, AttrType::Origin as u8, 0x01, 0x03];

        match read_path_attribute(input) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::InvalidOriginAttribute)
                );
                assert_eq!(data, input);
            }
            _ => panic!("Expected InvalidOriginAttribute error"),
        }
    }

    #[test]
    fn test_read_path_attribute_communities() {
        let (attr, offset) = read_path_attribute(PATH_ATTR_COMMUNITIES_TWO).unwrap();

        assert_eq!(
            attr,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::Communities(vec![0x00010064, 0xFFFFFF01]),
            }
        );
        assert_eq!(offset, 11);
    }

    #[test]
    fn test_write_path_attribute_communities() {
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::Communities(vec![0x00010064, 0xFFFFFF01]),
        };

        let bytes = write_path_attribute(&attr);
        assert_eq!(bytes, PATH_ATTR_COMMUNITIES_TWO);
    }

    #[test]
    fn test_communities_roundtrip() {
        let original_communities = vec![0x00010064, 0xFFFFFF01, 0xFFFFFF02];
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::Communities(original_communities.clone()),
        };

        let bytes = write_path_attribute(&attr);
        let (parsed_attr, _) = read_path_attribute(&bytes).unwrap();

        if let PathAttrValue::Communities(communities) = parsed_attr.value {
            assert_eq!(communities, original_communities);
        } else {
            panic!("Expected Communities attribute after roundtrip");
        }
    }
}
