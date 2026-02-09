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
    attr_type_code, Aggregator, AsPath, AsPathSegment, AsPathSegmentType, AttrType, LargeCommunity,
    MpReachNlri, MpUnreachNlri, NextHopAddr, Origin, PathAttrFlag, PathAttrValue, PathAttribute,
};
use super::multiprotocol::{Afi, Safi};
use super::utils::{
    is_valid_unicast_ipv4, parse_nlri_list, parse_nlri_v6_list, read_u32, ParserError,
};
use crate::log::warn;
use crate::net::IpNetwork;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

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
        AttrType::Aggregator => attr_len == 6 || attr_len == 8, // 2-byte or 4-byte ASN + IPv4
        AttrType::AsPath => true,                               // Variable length
        AttrType::Communities => attr_len.is_multiple_of(4),    // Must be multiple of 4
        // RFC 4456: ORIGINATOR_ID is 4 bytes (IPv4 address)
        AttrType::OriginatorId => attr_len == 4,
        // RFC 4456: CLUSTER_LIST is N*4 bytes (list of IPv4 addresses)
        AttrType::ClusterList => attr_len.is_multiple_of(4),
        AttrType::MpReachNlri => true,   // Variable length
        AttrType::MpUnreachNlri => true, // Variable length
        AttrType::ExtendedCommunities => attr_len.is_multiple_of(8), // Must be multiple of 8
        AttrType::As4Path => true,       // Variable length (RFC 6793)
        AttrType::As4Aggregator => true, // Variable length - validation in parser (RFC 6793)
        AttrType::LargeCommunities => attr_len.is_multiple_of(12), // Must be multiple of 12
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
    // RFC 2858: MP_REACH_NLRI can replace NEXT_HOP for multiprotocol
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
    let has_mp_reach = path_attributes
        .iter()
        .any(|attr| matches!(attr.value, PathAttrValue::MpReachNlri(_)));

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

    // NEXT_HOP is required UNLESS MP_REACH_NLRI is present
    if !has_next_hop && !has_mp_reach {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::MissingWellKnownAttribute),
            data: vec![attr_type_code::NEXT_HOP],
        });
    }

    Ok(())
}

fn validate_nlri_afi(afi: &Afi, routes: &[IpNetwork]) -> bool {
    for route in routes {
        match (afi, route) {
            (Afi::Ipv4, IpNetwork::V4(_)) | (Afi::Ipv6, IpNetwork::V6(_)) => {}
            _ => return false,
        }
    }
    true
}

fn optional_attribute_error(attr_bytes: &[u8]) -> ParserError {
    ParserError::BgpError {
        error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
        data: attr_bytes.to_vec(),
    }
}

fn validate_mp_reach_buffer(
    afi: &Afi,
    next_hop_len: usize,
    bytes: &[u8],
    header_size: usize,
    reserved_size: usize,
) -> Result<(), ParserError> {
    // Validate next hop length based on AFI: IPv4=4 bytes, IPv6=16 or 32 bytes (global or global+link-local)
    // Per RFC 2545: IPv6 MP_REACH_NLRI must have IPv6 next hop (16 or 32 bytes)
    match (afi, next_hop_len) {
        (Afi::Ipv4, 4) | (Afi::Ipv6, 16) | (Afi::Ipv6, 32) => {}
        _ => {
            return Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError),
                data: Vec::new(),
            });
        }
    }

    let min_total_size = header_size + next_hop_len + reserved_size;
    if bytes.len() < min_total_size {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError),
            data: Vec::new(),
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

pub(super) fn read_attr_as_path(bytes: &[u8], use_4byte_asn: bool) -> Result<AsPath, ParserError> {
    // Empty AS_PATH is valid (iBGP or locally originated routes)
    if bytes.is_empty() {
        return Ok(AsPath { segments: vec![] });
    }

    // RFC 6793: Use encoding based on negotiated four-octet AS capability
    let asn_size = if use_4byte_asn { 4 } else { 2 };
    try_read_as_path(bytes, asn_size)
}

fn try_read_as_path(bytes: &[u8], asn_size: usize) -> Result<AsPath, ParserError> {
    let mut segments = vec![];
    let mut cursor = 0;

    while cursor < bytes.len() {
        if cursor + 2 > bytes.len() {
            return Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
                data: Vec::new(),
            });
        }

        let segment_type = AsPathSegmentType::try_from(bytes[cursor])?;
        let segment_len = bytes[cursor + 1] as usize;

        // Path segment length cannot be zero
        if segment_len == 0 {
            return Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
                data: Vec::new(),
            });
        }

        let segment_data_size = segment_len * asn_size;
        let segment_total_size = 2 + segment_data_size;

        if cursor + segment_total_size > bytes.len() {
            return Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
                data: Vec::new(),
            });
        }

        let asn_list = (0..segment_len)
            .map(|i| {
                let pos = cursor + 2 + (i * asn_size);
                if asn_size == 4 {
                    u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                } else {
                    u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as u32
                }
            })
            .collect();

        segments.push(AsPathSegment {
            segment_type,
            segment_len: segment_len as u8,
            asn_list,
        });

        cursor += segment_total_size;
    }

    // Verify we consumed all bytes
    if cursor != bytes.len() {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
            data: Vec::new(),
        });
    }

    Ok(AsPath { segments })
}

pub(super) fn read_attr_as4_path(bytes: &[u8]) -> Result<AsPath, ParserError> {
    // RFC 6793 §10: AS4_PATH validation
    // - Attribute length must be at least 6 bytes to carry one AS number
    // - Attribute length must be multiple of 2
    if bytes.len() < 6 || !bytes.len().is_multiple_of(2) {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
            data: Vec::new(),
        });
    }

    // Parse using the common AS_PATH parser with 4-byte ASNs
    let mut path = try_read_as_path(bytes, 4)?;

    // RFC 6793: AS_CONFED_SEQUENCE and AS_CONFED_SET MUST NOT be carried in AS4_PATH
    // If received, discard these segments
    let original_len = path.segments.len();
    path.segments.retain(|seg| {
        !matches!(
            seg.segment_type,
            AsPathSegmentType::AsConfedSequence | AsPathSegmentType::AsConfedSet
        )
    });

    // Log if we discarded confederation segments
    if path.segments.len() < original_len {
        warn!("discarded AS_CONFED segments from AS4_PATH per RFC 6793");
    }

    Ok(path)
}

pub(super) fn read_attr_next_hop(bytes: &[u8]) -> NextHopAddr {
    // Length already validated by validate_attribute_length
    let mut octets = [0u8; 4];
    octets.copy_from_slice(&bytes[0..4]);
    NextHopAddr::Ipv4(Ipv4Addr::from(octets))
}

pub(super) fn read_attr_aggregator(bytes: &[u8]) -> Aggregator {
    // RFC 6793: AGGREGATOR can be 6 bytes (2-byte ASN) or 8 bytes (4-byte ASN)
    // depending on whether both peers support 4-byte ASN capability
    if bytes.len() == 8 {
        // 4-byte ASN encoding (NEW speaker to NEW speaker)
        let asn = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let ip_addr = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
        Aggregator { asn, ip_addr }
    } else {
        // 2-byte ASN encoding (OLD speaker or to OLD speaker)
        let asn = u16::from_be_bytes([bytes[0], bytes[1]]) as u32;
        let ip_addr = Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]);
        Aggregator { asn, ip_addr }
    }
}

pub(super) fn read_attr_as4_aggregator(bytes: &[u8]) -> Result<Aggregator, ParserError> {
    if bytes.len() != 8 {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    Ok(read_attr_aggregator(bytes))
}

/// Check if a segment type is a confederation segment
fn is_confed_segment(segment_type: AsPathSegmentType) -> bool {
    matches!(
        segment_type,
        AsPathSegmentType::AsConfedSequence | AsPathSegmentType::AsConfedSet
    )
}

/// Count non-confederation ASNs in an AS path
fn count_non_confed_asns(path: &AsPath) -> usize {
    path.segments
        .iter()
        .filter(|seg| !is_confed_segment(seg.segment_type))
        .map(|seg| seg.asn_list.len())
        .sum()
}

/// Merge AS_PATH and AS4_PATH per RFC 6793 Section 4.2.3
/// This is used when receiving routes from a 2-byte-only speaker that added AS4_PATH
pub fn merge_as_paths(as_path: &AsPath, as4_path: &AsPath) -> AsPath {
    // Count non-confederation ASNs in each path
    let as_path_count = count_non_confed_asns(as_path);
    let as4_path_count = count_non_confed_asns(as4_path);

    // RFC 6793: If AS4_PATH is longer than AS_PATH, discard it (malformed)
    if as4_path_count > as_path_count {
        return as_path.clone();
    }

    // Calculate how many ASNs to prepend from AS_PATH
    let prepend_count = as_path_count - as4_path_count;

    let mut result_segments = Vec::new();
    let mut prepended = 0;

    // RFC 6793: Copy prepend_count ASNs from AS_PATH
    // Include confederation segments only if they are leading or adjacent to prepended segments
    for segment in &as_path.segments {
        if is_confed_segment(segment.segment_type) {
            // Only include confederation segments if we're still prepending
            if prepended < prepend_count {
                result_segments.push(segment.clone());
            } else {
                // Done prepending - stop processing AS_PATH
                break;
            }
        } else if prepended < prepend_count {
            let take_count = (prepend_count - prepended).min(segment.asn_list.len());
            if take_count > 0 {
                result_segments.push(AsPathSegment {
                    segment_type: segment.segment_type,
                    segment_len: take_count as u8,
                    asn_list: segment.asn_list[..take_count].to_vec(),
                });
                prepended += take_count;
            }
        } else {
            // Done prepending - stop processing AS_PATH
            break;
        }
    }

    // Then, append all non-confederation segments from AS4_PATH
    for segment in &as4_path.segments {
        if !is_confed_segment(segment.segment_type) {
            result_segments.push(segment.clone());
        }
    }

    AsPath {
        segments: result_segments,
    }
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

pub(super) fn read_attr_extended_communities(bytes: &[u8]) -> Result<Vec<u64>, ParserError> {
    // Length must be multiple of 8 (each extended community is 8 octets)
    if !bytes.len().is_multiple_of(8) {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    let mut ext_communities = Vec::new();
    for chunk in bytes.chunks_exact(8) {
        let extcomm = u64::from_be_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        ext_communities.push(extcomm);
    }

    Ok(ext_communities)
}

pub(super) fn read_attr_large_communities(
    bytes: &[u8],
) -> Result<Vec<LargeCommunity>, ParserError> {
    // Length must be multiple of 12 (each large community is 12 octets)
    if !bytes.len().is_multiple_of(12) {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    let mut large_communities = Vec::new();
    for chunk in bytes.chunks_exact(12) {
        let mut buf = [0u8; 12];
        buf.copy_from_slice(chunk);
        large_communities.push(LargeCommunity::from_bytes(buf));
    }

    Ok(large_communities)
}

/// RFC 4456: Read ORIGINATOR_ID attribute (4 bytes = IPv4 address)
pub(super) fn read_attr_originator_id(bytes: &[u8]) -> Ipv4Addr {
    let mut octets = [0u8; 4];
    octets.copy_from_slice(&bytes[0..4]);
    Ipv4Addr::from(octets)
}

/// RFC 4456: Read CLUSTER_LIST attribute (N*4 bytes = list of IPv4 addresses)
pub(super) fn read_attr_cluster_list(bytes: &[u8]) -> Vec<Ipv4Addr> {
    bytes
        .chunks_exact(4)
        .map(|chunk| {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(chunk);
            Ipv4Addr::from(octets)
        })
        .collect()
}

pub(super) fn read_attr_mp_reach_nlri(bytes: &[u8]) -> Result<MpReachNlri, ParserError> {
    // MP_REACH_NLRI: AFI(2) + SAFI(1) + NextHopLen(1) + NextHop + Reserved(1) + NLRI
    const HEADER_SIZE: usize = 4; // AFI(2) + SAFI(1) + NextHopLen(1)
    const RESERVED_SIZE: usize = 1;
    const MIN_SIZE: usize = HEADER_SIZE + RESERVED_SIZE; // Minimum without next hop address

    if bytes.len() < MIN_SIZE {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    let afi = Afi::try_from(u16::from_be_bytes([bytes[0], bytes[1]]))?;
    let safi = Safi::try_from(bytes[2])?;
    let next_hop_len = bytes[3] as usize;

    validate_mp_reach_buffer(&afi, next_hop_len, bytes, HEADER_SIZE, RESERVED_SIZE)?;

    // Extract next hop
    let next_hop = match afi {
        Afi::Ipv4 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&bytes[HEADER_SIZE..HEADER_SIZE + 4]);
            let addr = Ipv4Addr::from(octets);
            if !is_valid_unicast_ipv4(u32::from(addr)) {
                return Err(ParserError::BgpError {
                    error: BgpError::UpdateMessageError(
                        UpdateMessageError::InvalidNextHopAttribute,
                    ),
                    data: Vec::new(),
                });
            }
            NextHopAddr::Ipv4(addr)
        }
        Afi::Ipv6 => {
            // Use first 16 bytes (global nexthop), ignore link-local if present
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[HEADER_SIZE..HEADER_SIZE + 16]);
            NextHopAddr::Ipv6(Ipv6Addr::from(octets))
        }
    };

    let cursor = HEADER_SIZE + next_hop_len;

    // Parse NLRI (skip 1 reserved byte)
    let nlri = match afi {
        Afi::Ipv4 => parse_nlri_list(&bytes[cursor + RESERVED_SIZE..])?,
        Afi::Ipv6 => parse_nlri_v6_list(&bytes[cursor + RESERVED_SIZE..])?,
    };

    Ok(MpReachNlri {
        afi,
        safi,
        next_hop,
        nlri,
    })
}

pub(super) fn read_attr_mp_unreach_nlri(bytes: &[u8]) -> Result<MpUnreachNlri, ParserError> {
    if bytes.len() < 3 {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    let afi = Afi::try_from(u16::from_be_bytes([bytes[0], bytes[1]]))?;
    let safi = Safi::try_from(bytes[2])?;

    let withdrawn_routes = match afi {
        Afi::Ipv4 => parse_nlri_list(&bytes[3..])?,
        Afi::Ipv6 => parse_nlri_v6_list(&bytes[3..])?,
    };

    Ok(MpUnreachNlri {
        afi,
        safi,
        withdrawn_routes,
    })
}

pub(super) fn write_attr_mp_reach_nlri(mp_reach: &MpReachNlri) -> Vec<u8> {
    let mut bytes = Vec::new();

    // AFI (2 bytes)
    bytes.extend_from_slice(&(mp_reach.afi as u16).to_be_bytes());

    // SAFI (1 byte)
    bytes.push(mp_reach.safi as u8);

    // Next hop length and address
    match &mp_reach.next_hop {
        NextHopAddr::Ipv4(addr) => {
            bytes.push(4); // Length
            bytes.extend_from_slice(&addr.octets());
        }
        NextHopAddr::Ipv6(addr) => {
            bytes.push(16); // Length (global only)
            bytes.extend_from_slice(&addr.octets());
        }
    }

    // Reserved (1 byte)
    bytes.push(0);

    // NLRI
    let nlri_bytes = write_nlri_list(&mp_reach.nlri);
    bytes.extend_from_slice(&nlri_bytes);

    bytes
}

pub(super) fn write_attr_mp_unreach_nlri(mp_unreach: &MpUnreachNlri) -> Vec<u8> {
    let mut bytes = Vec::new();

    // AFI (2 bytes)
    bytes.extend_from_slice(&(mp_unreach.afi as u16).to_be_bytes());

    // SAFI (1 byte)
    bytes.push(mp_unreach.safi as u8);

    // Withdrawn routes
    bytes.extend_from_slice(&write_nlri_list(&mp_unreach.withdrawn_routes));

    bytes
}

pub(super) fn read_path_attribute(
    bytes: &[u8],
    use_4byte_asn: bool,
) -> Result<(Option<PathAttribute>, u8), ParserError> {
    let attribute_flag = PathAttrFlag(bytes[0]);
    let attr_type_code = bytes[1];

    let attr_len = match attribute_flag.extended_len() {
        true => u16::from_be_bytes([bytes[2], bytes[3]]),
        false => bytes[2] as u16,
    };

    let attr_type_opt = parse_attr_type(bytes, attribute_flag.0, attr_type_code, attr_len)?;

    let offset = if attribute_flag.extended_len() { 4 } else { 3 };
    let total_offset = offset + attr_len as usize;

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
                    let as_path = read_attr_as_path(attr_data, use_4byte_asn)?;
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
                AttrType::OriginatorId => {
                    let originator_id = read_attr_originator_id(attr_data);
                    PathAttrValue::OriginatorId(originator_id)
                }
                AttrType::ClusterList => {
                    let cluster_list = read_attr_cluster_list(attr_data);
                    PathAttrValue::ClusterList(cluster_list)
                }
                AttrType::MpReachNlri => {
                    let mp_reach = read_attr_mp_reach_nlri(attr_data)?;
                    // Validate routes match declared AFI
                    if !validate_nlri_afi(&mp_reach.afi, &mp_reach.nlri) {
                        return Err(optional_attribute_error(attr_bytes));
                    }
                    PathAttrValue::MpReachNlri(mp_reach)
                }
                AttrType::MpUnreachNlri => {
                    let mp_unreach = read_attr_mp_unreach_nlri(attr_data)?;
                    // Validate routes match declared AFI
                    if !validate_nlri_afi(&mp_unreach.afi, &mp_unreach.withdrawn_routes) {
                        return Err(optional_attribute_error(attr_bytes));
                    }
                    PathAttrValue::MpUnreachNlri(mp_unreach)
                }
                AttrType::ExtendedCommunities => {
                    let ext_communities = read_attr_extended_communities(attr_data)?;
                    PathAttrValue::ExtendedCommunities(ext_communities)
                }
                AttrType::LargeCommunities => {
                    let large_communities = read_attr_large_communities(attr_data)?;
                    PathAttrValue::LargeCommunities(large_communities)
                }
                AttrType::As4Path => {
                    match read_attr_as4_path(attr_data) {
                        Ok(as4_path) => PathAttrValue::As4Path(as4_path),
                        Err(_) => {
                            // RFC 6793 §10.2: Discard malformed AS4_PATH
                            return Ok((None, total_offset as u8));
                        }
                    }
                }
                AttrType::As4Aggregator => {
                    match read_attr_as4_aggregator(attr_data) {
                        Ok(as4_aggregator) => PathAttrValue::As4Aggregator(as4_aggregator),
                        Err(_) => {
                            // RFC 6793 §10.3: Discard malformed AS4_AGGREGATOR
                            return Ok((None, total_offset as u8));
                        }
                    }
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

    // Update PathAttribute flags if PARTIAL bit was set for unknown transitive
    let final_flags = match &attr_val {
        PathAttrValue::Unknown { flags, .. } => PathAttrFlag(*flags),
        _ => attribute_flag,
    };

    let attribute = PathAttribute {
        flags: final_flags,
        value: attr_val,
    };

    Ok((Some(attribute), total_offset as u8))
}

pub(super) fn read_path_attributes(
    bytes: &[u8],
    use_4byte_asn: bool,
) -> Result<Vec<PathAttribute>, ParserError> {
    let mut cursor = 0;
    let mut path_attributes: Vec<PathAttribute> = Vec::new();
    let mut seen_type_codes: HashSet<u8> = HashSet::new();

    while cursor < bytes.len() {
        let (attribute_opt, offset) = read_path_attribute(&bytes[cursor..], use_4byte_asn)?;
        let offset_usize = offset as usize;

        if let Some(attribute) = attribute_opt {
            let type_code = attribute.type_code();
            if !seen_type_codes.insert(type_code) {
                return Err(ParserError::BgpError {
                    error: BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
                    data: Vec::new(),
                });
            }
            path_attributes.push(attribute);
        } else {
            // Attribute was discarded - extract type code from raw bytes for logging
            let attr_type_code = bytes[cursor + 1];
            warn!(
                type_code = attr_type_code,
                "discarded malformed attribute per RFC 6793"
            );
        }

        cursor += offset_usize;
    }

    // Validate that we don't have both NEXT_HOP and MP_REACH_NLRI
    let has_next_hop = path_attributes
        .iter()
        .any(|attr| matches!(attr.value, PathAttrValue::NextHop(_)));
    let has_mp_reach = path_attributes
        .iter()
        .any(|attr| matches!(attr.value, PathAttrValue::MpReachNlri(_)));

    if has_next_hop && has_mp_reach {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
            data: Vec::new(),
        });
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

fn encode_asn(asn: u32, use_4byte_asn: bool) -> Vec<u8> {
    if use_4byte_asn {
        asn.to_be_bytes().to_vec()
    } else {
        (asn as u16).to_be_bytes().to_vec()
    }
}

pub(super) fn write_path_attribute(attr: &PathAttribute, use_4byte_asn: bool) -> Vec<u8> {
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
                    path_bytes.extend_from_slice(&encode_asn(*asn, use_4byte_asn));
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
            let mut agg_bytes = encode_asn(agg.asn, use_4byte_asn);
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
        PathAttrValue::OriginatorId(originator_id) => originator_id.octets().to_vec(),
        PathAttrValue::ClusterList(cluster_list) => {
            let mut cluster_bytes = Vec::new();
            for &cluster_id in cluster_list {
                cluster_bytes.extend_from_slice(&cluster_id.octets());
            }
            cluster_bytes
        }
        PathAttrValue::MpReachNlri(mp_reach) => write_attr_mp_reach_nlri(mp_reach),
        PathAttrValue::MpUnreachNlri(mp_unreach) => write_attr_mp_unreach_nlri(mp_unreach),
        PathAttrValue::ExtendedCommunities(ext_communities) => {
            let mut ext_comm_bytes = Vec::new();
            for &ext_comm in ext_communities {
                ext_comm_bytes.extend_from_slice(&ext_comm.to_be_bytes());
            }
            ext_comm_bytes
        }
        PathAttrValue::LargeCommunities(large_communities) => {
            let mut large_comm_bytes = Vec::new();
            for lc in large_communities {
                large_comm_bytes.extend_from_slice(&lc.to_bytes());
            }
            large_comm_bytes
        }
        PathAttrValue::As4Path(as_path) => {
            // RFC 6793: AS4_PATH always uses 4-byte ASN encoding
            let mut path_bytes = Vec::new();
            for segment in &as_path.segments {
                path_bytes.push(segment.segment_type as u8);
                path_bytes.push(segment.segment_len);
                for asn in &segment.asn_list {
                    let asn_4byte = asn.to_be_bytes();
                    path_bytes.extend_from_slice(&asn_4byte);
                }
            }
            path_bytes
        }
        PathAttrValue::As4Aggregator(agg) => {
            // RFC 6793: AS4_AGGREGATOR always uses 4-byte ASN encoding
            let mut agg_bytes = Vec::new();
            let asn_4byte = agg.asn.to_be_bytes();
            agg_bytes.extend_from_slice(&asn_4byte);
            agg_bytes.extend_from_slice(&agg.ip_addr.octets());
            agg_bytes
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
        PathAttrValue::OriginatorId(_) => AttrType::OriginatorId as u8,
        PathAttrValue::ClusterList(_) => AttrType::ClusterList as u8,
        PathAttrValue::MpReachNlri(_) => AttrType::MpReachNlri as u8,
        PathAttrValue::MpUnreachNlri(_) => AttrType::MpUnreachNlri as u8,
        PathAttrValue::ExtendedCommunities(_) => AttrType::ExtendedCommunities as u8,
        PathAttrValue::As4Path(_) => AttrType::As4Path as u8,
        PathAttrValue::As4Aggregator(_) => AttrType::As4Aggregator as u8,
        PathAttrValue::LargeCommunities(_) => AttrType::LargeCommunities as u8,
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

pub(super) fn write_path_attributes(
    path_attributes: &[PathAttribute],
    use_4byte_asn: bool,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    for attr in path_attributes {
        bytes.extend_from_slice(&write_path_attribute(attr, use_4byte_asn));
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sample MP_REACH_NLRI for IPv4 (192.168.1.1, NLRI=10.0.0.0/8)
    const MP_REACH_IPV4_SAMPLE: &[u8] = &[
        0x00, 0x01, // AFI = IPv4 (1)
        0x01, // SAFI = 1 (unicast)
        0x04, // Next hop length = 4
        0xc0, 0xa8, 0x01, 0x01, // Next hop 192.168.1.1
        0x00, // Reserved
        0x08, 0x0a, // NLRI: 10.0.0.0/8
    ];
    use crate::bgp::msg_notification::{BgpError, UpdateMessageError};
    use crate::bgp::msg_update_types::AttrType;

    use crate::bgp::{PATH_ATTR_COMMUNITIES_TWO, PATH_ATTR_EXTENDED_COMMUNITIES_TWO};

    const PATH_ATTR_ORIGIN_EGP: &[u8] =
        &[PathAttrFlag::TRANSITIVE, AttrType::Origin as u8, 0x01, 1];

    #[test]
    fn test_read_path_attribute_origin() {
        let (attribute_opt, offset) = read_path_attribute(PATH_ATTR_ORIGIN_EGP, false).unwrap();
        let attribute = attribute_opt.unwrap();

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

        match read_path_attribute(input, false) {
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
        let (attr_opt, offset) = read_path_attribute(PATH_ATTR_COMMUNITIES_TWO, false).unwrap();
        let attr = attr_opt.unwrap();

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

        let bytes = write_path_attribute(&attr, false);
        assert_eq!(bytes, PATH_ATTR_COMMUNITIES_TWO);
    }

    #[test]
    fn test_communities_roundtrip() {
        let original_communities = vec![0x00010064, 0xFFFFFF01, 0xFFFFFF02];
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::Communities(original_communities.clone()),
        };

        let bytes = write_path_attribute(&attr, false);
        let (parsed_attr_opt, _) = read_path_attribute(&bytes, false).unwrap();
        let parsed_attr = parsed_attr_opt.unwrap();

        if let PathAttrValue::Communities(communities) = parsed_attr.value {
            assert_eq!(communities, original_communities);
        } else {
            panic!("Expected Communities attribute after roundtrip");
        }
    }

    const PATH_ATTR_COMMUNITIES_EMPTY: &[u8] = &[
        PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
        AttrType::Communities as u8,
        0x00, // Length: 0
    ];

    const PATH_ATTR_COMMUNITIES_WELL_KNOWN: &[u8] = &[
        PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
        AttrType::Communities as u8,
        0x0c, // Length: 12 bytes (3 communities)
        0xFF,
        0xFF,
        0xFF,
        0x01, // NO_EXPORT
        0xFF,
        0xFF,
        0xFF,
        0x02, // NO_ADVERTISE
        0xFF,
        0xFF,
        0xFF,
        0x03, // NO_EXPORT_SUBCONFED
    ];

    #[test]
    fn test_read_path_attribute_communities_empty() {
        let (attr_opt, offset) = read_path_attribute(PATH_ATTR_COMMUNITIES_EMPTY, false).unwrap();
        let attr = attr_opt.unwrap();

        assert_eq!(
            attr,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::Communities(vec![]),
            }
        );
        assert_eq!(offset, 3); // 3-byte header only
    }

    #[test]
    fn test_read_path_attribute_communities_well_known() {
        let (attr_opt, _) = read_path_attribute(PATH_ATTR_COMMUNITIES_WELL_KNOWN, false).unwrap();
        let attr = attr_opt.unwrap();

        if let PathAttrValue::Communities(communities) = attr.value {
            assert_eq!(communities.len(), 3);
            assert_eq!(communities[0], 0xFFFFFF01); // NO_EXPORT
            assert_eq!(communities[1], 0xFFFFFF02); // NO_ADVERTISE
            assert_eq!(communities[2], 0xFFFFFF03); // NO_EXPORT_SUBCONFED
        } else {
            panic!("Expected Communities attribute");
        }
    }

    #[test]
    fn test_read_path_attribute_communities_invalid_length() {
        // Length not multiple of 4
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::Communities as u8,
            0x03, // Invalid length: 3 bytes (not multiple of 4)
            0x00,
            0x01,
            0x00,
        ];

        match read_path_attribute(input, false) {
            Err(ParserError::BgpError { error, .. }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError)
                );
            }
            _ => panic!("Expected OptionalAttributeError for invalid communities length"),
        }
    }

    #[test]
    fn test_write_path_attribute_communities_empty() {
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::Communities(vec![]),
        };

        let bytes = write_path_attribute(&attr, false);
        assert_eq!(bytes, PATH_ATTR_COMMUNITIES_EMPTY);
    }

    #[test]
    fn test_write_path_attribute_extended_communities() {
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::ExtendedCommunities(vec![
                0x0002FDE800000064, // rt:65000:100
                0x0102C0A801010064, // rt:192.168.1.1:100
            ]),
        };

        let bytes = write_path_attribute(&attr, false);
        assert_eq!(bytes, PATH_ATTR_EXTENDED_COMMUNITIES_TWO);
    }

    #[test]
    fn test_extended_communities_roundtrip() {
        use crate::bgp::msg_update_types::{from_ipv4, from_two_octet_as, SUBTYPE_ROUTE_TARGET};
        use std::net::Ipv4Addr;

        let original_ext_communities = vec![
            from_two_octet_as(SUBTYPE_ROUTE_TARGET, 65000, 100),
            from_ipv4(
                SUBTYPE_ROUTE_TARGET,
                u32::from(Ipv4Addr::new(192, 168, 1, 1)),
                100,
            ),
        ];
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::ExtendedCommunities(original_ext_communities.clone()),
        };

        let bytes = write_path_attribute(&attr, false);
        let (parsed_attr_opt, _) = read_path_attribute(&bytes, false).unwrap();
        let parsed_attr = parsed_attr_opt.unwrap();

        if let PathAttrValue::ExtendedCommunities(ext_communities) = parsed_attr.value {
            assert_eq!(ext_communities, original_ext_communities);
        } else {
            panic!("Expected ExtendedCommunities attribute after roundtrip");
        }
    }

    // AS_PATH attribute tests
    const PATH_ATTR_AS_PATH: &[u8] = &[
        PathAttrFlag::TRANSITIVE,
        AttrType::AsPath as u8,
        0x06,
        AsPathSegmentType::AsSet as u8,
        0x02,
        0x00,
        0x10,
        0x01,
        0x12,
    ];

    #[test]
    fn test_read_path_attribute_as_path() {
        let (as_path_opt, offset) = read_path_attribute(PATH_ATTR_AS_PATH, false).unwrap();
        let as_path = as_path_opt.unwrap();
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
            0x01,
            AsPathSegmentType::AsSet as u8,
        ];

        match read_path_attribute(input, false) {
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
            0x04,
            AsPathSegmentType::AsSequence as u8,
            0x02,
            0x00,
            0x10,
        ];

        match read_path_attribute(input, false) {
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
        let input: &[u8] = &[PathAttrFlag::TRANSITIVE, AttrType::AsPath as u8, 0x00];

        let (as_path_opt, offset) = read_path_attribute(input, false).unwrap();
        let as_path = as_path_opt.unwrap();
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
            0x0a,
            AsPathSegmentType::AsSequence as u8,
            0x02,
            0x00,
            0x0a,
            0x00,
            0x14,
            AsPathSegmentType::AsSet as u8,
            0x01,
            0x00,
            0x1e,
        ];

        let (as_path_opt, offset) = read_path_attribute(input, false).unwrap();
        let as_path = as_path_opt.unwrap();
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

    // NEXT_HOP attribute tests
    const PATH_ATTR_NEXT_HOP_IPV4: &[u8] = &[
        PathAttrFlag::TRANSITIVE,
        AttrType::NextHop as u8,
        0x04,
        0xc8,
        0xc9,
        0xca,
        0xcb,
    ];

    #[test]
    fn test_read_path_attribute_next_hop_ipv4() {
        let (as_path_opt, offset) = read_path_attribute(PATH_ATTR_NEXT_HOP_IPV4, false).unwrap();
        let as_path = as_path_opt.unwrap();
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
            PathAttrFlag::TRANSITIVE,
            AttrType::NextHop as u8,
            0x05,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
        ];

        match read_path_attribute(input, false) {
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
    fn test_read_path_attribute_next_hop_invalid_address() {
        let test_cases = vec![
            ("0.0.0.0", [0x00, 0x00, 0x00, 0x00]),
            ("255.255.255.255", [0xff, 0xff, 0xff, 0xff]),
            ("224.0.0.1", [0xe0, 0x00, 0x00, 0x01]),
            ("239.255.255.255", [0xef, 0xff, 0xff, 0xff]),
        ];

        for (name, ip_bytes) in test_cases {
            let input: Vec<u8> = vec![
                PathAttrFlag::TRANSITIVE,
                AttrType::NextHop as u8,
                0x04,
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3],
            ];

            match read_path_attribute(&input, false) {
                Err(ParserError::BgpError { error, data }) => {
                    assert_eq!(
                        error,
                        BgpError::UpdateMessageError(UpdateMessageError::InvalidNextHopAttribute),
                        "Failed for {}",
                        name
                    );
                    assert_eq!(data, input, "Failed for {}", name);
                }
                _ => panic!("Expected InvalidNextHopAttribute for {}", name),
            }
        }
    }

    // MED attribute tests
    #[test]
    fn test_read_path_attribute_multi_exit_disc() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL,
            AttrType::MultiExtiDisc as u8,
            0x04,
            0x00,
            0x01,
            0x00,
            0x01,
        ];

        let (as_path_opt, offset) = read_path_attribute(input, false).unwrap();
        let as_path = as_path_opt.unwrap();
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
    fn test_read_path_attribute_optional_invalid_length() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL,
            AttrType::MultiExtiDisc as u8,
            0x03,
            0x00,
            0x00,
            0x01,
        ];

        match read_path_attribute(input, false) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError)
                );
                assert_eq!(data, input.to_vec());
            }
            _ => panic!("Expected OptionalAttributeError"),
        }
    }

    // LOCAL_PREF attribute tests
    #[test]
    fn test_read_path_attribute_local_pref() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::LocalPref as u8,
            0x04,
            0x00,
            0x00,
            0x0f,
            0x01,
        ];

        let (as_path_opt, offset) = read_path_attribute(input, false).unwrap();
        let as_path = as_path_opt.unwrap();
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
            PathAttrFlag::TRANSITIVE,
            AttrType::LocalPref as u8,
            0x03,
            0x00,
            0x00,
            0x0f,
        ];

        match read_path_attribute(input, false) {
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

    // ATOMIC_AGGREGATE attribute tests
    #[test]
    fn test_read_path_attribute_atomic_aggregate() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::AtomicAggregate as u8,
            0x00,
        ];

        let (as_path_opt, offset) = read_path_attribute(input, false).unwrap();
        let as_path = as_path_opt.unwrap();
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
            PathAttrFlag::TRANSITIVE,
            AttrType::AtomicAggregate as u8,
            0x01,
            0x00,
        ];

        match read_path_attribute(input, false) {
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

    // AGGREGATOR attribute tests
    #[test]
    fn test_read_path_attribute_aggregator_ipv4() {
        use std::str::FromStr;

        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::Aggregator as u8,
            0x06,
            0x00,
            0x10,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
        ];

        let (as_path_opt, offset) = read_path_attribute(input, false).unwrap();
        let as_path = as_path_opt.unwrap();
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
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::Aggregator as u8,
            0x03,
            0x00,
            0x10,
            0x0a,
        ];

        match read_path_attribute(input, false) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError)
                );
                assert_eq!(data, input.to_vec());
            }
            _ => panic!("Expected OptionalAttributeError"),
        }
    }

    #[test]
    fn test_read_path_attribute_extended_communities() {
        let (attr_opt, offset) =
            read_path_attribute(PATH_ATTR_EXTENDED_COMMUNITIES_TWO, false).unwrap();
        let attr = attr_opt.unwrap();

        assert_eq!(
            attr,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::ExtendedCommunities(vec![
                    0x0002FDE800000064, // rt:65000:100
                    0x0102C0A801010064, // rt:192.168.1.1:100
                ]),
            }
        );
        assert_eq!(offset, 19);
    }

    #[test]
    fn test_large_communities_roundtrip() {
        let original_large_communities = vec![
            LargeCommunity::new(65536, 100, 200),
            LargeCommunity::new(4200000000, 1, 2),
            LargeCommunity::new(0, 0, 0),
        ];
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::LargeCommunities(original_large_communities.clone()),
        };

        let bytes = write_path_attribute(&attr, false);
        let (parsed_attr_opt, _) = read_path_attribute(&bytes, false).unwrap();
        let parsed_attr = parsed_attr_opt.unwrap();

        if let PathAttrValue::LargeCommunities(large_communities) = parsed_attr.value {
            assert_eq!(large_communities, original_large_communities);
        } else {
            panic!("Expected LargeCommunities attribute after roundtrip");
        }
    }

    #[test]
    fn test_read_attr_large_communities() {
        // Wire format: [GA:4][LD1:4][LD2:4] for each community
        let bytes = vec![
            0x00, 0x01, 0x00, 0x00, // GA = 65536
            0x00, 0x00, 0x00, 0x64, // LD1 = 100
            0x00, 0x00, 0x00, 0xC8, // LD2 = 200
            0xFA, 0x56, 0xEA, 0x00, // GA = 4200000000
            0x00, 0x00, 0x00, 0x01, // LD1 = 1
            0x00, 0x00, 0x00, 0x02, // LD2 = 2
        ];

        let large_communities = read_attr_large_communities(&bytes).unwrap();
        assert_eq!(large_communities.len(), 2);

        assert_eq!(large_communities[0], LargeCommunity::new(65536, 100, 200));
        assert_eq!(large_communities[1], LargeCommunity::new(4200000000, 1, 2));

        // Verify field extraction
        assert_eq!(large_communities[0].global_admin, 65536);
        assert_eq!(large_communities[0].local_data_1, 100);
        assert_eq!(large_communities[0].local_data_2, 200);
    }

    #[test]
    fn test_read_attr_large_communities_invalid_length() {
        // Length not multiple of 12
        let bytes = vec![0x00, 0x01, 0x00, 0x00, 0x00];

        let result = read_attr_large_communities(&bytes);
        assert!(result.is_err());
        match result {
            Err(ParserError::BgpError { error, .. }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError)
                );
            }
            _ => panic!("Expected OptionalAttributeError for invalid length"),
        }
    }

    #[test]
    fn test_validate_nlri_afi_mismatch() {
        use crate::net::{Ipv4Net, Ipv6Net};
        use std::net::{Ipv4Addr, Ipv6Addr};

        // IPv4 AFI with IPv6 routes should fail
        let ipv6_routes = vec![IpNetwork::V6(Ipv6Net {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            prefix_length: 64,
        })];
        assert!(!validate_nlri_afi(&Afi::Ipv4, &ipv6_routes));

        // IPv6 AFI with IPv4 routes should fail
        let ipv4_routes = vec![IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(192, 168, 1, 0),
            prefix_length: 24,
        })];
        assert!(!validate_nlri_afi(&Afi::Ipv6, &ipv4_routes));

        // IPv4 AFI with IPv4 routes should succeed
        assert!(validate_nlri_afi(&Afi::Ipv4, &ipv4_routes));

        // IPv6 AFI with IPv6 routes should succeed
        assert!(validate_nlri_afi(&Afi::Ipv6, &ipv6_routes));
    }

    #[test]
    fn test_read_attr_mp_reach_nlri_ipv4() {
        use crate::net::Ipv4Net;
        use std::net::Ipv4Addr;

        let result = read_attr_mp_reach_nlri(MP_REACH_IPV4_SAMPLE).unwrap();

        assert_eq!(result.afi, Afi::Ipv4);
        assert_eq!(result.safi, Safi::Unicast);
        assert_eq!(
            result.next_hop,
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(result.nlri.len(), 1);
        assert_eq!(
            result.nlri[0],
            IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 0, 0),
                prefix_length: 8,
            })
        );
    }

    #[test]
    fn test_read_attr_mp_reach_nlri_ipv6() {
        use crate::net::Ipv6Net;
        use std::net::Ipv6Addr;

        // MP_REACH_NLRI: AFI=IPv6, SAFI=1, next_hop=2001:db8::1, NLRI=2001:db8::/32
        let input: &[u8] = &[
            0x00, 0x02, // AFI = IPv6 (2)
            0x01, // SAFI = 1 (unicast)
            0x10, // Next hop length = 16
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // Next hop 2001:db8::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, // Reserved
            0x20, 0x20, 0x01, 0x0d, 0xb8, // NLRI: 2001:db8::/32
        ];

        let result = read_attr_mp_reach_nlri(input).unwrap();

        assert_eq!(result.afi, Afi::Ipv6);
        assert_eq!(result.safi, Safi::Unicast);
        assert_eq!(
            result.next_hop,
            NextHopAddr::Ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(result.nlri.len(), 1);
        assert_eq!(
            result.nlri[0],
            IpNetwork::V6(Ipv6Net {
                address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
                prefix_length: 32,
            })
        );
    }

    #[test]
    fn test_read_attr_mp_unreach_nlri_ipv4() {
        use crate::net::Ipv4Net;
        use std::net::Ipv4Addr;

        // MP_UNREACH_NLRI: AFI=IPv4, SAFI=1, withdrawn=10.0.0.0/8
        let input: &[u8] = &[
            0x00, 0x01, // AFI = IPv4 (1)
            0x01, // SAFI = 1 (unicast)
            0x08, 0x0a, // Withdrawn: 10.0.0.0/8
        ];

        let result = read_attr_mp_unreach_nlri(input).unwrap();

        assert_eq!(result.afi, Afi::Ipv4);
        assert_eq!(result.safi, Safi::Unicast);
        assert_eq!(result.withdrawn_routes.len(), 1);
        assert_eq!(
            result.withdrawn_routes[0],
            IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 0, 0),
                prefix_length: 8,
            })
        );
    }

    #[test]
    fn test_read_attr_mp_unreach_nlri_ipv6() {
        use crate::net::Ipv6Net;
        use std::net::Ipv6Addr;

        // MP_UNREACH_NLRI: AFI=IPv6, SAFI=1, withdrawn=2001:db8::/32
        let input: &[u8] = &[
            0x00, 0x02, // AFI = IPv6 (2)
            0x01, // SAFI = 1 (unicast)
            0x20, 0x20, 0x01, 0x0d, 0xb8, // Withdrawn: 2001:db8::/32
        ];

        let result = read_attr_mp_unreach_nlri(input).unwrap();

        assert_eq!(result.afi, Afi::Ipv6);
        assert_eq!(result.safi, Safi::Unicast);
        assert_eq!(result.withdrawn_routes.len(), 1);
        assert_eq!(
            result.withdrawn_routes[0],
            IpNetwork::V6(Ipv6Net {
                address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
                prefix_length: 32,
            })
        );
    }

    #[test]
    fn test_reject_both_next_hop_and_mp_reach() {
        // Create attributes with both NEXT_HOP and MP_REACH_NLRI
        let mut attrs_bytes = Vec::new();

        // NEXT_HOP attribute (flags=0x40, type=3, length=4, value=192.168.1.1)
        attrs_bytes.extend_from_slice(&[
            0x40, // flags: TRANSITIVE
            0x03, // type: NEXT_HOP
            0x04, // length: 4
            192, 168, 1, 1, // next_hop: 192.168.1.1
        ]);

        // MP_REACH_NLRI attribute using sample data
        attrs_bytes.extend_from_slice(&[
            0x80,                             // flags: OPTIONAL
            0x0e,                             // type: MP_REACH_NLRI
            MP_REACH_IPV4_SAMPLE.len() as u8, // length
        ]);
        attrs_bytes.extend_from_slice(MP_REACH_IPV4_SAMPLE);

        // Should fail with MalformedAttributeList
        let result = read_path_attributes(&attrs_bytes, false);
        assert!(result.is_err());
        if let Err(ParserError::BgpError { error, .. }) = result {
            assert_eq!(
                error,
                BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList)
            );
        } else {
            panic!("Expected MalformedAttributeList error");
        }
    }

    // RFC 6793 Attribute Discard Tests

    #[test]
    fn test_malformed_as4_path_aggreator_attributes_discarded() {
        struct TestCase {
            name: &'static str,
            input: &'static [u8],
            expected_offset: Option<u8>,
        }

        let tests = vec![
            TestCase {
                name: "AS4_PATH truncated - segment length claims 2 ASNs but only 1 present",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x06, // Length: 6 bytes
                    AsPathSegmentType::AsSequence as u8,
                    0x02, // Segment length claims 2 ASNs (but we only have data for 1)
                    0x00,
                    0x00,
                    0x00,
                    0x0a, // First ASN: 10 (second ASN missing)
                ],
                expected_offset: Some(9),
            },
            TestCase {
                name: "AS4_PATH invalid segment type",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x06, // Length: 6 bytes
                    0xFF, // Invalid segment type (255)
                    0x01, // Segment length: 1 ASN
                    0x00,
                    0x00,
                    0x00,
                    0x0a, // ASN: 10
                ],
                expected_offset: None,
            },
            TestCase {
                name: "AS4_AGGREGATOR wrong length",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Aggregator as u8,
                    0x06, // Length: 6 bytes (should be 8)
                    0x00,
                    0x00,
                    0x00,
                    0x0a, // ASN: 10
                    0xc0,
                    0xa8, // IP incomplete
                ],
                expected_offset: Some(9),
            },
            TestCase {
                name: "AS4_PATH too short",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x04, // Length: 4 bytes (too short - need at least 6)
                    AsPathSegmentType::AsSequence as u8,
                    0x00, // Segment length: 0
                    0x00,
                    0x00,
                ],
                expected_offset: None,
            },
            TestCase {
                name: "AS4_PATH odd length",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x07, // Length: 7 bytes (not multiple of 2)
                    AsPathSegmentType::AsSequence as u8,
                    0x01, // Segment length: 1 ASN
                    0x00,
                    0x00,
                    0x00,
                    0x0a, // ASN: 10
                    0x00, // Extra odd byte
                ],
                expected_offset: None,
            },
            TestCase {
                name: "AS4_PATH zero segment length",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x06, // Length: 6 bytes
                    AsPathSegmentType::AsSequence as u8,
                    0x00, // Segment length: 0 (invalid)
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ],
                expected_offset: None,
            },
        ];

        for test in tests {
            let result = read_path_attribute(test.input, false);
            assert!(result.is_ok(), "{}: should return Ok", test.name);
            let (attr_opt, offset) = result.unwrap();
            assert!(
                attr_opt.is_none(),
                "{}: malformed attribute should be discarded",
                test.name
            );
            if let Some(expected) = test.expected_offset {
                assert_eq!(offset, expected, "{}: offset mismatch", test.name);
            }
        }
    }

    #[test]
    fn test_as4_path_well_formed_accepted() {
        // Well-formed AS4_PATH should still be accepted
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::As4Path as u8,
            0x0a, // Length: 10 bytes
            AsPathSegmentType::AsSequence as u8,
            0x02, // Segment length: 2 ASNs
            0x00,
            0x00,
            0x00,
            0x0a, // First ASN: 10
            0x00,
            0x00,
            0x00,
            0x14, // Second ASN: 20
        ];

        let result = read_path_attribute(input, false);
        assert!(result.is_ok());
        let (attr_opt, _) = result.unwrap();
        assert!(
            attr_opt.is_some(),
            "Well-formed AS4_PATH should be accepted"
        );

        let attr = attr_opt.unwrap();
        if let PathAttrValue::As4Path(as_path) = attr.value {
            assert_eq!(as_path.segments.len(), 1);
            assert_eq!(as_path.segments[0].asn_list, vec![10, 20]);
        } else {
            panic!("Expected As4Path attribute");
        }
    }

    #[test]
    fn test_malformed_as_path() {
        // Regular AS_PATH (well-known mandatory) should still cause errors
        // Segment length claims 2 ASNs but we only provide data for 1
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::AsPath as u8,
            0x04, // Length: 4 bytes (segment header=2, 1 ASN in 2-byte format=2)
            AsPathSegmentType::AsSequence as u8,
            0x02, // Segment length claims: 2 ASNs (but only 1 ASN worth of data follows)
            0x00,
            0x0a, // First ASN: 10 (second ASN missing - truncated)
        ];

        let result = read_path_attribute(input, false);
        assert!(result.is_err(), "Malformed AS_PATH should cause error");

        if let Err(ParserError::BgpError { error, .. }) = result {
            assert_eq!(
                error,
                BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath)
            );
        } else {
            panic!("Expected MalformedASPath error");
        }
    }

    #[test]
    fn test_as4_path_confed_segment_filtering() {
        struct TestCase {
            name: &'static str,
            input: &'static [u8],
            expected_segments: usize,
            expected_asns: Vec<u32>,
        }

        let tests = vec![
            TestCase {
                name: "only confederation segments - result is empty",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x0a, // Length: 10 bytes
                    AsPathSegmentType::AsConfedSequence as u8,
                    0x02, // Segment length: 2 ASNs
                    0x00,
                    0x00,
                    0x00,
                    0x0a, // ASN: 10
                    0x00,
                    0x00,
                    0x00,
                    0x14, // ASN: 20
                ],
                expected_segments: 0,
                expected_asns: vec![],
            },
            TestCase {
                name: "mixed regular and confederation segments",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x12, // Length: 18 bytes (3 segments: 6+6+6)
                    // First segment: regular AS_SEQUENCE
                    AsPathSegmentType::AsSequence as u8,
                    0x01, // Segment length: 1 ASN
                    0x00,
                    0x00,
                    0x00,
                    0x0a, // ASN: 10
                    // Second segment: AS_CONFED_SEQUENCE (filtered)
                    AsPathSegmentType::AsConfedSequence as u8,
                    0x01, // Segment length: 1 ASN
                    0x00,
                    0x00,
                    0x00,
                    0x14, // ASN: 20
                    // Third segment: AS_CONFED_SET (filtered)
                    AsPathSegmentType::AsConfedSet as u8,
                    0x01, // Segment length: 1 ASN
                    0x00,
                    0x00,
                    0x00,
                    0x1e, // ASN: 30
                ],
                expected_segments: 1,
                expected_asns: vec![10],
            },
        ];

        for test in tests {
            let result = read_path_attribute(test.input, false);
            assert!(result.is_ok(), "{}: should return Ok", test.name);
            let (attr_opt, _) = result.unwrap();
            assert!(
                attr_opt.is_some(),
                "{}: AS4_PATH should not be discarded",
                test.name
            );

            let attr = attr_opt.unwrap();
            if let PathAttrValue::As4Path(as_path) = attr.value {
                assert_eq!(
                    as_path.segments.len(),
                    test.expected_segments,
                    "{}: segment count mismatch",
                    test.name
                );
                if test.expected_segments > 0 {
                    assert_eq!(
                        as_path.segments[0].segment_type,
                        AsPathSegmentType::AsSequence,
                        "{}: segment type mismatch",
                        test.name
                    );
                    assert_eq!(
                        as_path.segments[0].asn_list, test.expected_asns,
                        "{}: ASN list mismatch",
                        test.name
                    );
                }
            } else {
                panic!("{}: Expected As4Path attribute", test.name);
            }
        }
    }

    // Helper function to create AS path segments
    fn make_as_path(segments: Vec<(AsPathSegmentType, Vec<u32>)>) -> AsPath {
        AsPath {
            segments: segments
                .into_iter()
                .map(|(segment_type, asn_list)| AsPathSegment {
                    segment_type,
                    segment_len: asn_list.len() as u8,
                    asn_list,
                })
                .collect(),
        }
    }

    #[test]
    fn test_merge_as_paths() {
        use AsPathSegmentType::{AsConfedSequence, AsSequence};

        struct TestCase {
            name: &'static str,
            as_path: Vec<(AsPathSegmentType, Vec<u32>)>,
            as4_path: Vec<(AsPathSegmentType, Vec<u32>)>,
            expected: Vec<(AsPathSegmentType, Vec<u32>)>,
        }

        let tests = vec![
            TestCase {
                name: "normal merge",
                as_path: vec![(AsSequence, vec![100, 200, 300])],
                as4_path: vec![(AsSequence, vec![300])],
                expected: vec![(AsSequence, vec![100, 200]), (AsSequence, vec![300])],
            },
            TestCase {
                name: "malformed as4_path longer than as_path",
                as_path: vec![(AsSequence, vec![100, 200])],
                as4_path: vec![(AsSequence, vec![100, 200, 300])],
                expected: vec![(AsSequence, vec![100, 200])],
            },
            TestCase {
                name: "same length paths",
                as_path: vec![(AsSequence, vec![100, 200])],
                as4_path: vec![(AsSequence, vec![100, 200])],
                expected: vec![(AsSequence, vec![100, 200])],
            },
            TestCase {
                name: "leading confederation segments",
                as_path: vec![
                    (AsConfedSequence, vec![50, 60]),
                    (AsSequence, vec![100, 200, 300]),
                ],
                as4_path: vec![(AsSequence, vec![300])],
                expected: vec![
                    (AsConfedSequence, vec![50, 60]),
                    (AsSequence, vec![100, 200]),
                    (AsSequence, vec![300]),
                ],
            },
            TestCase {
                name: "trailing confederation segments discarded",
                as_path: vec![
                    (AsSequence, vec![100, 200, 300]),
                    (AsConfedSequence, vec![50, 60]),
                ],
                as4_path: vec![(AsSequence, vec![300])],
                expected: vec![(AsSequence, vec![100, 200]), (AsSequence, vec![300])],
            },
            TestCase {
                name: "multiple segments",
                as_path: vec![(AsSequence, vec![100, 200]), (AsSequence, vec![300, 400])],
                as4_path: vec![(AsSequence, vec![400])],
                expected: vec![
                    (AsSequence, vec![100, 200]),
                    (AsSequence, vec![300]),
                    (AsSequence, vec![400]),
                ],
            },
            TestCase {
                name: "partial segment prepend",
                as_path: vec![(AsSequence, vec![100, 200, 300])],
                as4_path: vec![(AsSequence, vec![200, 300])],
                expected: vec![(AsSequence, vec![100]), (AsSequence, vec![200, 300])],
            },
            TestCase {
                name: "as4_path with confed segments filtered",
                as_path: vec![(AsSequence, vec![100, 200])],
                as4_path: vec![(AsConfedSequence, vec![50]), (AsSequence, vec![200])],
                expected: vec![(AsSequence, vec![100]), (AsSequence, vec![200])],
            },
        ];

        for test in tests {
            let as_path = make_as_path(test.as_path);
            let as4_path = make_as_path(test.as4_path);
            let expected = make_as_path(test.expected);

            let result = merge_as_paths(&as_path, &as4_path);

            assert_eq!(
                result.segments.len(),
                expected.segments.len(),
                "{}: segment count mismatch",
                test.name
            );

            for (i, (result_seg, expected_seg)) in result
                .segments
                .iter()
                .zip(expected.segments.iter())
                .enumerate()
            {
                assert_eq!(
                    result_seg.segment_type, expected_seg.segment_type,
                    "{}: segment {} type mismatch",
                    test.name, i
                );
                assert_eq!(
                    result_seg.asn_list, expected_seg.asn_list,
                    "{}: segment {} ASN list mismatch",
                    test.name, i
                );
            }
        }
    }

    #[test]
    fn test_count_non_confed_asns() {
        let path = make_as_path(vec![
            (AsPathSegmentType::AsConfedSequence, vec![50, 60]),
            (AsPathSegmentType::AsSequence, vec![100, 200]),
            (AsPathSegmentType::AsConfedSet, vec![70]),
            (AsPathSegmentType::AsSequence, vec![300]),
        ]);

        assert_eq!(count_non_confed_asns(&path), 3); // 100, 200, 300
    }

    #[test]
    fn test_is_confed_segment() {
        assert!(is_confed_segment(AsPathSegmentType::AsConfedSequence));
        assert!(is_confed_segment(AsPathSegmentType::AsConfedSet));
        assert!(!is_confed_segment(AsPathSegmentType::AsSequence));
        assert!(!is_confed_segment(AsPathSegmentType::AsSet));
    }

    #[test]
    fn test_read_attr_originator_id() {
        assert_eq!(
            read_attr_originator_id(&[192, 168, 1, 1]),
            Ipv4Addr::new(192, 168, 1, 1)
        );
        assert_eq!(
            read_attr_originator_id(&[10, 0, 0, 1]),
            Ipv4Addr::new(10, 0, 0, 1)
        );
    }

    #[test]
    fn test_read_attr_cluster_list() {
        assert_eq!(
            read_attr_cluster_list(&[192, 168, 1, 1]),
            vec![Ipv4Addr::new(192, 168, 1, 1)]
        );
        assert_eq!(
            read_attr_cluster_list(&[192, 168, 1, 1, 10, 0, 0, 1, 172, 16, 0, 1]),
            vec![
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(172, 16, 0, 1),
            ]
        );
        assert!(read_attr_cluster_list(&[]).is_empty());
    }
}
