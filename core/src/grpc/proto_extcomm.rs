// Copyright 2025 bgpgg Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Extended Community proto conversions
//!
//! This module handles conversion between bgpgg's internal u64 representation
//! of extended communities and the protobuf ExtendedCommunity message format.

use super::proto;
use crate::bgp::ext_community::*;
use std::net::Ipv4Addr;

/// Convert proto ExtendedCommunity to internal u64 representation
pub(super) fn proto_extcomm_to_u64(proto: &proto::ExtendedCommunity) -> Result<u64, String> {
    let community = proto
        .community
        .as_ref()
        .ok_or("ExtendedCommunity missing oneof field")?;

    match community {
        proto::extended_community::Community::TwoOctetAs(ec) => {
            if ec.asn > 65535 {
                return Err(format!("ASN {} exceeds 16-bit max (65535)", ec.asn));
            }
            let mut val = from_two_octet_as(ec.sub_type as u8, ec.asn as u16, ec.local_admin);
            // Set non-transitive bit if needed
            if !ec.is_transitive {
                val |= (TYPE_NON_TRANSITIVE_BIT as u64) << 56;
            }
            Ok(val)
        }

        proto::extended_community::Community::Ipv4Address(ec) => {
            if ec.local_admin > 65535 {
                return Err(format!(
                    "Local admin {} exceeds 16-bit max (65535)",
                    ec.local_admin
                ));
            }
            let ip: Ipv4Addr = ec
                .address
                .parse()
                .map_err(|_| format!("Invalid IPv4 address: {}", ec.address))?;
            let mut val = from_ipv4(ec.sub_type as u8, u32::from(ip), ec.local_admin as u16);
            // Set non-transitive bit if needed
            if !ec.is_transitive {
                val |= (TYPE_NON_TRANSITIVE_BIT as u64) << 56;
            }
            Ok(val)
        }

        proto::extended_community::Community::FourOctetAs(ec) => {
            if ec.local_admin > 65535 {
                return Err(format!(
                    "Local admin {} exceeds 16-bit max (65535)",
                    ec.local_admin
                ));
            }
            let mut val = from_four_octet_as(ec.sub_type as u8, ec.asn, ec.local_admin as u16);
            // Set non-transitive bit if needed
            if !ec.is_transitive {
                val |= (TYPE_NON_TRANSITIVE_BIT as u64) << 56;
            }
            Ok(val)
        }

        proto::extended_community::Community::LinkBandwidth(ec) => {
            if ec.asn > 65535 {
                return Err(format!("ASN {} exceeds 16-bit max (65535)", ec.asn));
            }
            // Link Bandwidth uses same format as two-octet AS, but with float32 bandwidth
            let bandwidth_bits = ec.bandwidth.to_bits();
            let mut val = from_two_octet_as(SUBTYPE_LINK_BANDWIDTH, ec.asn as u16, bandwidth_bits);
            // Set non-transitive bit if needed
            if !ec.is_transitive {
                val |= (TYPE_NON_TRANSITIVE_BIT as u64) << 56;
            }
            Ok(val)
        }

        proto::extended_community::Community::Opaque(ec) => {
            if ec.value.len() != 6 {
                return Err(format!(
                    "Opaque value must be 6 bytes, got {}",
                    ec.value.len()
                ));
            }
            let mut typ = TYPE_OPAQUE;
            if !ec.is_transitive {
                typ |= TYPE_NON_TRANSITIVE_BIT;
            }
            // Build u64: [type][0x00 subtype][6 bytes value]
            let mut bytes = [0u8; 8];
            bytes[0] = typ;
            bytes[2..8].copy_from_slice(&ec.value);
            Ok(u64::from_be_bytes(bytes))
        }

        proto::extended_community::Community::Unknown(ec) => {
            if ec.value.len() != 7 {
                return Err(format!(
                    "Unknown value must be 7 bytes, got {}",
                    ec.value.len()
                ));
            }
            let mut bytes = [0u8; 8];
            bytes[0] = ec.type_code as u8;
            bytes[1..8].copy_from_slice(&ec.value);
            Ok(u64::from_be_bytes(bytes))
        }
    }
}

/// Convert internal u64 representation to proto ExtendedCommunity
pub(super) fn u64_to_proto_extcomm(extcomm: u64) -> proto::ExtendedCommunity {
    let typ = ext_type(extcomm);
    let subtype = ext_subtype(extcomm);
    let value_bytes = ext_value(extcomm);
    let is_transitive = (typ & TYPE_NON_TRANSITIVE_BIT) == 0;
    let base_type = typ & !TYPE_NON_TRANSITIVE_BIT;

    let community = match base_type {
        TYPE_TWO_OCTET_AS => {
            let asn = u16::from_be_bytes([value_bytes[0], value_bytes[1]]);
            let local_admin_bytes = u32::from_be_bytes([
                value_bytes[2],
                value_bytes[3],
                value_bytes[4],
                value_bytes[5],
            ]);

            // Link Bandwidth has same base type but different subtype
            if subtype == SUBTYPE_LINK_BANDWIDTH {
                let bandwidth = f32::from_bits(local_admin_bytes);
                proto::extended_community::Community::LinkBandwidth(
                    proto::extended_community::LinkBandwidth {
                        is_transitive,
                        asn: asn as u32,
                        bandwidth,
                    },
                )
            } else {
                proto::extended_community::Community::TwoOctetAs(
                    proto::extended_community::TwoOctetAsSpecific {
                        is_transitive,
                        sub_type: subtype as u32,
                        asn: asn as u32,
                        local_admin: local_admin_bytes,
                    },
                )
            }
        }

        TYPE_IPV4_ADDRESS => {
            let ip = Ipv4Addr::new(
                value_bytes[0],
                value_bytes[1],
                value_bytes[2],
                value_bytes[3],
            );
            let local_admin = u16::from_be_bytes([value_bytes[4], value_bytes[5]]);
            proto::extended_community::Community::Ipv4Address(
                proto::extended_community::IPv4AddressSpecific {
                    is_transitive,
                    sub_type: subtype as u32,
                    address: ip.to_string(),
                    local_admin: local_admin as u32,
                },
            )
        }

        TYPE_FOUR_OCTET_AS => {
            let asn = u32::from_be_bytes([
                value_bytes[0],
                value_bytes[1],
                value_bytes[2],
                value_bytes[3],
            ]);
            let local_admin = u16::from_be_bytes([value_bytes[4], value_bytes[5]]);
            proto::extended_community::Community::FourOctetAs(
                proto::extended_community::FourOctetAsSpecific {
                    is_transitive,
                    sub_type: subtype as u32,
                    asn,
                    local_admin: local_admin as u32,
                },
            )
        }

        TYPE_OPAQUE => {
            proto::extended_community::Community::Opaque(proto::extended_community::Opaque {
                is_transitive,
                value: value_bytes.to_vec(),
            })
        }

        _ => {
            // Unknown type - preserve all 7 bytes (subtype + value)
            let mut value = vec![subtype];
            value.extend_from_slice(&value_bytes);
            proto::extended_community::Community::Unknown(proto::extended_community::Unknown {
                type_code: typ as u32,
                value,
            })
        }
    };

    proto::ExtendedCommunity {
        community: Some(community),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_two_octet_as_rt_roundtrip() {
        let original = from_two_octet_as(SUBTYPE_ROUTE_TARGET, 65000, 100);

        // u64 -> proto
        let proto_ec = u64_to_proto_extcomm(original);
        assert!(matches!(
            proto_ec.community,
            Some(proto::extended_community::Community::TwoOctetAs(_))
        ));

        // proto -> u64
        let result = proto_extcomm_to_u64(&proto_ec).unwrap();
        assert_eq!(original, result);
    }

    #[test]
    fn test_ipv4_address_rt_roundtrip() {
        let original = from_ipv4(SUBTYPE_ROUTE_TARGET, 0xC0A80101, 100); // 192.168.1.1

        let proto_ec = u64_to_proto_extcomm(original);
        assert!(matches!(
            proto_ec.community,
            Some(proto::extended_community::Community::Ipv4Address(_))
        ));

        let result = proto_extcomm_to_u64(&proto_ec).unwrap();
        assert_eq!(original, result);
    }

    #[test]
    fn test_four_octet_as_ro_roundtrip() {
        let original = from_four_octet_as(SUBTYPE_ROUTE_ORIGIN, 4200000000, 1);

        let proto_ec = u64_to_proto_extcomm(original);
        assert!(matches!(
            proto_ec.community,
            Some(proto::extended_community::Community::FourOctetAs(_))
        ));

        let result = proto_extcomm_to_u64(&proto_ec).unwrap();
        assert_eq!(original, result);
    }

    #[test]
    fn test_link_bandwidth_roundtrip() {
        // Create Link Bandwidth: non-transitive, ASN 65000, 1.5 Gbps (in bytes/sec)
        let bandwidth_bps = 1_500_000_000.0f32;
        let bandwidth_bits = bandwidth_bps.to_bits();
        let original = from_two_octet_as(SUBTYPE_LINK_BANDWIDTH, 65000, bandwidth_bits)
            | ((TYPE_NON_TRANSITIVE_BIT as u64) << 56);

        let proto_ec = u64_to_proto_extcomm(original);
        if let Some(proto::extended_community::Community::LinkBandwidth(lb)) = &proto_ec.community
        {
            assert!(!lb.is_transitive);
            assert_eq!(lb.asn, 65000);
            assert_eq!(lb.bandwidth, bandwidth_bps);
        } else {
            panic!("Expected LinkBandwidth variant");
        }

        let result = proto_extcomm_to_u64(&proto_ec).unwrap();
        assert_eq!(original, result);
    }

    #[test]
    fn test_link_bandwidth_transitive() {
        // Test transitive Link Bandwidth (uncommon but allowed by spec)
        let bandwidth_bps = 100_000.0f32;
        let bandwidth_bits = bandwidth_bps.to_bits();
        let original = from_two_octet_as(SUBTYPE_LINK_BANDWIDTH, 200, bandwidth_bits);

        let proto_ec = u64_to_proto_extcomm(original);
        if let Some(proto::extended_community::Community::LinkBandwidth(lb)) = &proto_ec.community
        {
            assert!(lb.is_transitive);
            assert_eq!(lb.asn, 200);
            assert_eq!(lb.bandwidth, bandwidth_bps);
        } else {
            panic!("Expected LinkBandwidth variant");
        }

        let result = proto_extcomm_to_u64(&proto_ec).unwrap();
        assert_eq!(original, result);
    }

    #[test]
    fn test_opaque_roundtrip() {
        // Create opaque extended community: [type][subtype][6 bytes value]
        let mut typ = TYPE_OPAQUE;
        typ |= TYPE_NON_TRANSITIVE_BIT; // non-transitive
        let val: u64 = ((typ as u64) << 56) | 0xAABBCCDDEE00;

        let proto_ec = u64_to_proto_extcomm(val);
        if let Some(proto::extended_community::Community::Opaque(op)) = &proto_ec.community {
            assert!(!op.is_transitive);
            assert_eq!(op.value, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00]);
        } else {
            panic!("Expected Opaque variant");
        }

        let result = proto_extcomm_to_u64(&proto_ec).unwrap();
        assert_eq!(val, result);
    }

    #[test]
    fn test_unknown_type_roundtrip() {
        // Unknown type 0x99 with arbitrary data
        let val: u64 = 0x99FF_AABB_CCDD_EE00;

        let proto_ec = u64_to_proto_extcomm(val);
        if let Some(proto::extended_community::Community::Unknown(u)) = &proto_ec.community {
            assert_eq!(u.type_code, 0x99);
            assert_eq!(u.value, vec![0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00]);
        } else {
            panic!("Expected Unknown variant");
        }

        let result = proto_extcomm_to_u64(&proto_ec).unwrap();
        assert_eq!(val, result);
    }

    #[test]
    fn test_non_transitive_two_octet_as() {
        let mut val = from_two_octet_as(SUBTYPE_ROUTE_TARGET, 100, 200);
        val |= (TYPE_NON_TRANSITIVE_BIT as u64) << 56;

        let proto_ec = u64_to_proto_extcomm(val);
        if let Some(proto::extended_community::Community::TwoOctetAs(ec)) = &proto_ec.community {
            assert!(!ec.is_transitive);
            assert_eq!(ec.asn, 100);
            assert_eq!(ec.local_admin, 200);
        } else {
            panic!("Expected TwoOctetAs variant");
        }

        let result = proto_extcomm_to_u64(&proto_ec).unwrap();
        assert_eq!(val, result);
    }

    #[test]
    fn test_proto_extcomm_validation_asn_too_large() {
        let ec = proto::ExtendedCommunity {
            community: Some(proto::extended_community::Community::TwoOctetAs(
                proto::extended_community::TwoOctetAsSpecific {
                    is_transitive: true,
                    sub_type: 2,
                    asn: 70000, // exceeds 16-bit max
                    local_admin: 100,
                },
            )),
        };

        let result = proto_extcomm_to_u64(&ec);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds 16-bit max"));
    }

    #[test]
    fn test_proto_extcomm_validation_local_admin_too_large() {
        let ec = proto::ExtendedCommunity {
            community: Some(proto::extended_community::Community::Ipv4Address(
                proto::extended_community::IPv4AddressSpecific {
                    is_transitive: true,
                    sub_type: 2,
                    address: "192.168.1.1".to_string(),
                    local_admin: 70000, // exceeds 16-bit max
                },
            )),
        };

        let result = proto_extcomm_to_u64(&ec);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds 16-bit max"));
    }

    #[test]
    fn test_proto_extcomm_validation_invalid_ipv4() {
        let ec = proto::ExtendedCommunity {
            community: Some(proto::extended_community::Community::Ipv4Address(
                proto::extended_community::IPv4AddressSpecific {
                    is_transitive: true,
                    sub_type: 2,
                    address: "999.999.999.999".to_string(),
                    local_admin: 100,
                },
            )),
        };

        let result = proto_extcomm_to_u64(&ec);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid IPv4"));
    }

    #[test]
    fn test_proto_extcomm_validation_opaque_wrong_length() {
        let ec = proto::ExtendedCommunity {
            community: Some(proto::extended_community::Community::Opaque(
                proto::extended_community::Opaque {
                    is_transitive: true,
                    value: vec![0xAA, 0xBB, 0xCC], // only 3 bytes, should be 6
                },
            )),
        };

        let result = proto_extcomm_to_u64(&ec);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be 6 bytes"));
    }

    #[test]
    fn test_proto_extcomm_validation_unknown_wrong_length() {
        let ec = proto::ExtendedCommunity {
            community: Some(proto::extended_community::Community::Unknown(
                proto::extended_community::Unknown {
                    type_code: 0x99,
                    value: vec![0xAA, 0xBB], // only 2 bytes, should be 7
                },
            )),
        };

        let result = proto_extcomm_to_u64(&ec);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be 7 bytes"));
    }

    #[test]
    fn test_link_bandwidth_asn_validation() {
        let ec = proto::ExtendedCommunity {
            community: Some(proto::extended_community::Community::LinkBandwidth(
                proto::extended_community::LinkBandwidth {
                    is_transitive: false,
                    asn: 70000, // exceeds 16-bit max
                    bandwidth: 1000.0,
                },
            )),
        };

        let result = proto_extcomm_to_u64(&ec);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds 16-bit max"));
    }

    #[test]
    fn test_link_bandwidth_float_zero() {
        let bandwidth = 0.0f32;
        let bandwidth_bits = bandwidth.to_bits();
        let original = from_two_octet_as(SUBTYPE_LINK_BANDWIDTH, 100, bandwidth_bits);

        let proto_ec = u64_to_proto_extcomm(original);
        if let Some(proto::extended_community::Community::LinkBandwidth(lb)) = &proto_ec.community
        {
            assert_eq!(lb.bandwidth, 0.0);
        } else {
            panic!("Expected LinkBandwidth variant");
        }

        let result = proto_extcomm_to_u64(&proto_ec).unwrap();
        assert_eq!(original, result);
    }

    #[test]
    fn test_link_bandwidth_float_large_value() {
        // Test with large bandwidth value (10 Gbps in bytes/sec)
        let bandwidth = 10_000_000_000.0f32;
        let bandwidth_bits = bandwidth.to_bits();
        let original = from_two_octet_as(SUBTYPE_LINK_BANDWIDTH, 65000, bandwidth_bits);

        let proto_ec = u64_to_proto_extcomm(original);
        if let Some(proto::extended_community::Community::LinkBandwidth(lb)) = &proto_ec.community
        {
            // Float comparison with some tolerance due to precision
            assert!((lb.bandwidth - bandwidth).abs() < 1.0);
        } else {
            panic!("Expected LinkBandwidth variant");
        }

        let result = proto_extcomm_to_u64(&proto_ec).unwrap();
        assert_eq!(original, result);
    }
}
