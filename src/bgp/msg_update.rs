use super::utils::{parse_nlri_list, read_u32, IpNetwork, ParserError};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq)]
struct PathAttrFlag(u8);

impl PathAttrFlag {
    const OPTIONAL: u8 = 1 << 7;
    const TRANSITIVE: u8 = 1 << 6;
    const PARTIAL: u8 = 1 << 5;
    const EXTENDED_LENGTH: u8 = 1 << 4;

    fn extended_len(&self) -> bool {
        self.0 & Self::EXTENDED_LENGTH != 0
    }
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
            _ => Err(ParserError::ParseError(String::from("Invalid Origin"))),
        }
    }
}

#[derive(Debug, PartialEq)]
enum Origin {
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
            _ => Err(ParserError::ParseError(String::from("Invalid Origin"))),
        }
    }
}

#[derive(Debug, PartialEq)]
struct AsPathSegment {
    segment_type: AsPathSegmentType,
    segment_len: u8,
    asn_list: Vec<u16>,
}

#[derive(Debug, PartialEq)]
enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
}

impl TryFrom<u8> for AsPathSegmentType {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AsPathSegmentType::AsSet),
            2 => Ok(AsPathSegmentType::AsSequence),
            _ => Err(ParserError::ParseError(String::from(
                "Invalid AS path segment type",
            ))),
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
        let segment_type = AsPathSegmentType::try_from(bytes[cursor])?;
        let segment_len = bytes[cursor + 1];
        let mut asn_list = vec![];

        cursor = cursor + 2;

        for _ in 0..segment_len {
            let asn = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
            asn_list.push(asn);

            cursor = cursor + 2;
        }

        let segment = AsPathSegment {
            segment_type,
            segment_len,
            asn_list,
        };

        segments.push(segment);
    }

    return Ok(AsPath { segments });
}

fn read_attr_next_hop(bytes: &[u8]) -> Result<NextHopAddr, ParserError> {
    match bytes.len() {
        4 => {
            let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            Ok(NextHopAddr::Ipv4(ip))
        }
        16 => {
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(bytes);

            let ip = Ipv6Addr::from(ip_bytes);
            Ok(NextHopAddr::Ipv6(ip))
        }
        _ => Err(ParserError::InvalidLength(String::from(
            "Invalid next hop length",
        ))),
    }
}

fn read_attr_aggregator(bytes: &[u8]) -> Result<Aggregator, ParserError> {
    if bytes.len() != 6 {
        return Err(ParserError::InvalidLength(
            "Invalid length for aggregator".to_string(),
        ));
    }

    let asn = u16::from_be_bytes([bytes[0], bytes[1]]);
    let ip_addr = Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]);

    Ok(Aggregator { asn, ip_addr })
}

fn read_path_attribute(bytes: &[u8]) -> Result<(PathAttribute, u8), ParserError> {
    let attribute_flag = PathAttrFlag(bytes[0]);
    let attr_type = AttrType::try_from(bytes[1])?;

    let attr_len = match attribute_flag.extended_len() {
        true => u16::from_be_bytes([bytes[2], bytes[3]]),
        false => bytes[2] as u16,
    };

    let mut offset = 3;
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
                return Err(ParserError::InvalidLength(String::from(
                    "Atomic aggreagte should have no value.",
                )));
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

impl UpdateMessage {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ParserError> {
        let mut data = bytes;

        let withdrawn_routes_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        data = data[2..].to_vec();

        let withdrawn_routes = parse_nlri_list(&data[..withdrawn_routes_len]);
        data = data[withdrawn_routes_len..].to_vec();

        let total_path_attributes_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        data = data[2..].to_vec();

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
        0x00, 0x0f, // Withdrawn routes length
        0x18, 0x0a, 0x0b, 0x0c, 0x00, // Withdrawn route #1
        0x18, 0x0a, 0x0b, 0x0d, 0x00, // Withdrawn route #2
        0x18, 0x0a, 0x0b, 0x0e, 0x00, // Withdrawn route #2
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
    fn test_read_path_attribute_next_hop_ipv6() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE, // Attribute flags
            AttrType::NextHop as u8,  // Attribute type
            0x10,                     // Attribute length
            // IPv6
            0x20,
            0x01,
            0x0d,
            0xb8,
            0x85,
            0xa3,
            0x00,
            0x00,
            0x00,
            0x00,
            0x8a,
            0x2e,
            0x03,
            0x70,
            0x73,
            0x34,
        ];

        let (as_path, offset) = read_path_attribute(input).unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::NextHop(NextHopAddr::Ipv6(
                    Ipv6Addr::from_str("2001:0db8:85a3:0000:0000:8a2e:0370:7334").unwrap()
                )),
            }
        );
        assert_eq!(offset, 19);
    }

    #[test]
    fn test_read_path_attribute_next_hop_invalid_next_hop() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE, // Attribute flags
            AttrType::NextHop as u8,  // Attribute type
            0x05,                     // Attribute length (invalid)
            // IPv4
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
        ];

        assert!(matches!(
            read_path_attribute(input),
            Err(ParserError::InvalidLength(_))
        ))
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
            0x03,                          // Attribute length (invalid)
            // Attribute value
            0x00,
            0x00,
            0x01,
        ];

        assert!(matches!(
            read_path_attribute(input),
            Err(ParserError::InvalidLength(_))
        ))
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
            0x03,                      // Attribute length
            // Attribute value
            0x00,
            0x00,
            0x0f,
        ];

        assert!(matches!(
            read_path_attribute(input),
            Err(ParserError::InvalidLength(_))
        ))
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
            0x01,                            // Attribute length
            0x00,                            // Attribute value
        ];

        assert!(matches!(
            read_path_attribute(input),
            Err(ParserError::InvalidLength(_))
        ))
    }

    #[test]
    fn test_read_path_attribute_aggregator_ipv4() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,   // Attribute flags
            AttrType::Aggregator as u8, // Attribute type
            0x06,                       // Attribute length
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
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
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
            PathAttrFlag::TRANSITIVE,   // Attribute flags
            AttrType::Aggregator as u8, // Attribute type
            0x03,                       // Attribute length
            // Attribute value
            0x00, // ASN
            0x10,
            0x0a, // IPv4
            0x0b,
            0x0c,
            0x0d,
        ];

        assert!(matches!(
            read_path_attribute(input),
            Err(ParserError::InvalidLength(_))
        ))
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
                0x18, 0x0a, 0x0b, 0x0f, 0x00, // NLRI #1
                0x18, 0x0a, 0x0b, 0x10, 0x00, // NLRI #2
            ]

        ].concat(),
        expected UpdateMessage{
            withdrawn_routes_len: 15,
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
                0x18, 0x0a, 0x0b, 0x0f, 0x00, // NLRI #1
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
            withdrawn_routes_len: 15,
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
}
