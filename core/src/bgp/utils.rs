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
use crate::net::{IpNetwork, Ipv4Net, Ipv6Net};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

const MAX_IPV4_PREFIX_LEN: u8 = 32;
const MAX_IPV6_PREFIX_LEN: u8 = 128;

/// Validate prefix length and calculate byte length for NLRI
fn validate_and_calculate_byte_len(
    prefix_length: u8,
    max_prefix_len: u8,
    remaining_bytes: usize,
) -> Result<usize, ParserError> {
    // Check prefix length before calculating byte_len
    if prefix_length > max_prefix_len {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField),
            data: Vec::new(),
        });
    }

    let byte_len: usize = (prefix_length as usize).div_ceil(8);

    if byte_len > remaining_bytes {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField),
            data: Vec::new(),
        });
    }

    Ok(byte_len)
}

#[derive(Debug, PartialEq)]
pub enum ParserError {
    IoError(String),
    BgpError {
        error: super::msg_notification::BgpError,
        data: Vec<u8>,
    },
}

impl Display for ParserError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ParserError::IoError(s) => write!(f, "IO error: {}", s),
            ParserError::BgpError { error, .. } => write!(f, "BGP error: {:?}", error),
        }
    }
}

impl Error for ParserError {}

/// RFC 7911: Parse NLRI list with 4-byte path identifiers prepended to each entry
pub fn parse_nlri_list_addpath(bytes: &[u8]) -> Result<Vec<(IpNetwork, u32)>, ParserError> {
    let mut cursor = 0;
    let mut nlri_list = Vec::new();

    while cursor < bytes.len() {
        if cursor + 4 > bytes.len() {
            return Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField),
                data: Vec::new(),
            });
        }
        let path_id = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        cursor += 4;

        let prefix_length = bytes[cursor];
        cursor += 1;

        let byte_len = validate_and_calculate_byte_len(
            prefix_length,
            MAX_IPV4_PREFIX_LEN,
            bytes.len() - cursor,
        )?;

        let mut ip_buffer = [0; 4];
        ip_buffer[..byte_len].copy_from_slice(&bytes[cursor..(byte_len + cursor)]);

        let net = Ipv4Net {
            address: Ipv4Addr::from(ip_buffer),
            prefix_length,
        };

        if net.is_multicast() {
            cursor += byte_len;
            continue;
        }

        nlri_list.push((IpNetwork::V4(net), path_id));
        cursor += byte_len;
    }

    Ok(nlri_list)
}

pub fn parse_nlri_list(bytes: &[u8]) -> Result<Vec<IpNetwork>, ParserError> {
    let mut cursor = 0;
    let mut nlri_list: Vec<IpNetwork> = Vec::new();

    while cursor < bytes.len() {
        let prefix_length = bytes[cursor];
        cursor += 1;

        let byte_len = validate_and_calculate_byte_len(
            prefix_length,
            MAX_IPV4_PREFIX_LEN,
            bytes.len() - cursor,
        )?;

        let mut ip_buffer = [0; 4];
        ip_buffer[..byte_len].copy_from_slice(&bytes[cursor..(byte_len + cursor)]);

        let net = Ipv4Net {
            address: Ipv4Addr::from(ip_buffer),
            prefix_length,
        };

        // Semantic check: skip multicast prefixes (224.0.0.0/4)
        if net.is_multicast() {
            eprintln!(
                "Warning: ignoring multicast NLRI prefix, prefix={:?}",
                format!("{:?}", net)
            );
            cursor += byte_len;
            continue;
        }

        nlri_list.push(IpNetwork::V4(net));
        cursor += byte_len;
    }

    Ok(nlri_list)
}

/// RFC 7911: Parse IPv6 NLRI list with 4-byte path identifiers prepended to each entry
pub fn parse_nlri_v6_list_addpath(bytes: &[u8]) -> Result<Vec<(IpNetwork, u32)>, ParserError> {
    let mut cursor = 0;
    let mut nlri_list = Vec::new();

    while cursor < bytes.len() {
        if cursor + 4 > bytes.len() {
            return Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField),
                data: Vec::new(),
            });
        }
        let path_id = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        cursor += 4;

        let prefix_length = bytes[cursor];
        cursor += 1;

        let byte_len = validate_and_calculate_byte_len(
            prefix_length,
            MAX_IPV6_PREFIX_LEN,
            bytes.len() - cursor,
        )?;

        let mut ip_buffer = [0; 16];
        ip_buffer[..byte_len].copy_from_slice(&bytes[cursor..(byte_len + cursor)]);

        let net = Ipv6Net {
            address: Ipv6Addr::from(ip_buffer),
            prefix_length,
        };

        nlri_list.push((IpNetwork::V6(net), path_id));
        cursor += byte_len;
    }

    Ok(nlri_list)
}

pub fn parse_nlri_v6_list(bytes: &[u8]) -> Result<Vec<IpNetwork>, ParserError> {
    let mut cursor = 0;
    let mut nlri_list: Vec<IpNetwork> = Vec::new();

    while cursor < bytes.len() {
        let prefix_length = bytes[cursor];
        cursor += 1;

        let byte_len = validate_and_calculate_byte_len(
            prefix_length,
            MAX_IPV6_PREFIX_LEN,
            bytes.len() - cursor,
        )?;

        let mut ip_buffer = [0; 16];
        ip_buffer[..byte_len].copy_from_slice(&bytes[cursor..(byte_len + cursor)]);

        let net = Ipv6Net {
            address: Ipv6Addr::from(ip_buffer),
            prefix_length,
        };

        nlri_list.push(IpNetwork::V6(net));
        cursor += byte_len;
    }

    Ok(nlri_list)
}

pub fn read_u32(bytes: &[u8]) -> Result<u32, ParserError> {
    match bytes.len() {
        4 => Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        _ => Err(ParserError::BgpError {
            error: super::msg_notification::BgpError::UpdateMessageError(
                super::msg_notification::UpdateMessageError::AttributeLengthError,
            ),
            data: Vec::new(),
        }),
    }
}

/// Validates if an IPv4 address is a valid unicast host address.
/// Returns false for 0.0.0.0, 255.255.255.255, or multicast (224.0.0.0/4).
pub fn is_valid_unicast_ipv4(ip: u32) -> bool {
    !(ip == 0 || ip == 0xFFFFFFFF || (ip & 0xF0000000) == 0xE0000000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_notification::{BgpError, UpdateMessageError};

    #[test]
    fn test_parse_nlri_list_single() {
        let data: Vec<u8> = vec![0x18, 0x0a, 0x0b, 0x0c]; // /24 prefix: 1 byte length + 3 bytes IP

        let result = parse_nlri_list(&data).unwrap();
        let expected = vec![IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 11, 12, 0),
            prefix_length: 24,
        })];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_nlri_list_multiple() {
        let data: Vec<u8> = vec![
            0x18, 0x0a, 0x0b, 0x0c, // /24 prefix: 1 byte length + 3 bytes IP
            0x15, 0x0a, 0x0b, 0x08, // /21 prefix: 1 byte length + 3 bytes IP
        ];

        let result = parse_nlri_list(&data).unwrap();
        let expected = vec![
            IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 11, 12, 0),
                prefix_length: 24,
            }),
            IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 11, 8, 0),
                prefix_length: 21,
            }),
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_nlri_list_invalid_prefix_length() {
        let data: Vec<u8> = vec![33, 0x0a, 0x0b, 0x0c, 0x0d, 0x00]; // /33 is invalid for IPv4

        match parse_nlri_list(&data) {
            Err(ParserError::BgpError { error, .. }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField)
                );
            }
            _ => panic!("Expected InvalidNetworkField"),
        }
    }

    #[test]
    fn test_parse_nlri_list_truncated() {
        // Claims /24 (needs 3 bytes) but only provides 2
        let data: Vec<u8> = vec![24, 0x0a, 0x0b];

        match parse_nlri_list(&data) {
            Err(ParserError::BgpError { error, .. }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField)
                );
            }
            _ => panic!("Expected InvalidNetworkField"),
        }
    }

    #[test]
    fn test_ipv4net_is_multicast() {
        let multicast = Ipv4Net {
            address: Ipv4Addr::new(224, 0, 0, 1),
            prefix_length: 24,
        };
        assert!(multicast.is_multicast());

        let unicast = Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        };
        assert!(!unicast.is_multicast());
    }

    #[test]
    fn test_parse_nlri_list_multicast_filtered() {
        // Mix of valid unicast and multicast prefixes
        let data: Vec<u8> = vec![
            24, 10, 11, 12, // 10.11.12.0/24 - valid
            24, 224, 0, 0, // 224.0.0.0/24 - multicast, should be filtered
            24, 192, 168, 1, // 192.168.1.0/24 - valid
        ];

        let result = parse_nlri_list(&data).unwrap();

        // Only unicast prefixes should be returned
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 11, 12, 0),
                prefix_length: 24,
            })
        );
        assert_eq!(
            result[1],
            IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(192, 168, 1, 0),
                prefix_length: 24,
            })
        );
    }

    #[test]
    fn test_is_valid_unicast_ipv4() {
        let test_cases = vec![
            (u32::from(Ipv4Addr::new(10, 0, 0, 1)), true, "10.0.0.1"),
            (
                u32::from(Ipv4Addr::new(192, 168, 1, 1)),
                true,
                "192.168.1.1",
            ),
            (u32::from(Ipv4Addr::new(1, 1, 1, 1)), true, "1.1.1.1"),
            (
                u32::from(Ipv4Addr::new(223, 255, 255, 255)),
                true,
                "223.255.255.255",
            ),
            (0x00000000, false, "0.0.0.0"),
            (0xFFFFFFFF, false, "255.255.255.255"),
            (0xE0000001, false, "224.0.0.1 (multicast)"),
            (0xEFFFFFFF, false, "239.255.255.255 (multicast)"),
        ];

        for (ip, expected, name) in test_cases {
            assert_eq!(is_valid_unicast_ipv4(ip), expected, "Failed for {}", name);
        }
    }

    #[test]
    fn test_parse_nlri_v6_list_single() {
        // 2001:db8::/32
        let data: Vec<u8> = vec![0x20, 0x20, 0x01, 0x0d, 0xb8];

        let result = parse_nlri_v6_list(&data).unwrap();
        let expected = vec![IpNetwork::V6(Ipv6Net {
            address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
            prefix_length: 32,
        })];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_nlri_v6_list_multiple() {
        // Test various prefix lengths: /32, /48, /64, /128
        let data: Vec<u8> = vec![
            0x20, 0x20, 0x01, 0x0d, 0xb8, // 2001:db8::/32
            0x30, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, // 2001:db8:1::/48
            0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, // 2001:db8:0:1::/64
            0x80, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, // 2001:db8::1/128
        ];

        let result = parse_nlri_v6_list(&data).unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(
            result[0],
            IpNetwork::V6(Ipv6Net {
                address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
                prefix_length: 32,
            })
        );
        assert_eq!(
            result[1],
            IpNetwork::V6(Ipv6Net {
                address: Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 0),
                prefix_length: 48,
            })
        );
        assert_eq!(
            result[2],
            IpNetwork::V6(Ipv6Net {
                address: Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0, 0, 0, 0),
                prefix_length: 64,
            })
        );
        assert_eq!(
            result[3],
            IpNetwork::V6(Ipv6Net {
                address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                prefix_length: 128,
            })
        );
    }

    #[test]
    fn test_parse_nlri_v6_list_empty() {
        let data: Vec<u8> = vec![];
        let result = parse_nlri_v6_list(&data).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_nlri_v6_list_invalid_prefix_length() {
        let data: Vec<u8> = vec![129, 0x20, 0x01]; // /129 is invalid for IPv6

        match parse_nlri_v6_list(&data) {
            Err(ParserError::BgpError { error, .. }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField)
                );
            }
            _ => panic!("Expected InvalidNetworkField"),
        }
    }

    #[test]
    fn test_parse_nlri_v6_list_truncated() {
        // Claims /32 (needs 4 bytes) but only provides 2
        let data: Vec<u8> = vec![32, 0x20, 0x01];

        match parse_nlri_v6_list(&data) {
            Err(ParserError::BgpError { error, .. }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField)
                );
            }
            _ => panic!("Expected InvalidNetworkField"),
        }
    }

    #[test]
    fn test_parse_nlri_list_addpath() {
        // path_id(4) + prefix_len(1) + prefix_octets(3) = 8 bytes per entry
        let data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x01, // path_id = 1
            0x18, 0x0a, 0x0b, 0x0c, // 10.11.12.0/24
            0x00, 0x00, 0x00, 0x02, // path_id = 2
            0x10, 0xc0, 0xa8, // 192.168.0.0/16
        ];

        let result = parse_nlri_list_addpath(&data).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            (
                IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(10, 11, 12, 0),
                    prefix_length: 24,
                }),
                1
            )
        );
        assert_eq!(
            result[1],
            (
                IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(192, 168, 0, 0),
                    prefix_length: 16,
                }),
                2
            )
        );
    }

    #[test]
    fn test_parse_nlri_list_addpath_truncated_path_id() {
        // Only 2 bytes where 4-byte path_id is expected
        let data: Vec<u8> = vec![0x00, 0x01];
        assert!(parse_nlri_list_addpath(&data).is_err());
    }
}
