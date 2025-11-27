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

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

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

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum IpNetwork {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Ipv4Net {
    pub address: Ipv4Addr,
    pub prefix_length: u8,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Ipv6Net {
    pub address: Ipv6Addr,
    pub prefix_length: u8,
}

pub fn parse_nlri_list(bytes: &[u8]) -> Vec<IpNetwork> {
    let mut cursor = 0;
    let mut nlri_list: Vec<IpNetwork> = Vec::new();

    while cursor < bytes.len() {
        let prefix_length = bytes[cursor];
        cursor = cursor + 1;

        let byte_len: usize = (prefix_length as usize + 7) / 8;

        let mut ip_buffer = [0; 4];
        for i in 0..byte_len {
            ip_buffer[i] = bytes[cursor + i];
        }

        let address = Ipv4Addr::from(ip_buffer);
        let network = IpNetwork::V4(Ipv4Net {
            address,
            prefix_length,
        });

        nlri_list.push(network);

        cursor = cursor + byte_len;
    }

    return nlri_list;
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

    #[test]
    fn test_parse_nlri_list_single() {
        let data: Vec<u8> = vec![0x18, 0x0a, 0x0b, 0x0c]; // /24 prefix: 1 byte length + 3 bytes IP

        let result = parse_nlri_list(&data);
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

        let result = parse_nlri_list(&data);
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
}
