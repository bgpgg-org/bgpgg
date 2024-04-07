use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq)]
pub enum ParserError {
    IoError(String),
    ParseError(String),
    InvalidLength(String),
}

impl Display for ParserError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ParserError::IoError(s) => write!(f, "Parse error: {}", s),
            ParserError::ParseError(s) => write!(f, "Parse error: {}", s),
            ParserError::InvalidLength(s) => write!(f, "Parse error: {}", s),
        }
    }
}

impl Error for ParserError {}

#[derive(Debug, PartialEq)]
pub enum IpNetwork {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

#[derive(Debug, PartialEq)]
pub struct Ipv4Net {
    pub address: Ipv4Addr,
    pub prefix_length: u8,
}

#[derive(Debug, PartialEq)]
pub struct Ipv6Net {
    address: Ipv6Addr,
    prefix_length: u8,
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

        cursor = cursor + byte_len + 1;
    }

    return nlri_list;
}

pub fn read_u32(bytes: &[u8]) -> Result<u32, ParserError> {
    match bytes.len() {
        4 => Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        _ => Err(ParserError::InvalidLength(String::from(
            "Invalid length for u32",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nlri_list_single() {
        let data: Vec<u8> = vec![0x18, 0x0a, 0x0b, 0x0c, 0x00];

        let result = parse_nlri_list(&data);
        let expected = vec![IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 11, 12, 0),
            prefix_length: 24,
        })];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_nlri_list_multiple() {
        let data: Vec<u8> = vec![0x18, 0x0a, 0x0b, 0x0c, 0x00, 0x15, 0x0a, 0x0b, 0x08, 0x00];

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
}
