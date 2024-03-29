use std::io::Read;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

// maximum message size is 4096 octets.
const BGP_HEADER_SIZE_BYTES: usize = 19;

enum MessageType {
    OPEN = 1,
    UPDATE = 2,
    NOTIFICATION = 3,
    KEEPALIVE = 4,
}

impl MessageType {
    fn from_u8(value: u8) -> Option<MessageType> {
        match value {
            1 => Some(MessageType::OPEN),
            2 => Some(MessageType::OPEN),
            3 => Some(MessageType::OPEN),
            4 => Some(MessageType::OPEN),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
enum IpNetwork {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

#[derive(Debug, PartialEq)]
struct Ipv4Net {
    address: Ipv4Addr,
    prefix_length: u8,
}

#[derive(Debug, PartialEq)]
struct Ipv6Net {
    address: Ipv6Addr,
    prefix_length: u8,
}

pub enum BgpMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
}

impl BgpMessage {
    fn from_bytes(message_type: u8, bytes: Vec<u8>) -> Result<Self, io::Error> {
        match MessageType::from_u8(message_type) {
            Some(MessageType::OPEN) => {
                let open_message = OpenMessage::from_bytes(bytes)?;
                Ok(BgpMessage::Open(open_message))
            },
            Some(MessageType::UPDATE) => {
                let update_message = UpdateMessage::from_bytes(bytes)?;
                Ok(BgpMessage::Update(update_message))
            }
            _ => {
                Err(io::Error::new(io::ErrorKind::Other, "Unknown message type"))
            }
        }
    }
}

struct UpdateMessage {
    withdrawn_routes_length: u16,
    withdrawn_routes: Vec<IpNetwork>,
    total_path_attribute_length: u16,
    // path_attributes: ?
}

fn parse_nlri_list(bytes: Vec<u8>) -> Vec<IpNetwork> {
    let mut cursor = 0;

    let mut nlri_list: Vec<IpNetwork> = Vec::new();

    while cursor < bytes.len() {
        let prefix_length = bytes[cursor];
        cursor = cursor + 1;

        let byte_len: usize = (prefix_length as usize + 7) / 8;

        let mut buff = [0; 4];
        for i in 0..byte_len {
            buff[i] = bytes[cursor + i];
        }

        let address = Ipv4Addr::from(buff);
        let network = IpNetwork::V4(Ipv4Net{address, prefix_length: prefix_length});

        nlri_list.push(network);

        cursor = cursor + byte_len + 1;
    }

    return nlri_list
}

impl UpdateMessage {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, io::Error> {
        let withdrawn_routes_length = u16::from_be_bytes([bytes[0], bytes[1]]);

        let withdraw_routes_end = (2 + withdrawn_routes_length) as usize;
        let withdrawn_routes = parse_nlri_list(bytes[2..withdraw_routes_end].to_vec());

        let total_path_attribute_length = u16::from_be_bytes([bytes[withdraw_routes_end], bytes[withdraw_routes_end+2]]);

        Ok(UpdateMessage{
            withdrawn_routes_length,
            withdrawn_routes,
            total_path_attribute_length,
        })
    }
}


struct OpenMessage {
    version: u8,
    asn: u16,
    hold_time: u16,
    bgp_identifier: u32,
    optional_parameters_length: u8,
    // opetional_parameters: 
}

impl OpenMessage {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, io::Error> {
        if bytes.len() < 10 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid OpenMessage length"));
        }

        let version = bytes[0];
        let asn = u16::from_be_bytes([bytes[1], bytes[2]]);
        let hold_time = u16::from_be_bytes([bytes[3], bytes[4]]);
        let bgp_identifier = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        let optional_parameters_length = bytes[9];

        Ok(OpenMessage{
            version,
            asn,
            hold_time,
            bgp_identifier,
            optional_parameters_length,
        })
    }
}

pub fn read_bgp_message<R: Read>(mut stream: R) -> Result<BgpMessage, io::Error> {
    let mut header_buffer  = [0u8; BGP_HEADER_SIZE_BYTES];
    stream.read_exact(&mut header_buffer)?;

    let message_length = u16::from_be_bytes([header_buffer[16], header_buffer[17]]);
    let message_type = header_buffer[18];

    let body_length = message_length - BGP_HEADER_SIZE_BYTES as u16;
    let mut message_buffer = vec![0u8; body_length.into()];
    stream.read_exact(&mut message_buffer)?;

    BgpMessage::from_bytes(message_type, message_buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor; 

    const MOCK_OPEN_MESSAGE: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x1d, // Message length (29 bytes)
        0x01, // Message type (Open)
        0x04, // Version
        0x04, 0xd2, // ASN
        0x00, 0x0a, // Hold time
        0x0a, 0x0a, 0x0a, 0x0a, // BGP identififer
        0x00 // Optional parameters length
    ];

    #[test]
    fn test_read_open_message() {
        let stream = Cursor::new(MOCK_OPEN_MESSAGE);

        match read_bgp_message(stream) {
            Ok(BgpMessage::Open(open_message)) => {
                assert_eq!(open_message.version, 4);
                assert_eq!(open_message.asn, 1234);
                assert_eq!(open_message.hold_time, 10);
                assert_eq!(open_message.bgp_identifier, 168430090);
                assert_eq!(open_message.optional_parameters_length, 0);
            }
            Err(err) => panic!("Error {}", err),
            _ => panic!("Expected BgpMessage::OPEN")
        }
    }

    #[test]
    fn test_parse_nlri_list_single() {
        let data: Vec<u8> = vec!(
            0x18,
            0x0a, 0x0b, 0x0c, 0x00,
        );

        let result = parse_nlri_list(data);
        let expected = vec!(
            IpNetwork::V4(Ipv4Net{address: Ipv4Addr::new(10 , 11, 12, 0), prefix_length: 24}),
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_nlri_list_multiple() {
        let data: Vec<u8> = vec!(
            0x18,
            0x0a, 0x0b, 0x0c, 0x00,
            0x15,
            0x0a, 0x0b, 0x08, 0x00,
        );

        let result = parse_nlri_list(data);
        let expected = vec!(
            IpNetwork::V4(Ipv4Net{address: Ipv4Addr::new(10 , 11, 12, 0), prefix_length: 24}),
            IpNetwork::V4(Ipv4Net{address: Ipv4Addr::new(10 , 11, 8, 0), prefix_length: 21}),
        );
        assert_eq!(result, expected);
    }
}
