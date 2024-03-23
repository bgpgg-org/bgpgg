use std::io::Read;
use std::io;

// maximum message size is 4096 octets.
const BGP_HEADER_SIZE_BYTES: usize = 19;

enum MessageType {
    OPEN = 1,
    UPDATE = 2,
    NOTIFICATION = 3,
    KEEPALIVE = 4,
}

pub enum BgpMessage {
    Open(OpenMessage),
}

impl BgpMessage {
    fn from_bytes(message_type: u8, bytes: Vec<u8>) -> Result<Self, io::Error> {
        if message_type == MessageType::OPEN as u8 {
            let open_message = OpenMessage::from_bytes(bytes)?;
            Ok(BgpMessage::Open(open_message))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "Unknown message type"))
        }
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
        println!("{} {} {} {}", version, asn ,hold_time, bgp_identifier);

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
        let mock_stream = Cursor::new(MOCK_OPEN_MESSAGE);

        match read_bgp_message(mock_stream) {
            Ok(BgpMessage::Open(open_message)) => {
                assert_eq!(open_message.version, 4);
                assert_eq!(open_message.asn, 1234);
                assert_eq!(open_message.hold_time, 10);
                assert_eq!(open_message.bgp_identifier, 168430090);
                assert_eq!(open_message.optional_parameters_length, 0);
            }
            Err(err) => panic!("Error {}", err)
        }
    }
}
