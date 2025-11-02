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

use super::msg_keepalive::KeepAliveMessage;
use super::msg_notification::NotifcationMessage;
use super::msg_open::OpenMessage;
use super::msg_update::UpdateMessage;
use super::utils::ParserError;
use std::io::Read;

// maximum message size is 4096 octets.
const BGP_HEADER_SIZE_BYTES: usize = 19;

enum MessageType {
    OPEN = 1,
    UPDATE = 2,
    NOTIFICATION = 3,
    KEEPALIVE = 4,
}

impl TryFrom<u8> for MessageType {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MessageType::OPEN),
            2 => Ok(MessageType::UPDATE),
            3 => Ok(MessageType::NOTIFICATION),
            4 => Ok(MessageType::KEEPALIVE),
            _ => Err(ParserError::ParseError("Invalid message type".to_string())),
        }
    }
}

pub enum BgpMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
    KeepAlive(KeepAliveMessage),
    Notification(NotifcationMessage),
}

impl BgpMessage {
    fn from_bytes(message_type_val: u8, bytes: Vec<u8>) -> Result<Self, ParserError> {
        let message_type = MessageType::try_from(message_type_val)?;

        match message_type {
            MessageType::OPEN => {
                let message = OpenMessage::from_bytes(bytes)?;
                Ok(BgpMessage::Open(message))
            }
            MessageType::UPDATE => {
                let message = UpdateMessage::from_bytes(bytes)?;
                Ok(BgpMessage::Update(message))
            }
            MessageType::KEEPALIVE => Ok(BgpMessage::KeepAlive(KeepAliveMessage {})),
            MessageType::NOTIFICATION => {
                let message = NotifcationMessage::from_bytes(bytes);
                Ok(BgpMessage::Notification(message))
            }
        }
    }
}

pub fn read_bgp_message<R: Read>(mut stream: R) -> Result<BgpMessage, ParserError> {
    let mut header_buffer = [0u8; BGP_HEADER_SIZE_BYTES];
    let _ = match stream.read_exact(&mut header_buffer) {
        Err(err) => Err(ParserError::IoError(err.to_string())),
        Ok(val) => Ok(val),
    };

    let message_length = u16::from_be_bytes([header_buffer[16], header_buffer[17]]);
    let message_type = header_buffer[18];

    let body_length = message_length - BGP_HEADER_SIZE_BYTES as u16;
    let mut message_buffer = vec![0u8; body_length.into()];
    let _ = match stream.read_exact(&mut message_buffer) {
        Err(err) => Err(ParserError::IoError(err.to_string())),
        Ok(val) => Ok(val),
    };

    BgpMessage::from_bytes(message_type, message_buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const MOCK_OPEN_MESSAGE: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x1d, // Message length (29 bytes)
        0x01, // Message type (Open)
        0x04, // Version
        0x04, 0xd2, // ASN
        0x00, 0x0a, // Hold time
        0x0a, 0x0a, 0x0a, 0x0a, // BGP identififer
        0x00, // Optional parameters length
    ];

    #[test]
    fn test_read_open_message() {
        let stream = Cursor::new(MOCK_OPEN_MESSAGE);

        match read_bgp_message(stream).unwrap() {
            BgpMessage::Open(open_message) => {
                assert_eq!(open_message.version, 4);
                assert_eq!(open_message.asn, 1234);
                assert_eq!(open_message.hold_time, 10);
                assert_eq!(open_message.bgp_identifier, 168430090);
                assert_eq!(open_message.optional_params_len, 0);
                assert_eq!(open_message.optional_params, vec![]);
            }
            _ => panic!("Expected BgpMessage::OPEN"),
        }
    }
}
