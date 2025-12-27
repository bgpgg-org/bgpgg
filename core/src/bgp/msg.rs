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
use super::msg_notification::{BgpError, MessageHeaderError, NotificationMessage};
use super::msg_open::OpenMessage;
use super::msg_update::UpdateMessage;
use super::utils::ParserError;
use tokio::io::AsyncReadExt;

pub const BGP_HEADER_SIZE_BYTES: usize = 19;
pub const MAX_MESSAGE_SIZE: u16 = 4096;

// BGP header marker (16 bytes of 0xFF)
pub const BGP_MARKER: [u8; 16] = [0xff; 16];

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum MessageType {
    OPEN = 1,
    UPDATE = 2,
    NOTIFICATION = 3,
    KEEPALIVE = 4,
}

impl MessageType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Trait for BGP message types that can serialize themselves
pub trait Message {
    /// Returns the message type identifier
    fn kind(&self) -> MessageType;

    /// Serializes the message body (without BGP header)
    fn to_bytes(&self) -> Vec<u8>;

    /// Serializes the complete BGP message with header
    ///
    /// This method has a default implementation that uses to_bytes()
    /// and adds the BGP header automatically.
    fn serialize(&self) -> Vec<u8> {
        let body = self.to_bytes();
        let mut message = Vec::new();

        // BGP header marker (16 bytes of 0xFF)
        message.extend_from_slice(&BGP_MARKER);

        // Message length (header + body)
        let length = BGP_HEADER_SIZE_BYTES as u16 + body.len() as u16;
        message.extend_from_slice(&length.to_be_bytes());

        // Message type
        message.push(self.kind().as_u8());

        // Message body
        message.extend_from_slice(&body);

        message
    }
}

impl TryFrom<u8> for MessageType {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MessageType::OPEN),
            2 => Ok(MessageType::UPDATE),
            3 => Ok(MessageType::NOTIFICATION),
            4 => Ok(MessageType::KEEPALIVE),
            _ => Err(ParserError::BgpError {
                error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageType),
                data: vec![value],
            }),
        }
    }
}

pub enum BgpMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
    KeepAlive(KeepAliveMessage),
    Notification(NotificationMessage),
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
                let message = NotificationMessage::from_bytes(bytes);
                Ok(BgpMessage::Notification(message))
            }
        }
    }
}

pub async fn read_bgp_message<R: AsyncReadExt + Unpin>(
    mut stream: R,
) -> Result<BgpMessage, ParserError> {
    let mut header_buffer = [0u8; BGP_HEADER_SIZE_BYTES];
    stream
        .read_exact(&mut header_buffer)
        .await
        .map_err(|err| ParserError::IoError(err.to_string()))?;

    // Validate header fields (RFC 4271 Section 6.1)
    validate_marker(&header_buffer)?;

    let message_length = u16::from_be_bytes([header_buffer[16], header_buffer[17]]);
    let message_type = header_buffer[18];

    validate_length(message_length, message_type)?;
    validate_message_type(message_type)?;

    let body_length = message_length - BGP_HEADER_SIZE_BYTES as u16;
    let mut message_buffer = vec![0u8; body_length.into()];

    if body_length > 0 {
        stream
            .read_exact(&mut message_buffer)
            .await
            .map_err(|err| ParserError::IoError(err.to_string()))?;
    }

    BgpMessage::from_bytes(message_type, message_buffer)
}

fn validate_marker(header: &[u8]) -> Result<(), ParserError> {
    if &header[0..16] != &BGP_MARKER {
        return Err(ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized),
            data: Vec::new(),
        });
    }
    Ok(())
}

fn validate_length(message_length: u16, message_type: u8) -> Result<(), ParserError> {
    if message_length < BGP_HEADER_SIZE_BYTES as u16 {
        return Err(ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            data: message_length.to_be_bytes().to_vec(),
        });
    }

    if message_length > MAX_MESSAGE_SIZE {
        return Err(ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            data: message_length.to_be_bytes().to_vec(),
        });
    }

    // Validate message-type-specific length
    if message_type == MessageType::KEEPALIVE.as_u8()
        && message_length != BGP_HEADER_SIZE_BYTES as u16
    {
        return Err(ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            data: message_length.to_be_bytes().to_vec(),
        });
    }

    // NOTIFICATION minimum length is 21 (19 header + 2 for error code/subcode)
    if message_type == MessageType::NOTIFICATION.as_u8() && message_length < 21 {
        return Err(ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            data: message_length.to_be_bytes().to_vec(),
        });
    }

    Ok(())
}

fn validate_message_type(message_type: u8) -> Result<(), ParserError> {
    MessageType::try_from(message_type)
        .map(|_| ())
        .map_err(|_| ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageType),
            data: vec![message_type],
        })
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

    #[tokio::test]
    async fn test_read_open_message() {
        let stream = Cursor::new(MOCK_OPEN_MESSAGE);

        match read_bgp_message(stream).await.unwrap() {
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

    #[tokio::test]
    async fn test_read_message_invalid_marker() {
        let mut msg = MOCK_OPEN_MESSAGE.to_vec();
        msg[0] = 0x00;
        let stream = Cursor::new(msg);
        match read_bgp_message(stream).await {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized)
                );
                assert_eq!(data, Vec::<u8>::new());
            }
            _ => panic!("Expected InvalidMarker error"),
        }
    }

    #[tokio::test]
    async fn test_read_message_length_too_small() {
        let mut msg = MOCK_OPEN_MESSAGE.to_vec();
        msg[16] = 0x00;
        msg[17] = 0x12; // 18
        let stream = Cursor::new(msg);
        match read_bgp_message(stream).await {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength)
                );
                assert_eq!(data, vec![0x00, 0x12]); // Erroneous length field
            }
            _ => panic!("Expected BadMessageLength error"),
        }
    }

    #[tokio::test]
    async fn test_read_message_length_too_large() {
        let mut msg = MOCK_OPEN_MESSAGE.to_vec();
        msg[16] = 0x10;
        msg[17] = 0x01; // 4097
        let stream = Cursor::new(msg);
        match read_bgp_message(stream).await {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength)
                );
                assert_eq!(data, vec![0x10, 0x01]); // Erroneous length field
            }
            _ => panic!("Expected BadMessageLength error"),
        }
    }

    #[tokio::test]
    async fn test_read_message_invalid_type() {
        let mut msg = MOCK_OPEN_MESSAGE.to_vec();
        msg[18] = 99;
        let stream = Cursor::new(msg);
        match read_bgp_message(stream).await {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::MessageHeaderError(MessageHeaderError::BadMessageType)
                );
                assert_eq!(data, vec![99]); // Erroneous type field
            }
            _ => panic!("Expected BadMessageType error"),
        }
    }
}
