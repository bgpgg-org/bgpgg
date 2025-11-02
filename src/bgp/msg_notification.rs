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

#[repr(u8)]
#[derive(Debug, PartialEq)]
enum MessageHeaderError {
    ConnectionNotSynchronized = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
    Unknown(u8),
}

impl From<u8> for MessageHeaderError {
    fn from(value: u8) -> Self {
        match value {
            1 => MessageHeaderError::ConnectionNotSynchronized,
            2 => MessageHeaderError::BadMessageLength,
            3 => MessageHeaderError::BadMessageType,
            val => MessageHeaderError::Unknown(val),
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq)]
enum OpenMessageError {
    UnsupportedVersionNumber = 1,
    BadPeerAs = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptionalParameter = 4,
    UnacceptedHoldTime = 6,
    Unknown(u8),
}

impl From<u8> for OpenMessageError {
    fn from(value: u8) -> Self {
        match value {
            1 => OpenMessageError::UnsupportedVersionNumber,
            2 => OpenMessageError::BadPeerAs,
            3 => OpenMessageError::BadBgpIdentifier,
            4 => OpenMessageError::UnsupportedOptionalParameter,
            6 => OpenMessageError::UnacceptedHoldTime,
            val => OpenMessageError::Unknown(val),
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq)]
enum UpdateMessageError {
    MalformedAttributeList = 1,
    UnrecognizedWellKnownAttribute = 2,
    MissingWellKnownAttribute = 3,
    AttributeFlagsError = 4,
    AttributeLengthError = 5,
    InvalidOriginAttribute = 6,
    InvalidNextHopAttribute = 7,
    OptionalAttributeError = 8,
    InvalidNetworkField = 9,
    MalformedASPath = 10,
    MalformedNextHop = 11,
    Unknown(u8),
}

impl From<u8> for UpdateMessageError {
    fn from(value: u8) -> Self {
        match value {
            1 => UpdateMessageError::MalformedAttributeList,
            2 => UpdateMessageError::UnrecognizedWellKnownAttribute,
            3 => UpdateMessageError::MissingWellKnownAttribute,
            4 => UpdateMessageError::AttributeFlagsError,
            5 => UpdateMessageError::AttributeLengthError,
            6 => UpdateMessageError::InvalidOriginAttribute,
            7 => UpdateMessageError::InvalidNextHopAttribute,
            8 => UpdateMessageError::OptionalAttributeError,
            9 => UpdateMessageError::InvalidNetworkField,
            10 => UpdateMessageError::MalformedASPath,
            11 => UpdateMessageError::MalformedNextHop,
            val => UpdateMessageError::Unknown(val),
        }
    }
}

#[derive(Debug, PartialEq)]
enum BgpError {
    MessageHeaderError(MessageHeaderError),
    OpenMessageError(OpenMessageError),
    UpdateMessageError(UpdateMessageError),
    HoldTimerExpired,
    FiniteStateMachineError,
    Cease,
    Unknown,
}

#[repr(u8)]
enum ErrorCode {
    Cease = 0,
    MessageHeaderError = 1,
    OpenMessageError = 2,
    UpdateMessageError = 3,
    HoldTimerExpired = 4,
    FiniteStateMachineError = 5,
    Unknown(u8),
}

impl From<u8> for ErrorCode {
    fn from(value: u8) -> Self {
        match value {
            0 => ErrorCode::Cease,
            1 => ErrorCode::MessageHeaderError,
            2 => ErrorCode::OpenMessageError,
            3 => ErrorCode::UpdateMessageError,
            4 => ErrorCode::HoldTimerExpired,
            5 => ErrorCode::FiniteStateMachineError,
            val => ErrorCode::Unknown(val),
        }
    }
}

impl BgpError {
    fn new(err_code: u8, err_sub_code: u8) -> BgpError {
        match ErrorCode::from(err_code) {
            ErrorCode::Cease => BgpError::Cease,
            ErrorCode::MessageHeaderError => {
                BgpError::MessageHeaderError(MessageHeaderError::from(err_sub_code))
            }
            ErrorCode::OpenMessageError => {
                BgpError::OpenMessageError(OpenMessageError::from(err_sub_code))
            }
            ErrorCode::UpdateMessageError => {
                BgpError::UpdateMessageError(UpdateMessageError::from(err_sub_code))
            }
            ErrorCode::HoldTimerExpired => BgpError::HoldTimerExpired,
            ErrorCode::FiniteStateMachineError => BgpError::FiniteStateMachineError,
            _ => BgpError::Unknown,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct NotifcationMessage {
    error: BgpError,
    data: Vec<u8>,
}

impl NotifcationMessage {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let err_code = bytes[0];
        let err_sub_code = bytes[1];

        let bgp_error = BgpError::new(err_code, err_sub_code);
        let data = &bytes[2..];

        NotifcationMessage {
            error: bgp_error,
            data: data.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_bgp_error_new {
        ($name: ident, $err_code: expr, $err_sub_code: expr, expected $expected:expr) => {
            #[test]
            fn $name() {
                let error = BgpError::new($err_code, $err_sub_code);
                assert_eq!(error, $expected)
            }
        };
    }

    test_bgp_error_new!(
        bgp_error_new_msg_header_1, 1, 1,
        expected BgpError::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized)
    );
    test_bgp_error_new!(
        bgp_error_new_open_message_1, 2, 1,
        expected BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber)
    );
    test_bgp_error_new!(
        bgp_error_new_update_message_1, 3, 1,
        expected BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList)
    );
    test_bgp_error_new!(
        bgp_error_new_hold_timer, 4, 0,
        expected BgpError::HoldTimerExpired
    );
    test_bgp_error_new!(
        bgp_error_new_fsm, 5, 0,
        expected BgpError::FiniteStateMachineError
    );
    test_bgp_error_new!(
        bgp_error_new_cease, 0, 0,
        expected BgpError::Cease
    );
    test_bgp_error_new!(
        bgp_error_new_unknown, 99, 0,
        expected BgpError::Unknown
    );

    #[test]
    fn test_notification_message_from_bytes() {
        let input = vec![
            0x03, // Error code
            0x02, // Error subcode
            // Data
            // https://datatracker.ietf.org/doc/html/rfc4271#section-6.3
            0x00, 0xff, // Attribute type
            0x01, // Attribute length
            0x02, // Attribute Value
        ];
        let result = NotifcationMessage::from_bytes(input);

        assert_eq!(
            result,
            NotifcationMessage {
                error: BgpError::UpdateMessageError(
                    UpdateMessageError::UnrecognizedWellKnownAttribute
                ),
                data: vec![0x00, 0xff, 0x01, 0x02],
            }
        )
    }

    #[test]
    fn test_notification_message_from_bytes_no_data() {
        let input = vec![
            0x02, // Error code
            0x04, // Error subcode
        ];
        let result = NotifcationMessage::from_bytes(input);

        assert_eq!(
            result,
            NotifcationMessage {
                error: BgpError::OpenMessageError(OpenMessageError::UnsupportedOptionalParameter),
                data: vec![],
            }
        )
    }
}
