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

use super::msg::{Message, MessageType};
use super::msg_notification::{BgpError, OpenMessageError};
use super::utils::{is_valid_unicast_ipv4, ParserError};

const BGP_VERSION: u8 = 4;

#[derive(Debug)]
pub struct OpenMessage {
    pub version: u8,
    pub asn: u16,
    pub hold_time: u16,
    pub bgp_identifier: u32,
    pub optional_params_len: u8,
    pub optional_params: Vec<OptionalParam>,
}

#[derive(Debug, PartialEq)]
enum BgpCapabiltyCode {
    Multiprotocol = 1,
    RouteRefresh = 2,
    Unknown,
}

impl From<u8> for BgpCapabiltyCode {
    fn from(value: u8) -> Self {
        match value {
            1 => BgpCapabiltyCode::Multiprotocol,
            2 => BgpCapabiltyCode::RouteRefresh,
            _ => BgpCapabiltyCode::Unknown,
        }
    }
}

// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11
#[derive(Debug, PartialEq)]
#[repr(u8)]
enum OptionalParamTypes {
    Capabilities = 2, // RFC3392
    Unknown(u8),
}

impl From<u8> for OptionalParamTypes {
    fn from(value: u8) -> Self {
        match value {
            2 => OptionalParamTypes::Capabilities,
            val => OptionalParamTypes::Unknown(val),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct OptionalParam {
    param_type: OptionalParamTypes,
    param_len: u8,
    param_value: ParamVal,
}

#[derive(Debug, PartialEq)]
enum ParamVal {
    Capability(Capability),
    Unknown(Vec<u8>),
}

#[derive(Debug, PartialEq)]
struct Capability {
    code: BgpCapabiltyCode,
    len: u8,
    val: Vec<u8>,
}

impl Capability {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.code.as_u8());
        bytes.push(self.len);
        bytes.extend_from_slice(&self.val);
        bytes
    }
}

impl BgpCapabiltyCode {
    fn as_u8(&self) -> u8 {
        match self {
            BgpCapabiltyCode::Multiprotocol => 1,
            BgpCapabiltyCode::RouteRefresh => 2,
            BgpCapabiltyCode::Unknown => 0,
        }
    }
}

impl ParamVal {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            ParamVal::Capability(cap) => cap.to_bytes(),
            ParamVal::Unknown(data) => data.clone(),
        }
    }
}

impl OptionalParamTypes {
    fn as_u8(&self) -> u8 {
        match self {
            OptionalParamTypes::Capabilities => 2,
            OptionalParamTypes::Unknown(val) => *val,
        }
    }
}

impl OptionalParam {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.param_type.as_u8());
        bytes.push(self.param_len);
        bytes.extend_from_slice(&self.param_value.to_bytes());
        bytes
    }
}

fn read_optional_parameters(bytes: Vec<u8>) -> Vec<OptionalParam> {
    let mut cursor = 0;
    let mut params: Vec<OptionalParam> = Vec::new();

    while cursor < bytes.len() {
        let param_type_val = bytes[cursor];
        let param_len = bytes[cursor + 1] as usize;

        let param_type = OptionalParamTypes::from(param_type_val);

        cursor = cursor + 2;

        let param_value: ParamVal = match param_type {
            OptionalParamTypes::Capabilities => {
                let code = bytes[cursor];
                let len = bytes[cursor + 1] as usize;
                cursor = cursor + 2;

                let val = &bytes[cursor..cursor + len];
                cursor = cursor + len;

                ParamVal::Capability(Capability {
                    code: BgpCapabiltyCode::from(code),
                    len: len as u8,
                    val: val.to_vec(),
                })
            }
            _ => {
                let val = &bytes[cursor..cursor + param_len];
                cursor = cursor + param_len;

                ParamVal::Unknown(val.to_vec())
            }
        };

        params.push(OptionalParam {
            param_type,
            param_len: param_len as u8,
            param_value,
        })
    }

    return params;
}

/// Validate BGP version (RFC 4271 Section 6.2)
fn validate_version(version: u8) -> Result<(), ParserError> {
    if version != BGP_VERSION {
        // RFC 4271: Data field is a 2-octet unsigned integer indicating the largest
        // locally-supported version number (which is 4)
        return Err(ParserError::BgpError {
            error: BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber),
            data: (BGP_VERSION as u16).to_be_bytes().to_vec(),
        });
    }
    Ok(())
}

/// Validate Hold Time (RFC 4271 Section 6.2)
/// MUST reject Hold Time values of one or two seconds
fn validate_hold_time(hold_time: u16) -> Result<(), ParserError> {
    if hold_time == 1 || hold_time == 2 {
        // RFC 4271: No specific data field requirement for UnacceptableHoldTime
        return Err(ParserError::BgpError {
            error: BgpError::OpenMessageError(OpenMessageError::UnacceptedHoldTime),
            data: Vec::new(),
        });
    }
    Ok(())
}

/// Validate BGP Identifier (RFC 4271 Section 6.2)
/// Must be a valid unicast IP host address
/// Cannot be 0.0.0.0, 255.255.255.255, or multicast (224.0.0.0/4)
fn validate_bgp_identifier(bgp_identifier: u32) -> Result<(), ParserError> {
    if !is_valid_unicast_ipv4(bgp_identifier) {
        return Err(ParserError::BgpError {
            error: BgpError::OpenMessageError(OpenMessageError::BadBgpIdentifier),
            data: Vec::new(),
        });
    }
    Ok(())
}

impl OpenMessage {
    /// Creates a new OpenMessage with the specified parameters
    ///
    /// # Arguments
    /// * `asn` - Autonomous System Number
    /// * `hold_time` - Hold time in seconds
    /// * `bgp_identifier` - BGP identifier (usually an IPv4 address as u32)
    ///
    /// # Returns
    /// A new OpenMessage with version 4 and no optional parameters
    pub fn new(asn: u16, hold_time: u16, bgp_identifier: u32) -> Self {
        OpenMessage {
            version: BGP_VERSION,
            asn,
            hold_time,
            bgp_identifier,
            optional_params_len: 0,
            optional_params: vec![],
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ParserError> {
        if bytes.len() < 10 {
            // Malformed OPEN message - use Unspecific subcode (0)
            return Err(ParserError::BgpError {
                error: BgpError::OpenMessageError(OpenMessageError::Unknown(0)),
                data: Vec::new(),
            });
        }

        let version = bytes[0];
        let asn = u16::from_be_bytes([bytes[1], bytes[2]]);
        let hold_time = u16::from_be_bytes([bytes[3], bytes[4]]);
        let bgp_identifier = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);

        let optional_params_len = bytes[9];
        let remaining_bytes_len = (bytes.len() - 10) as u8;
        if optional_params_len != remaining_bytes_len {
            // Malformed optional parameters - use Unspecific subcode (0)
            return Err(ParserError::BgpError {
                error: BgpError::OpenMessageError(OpenMessageError::Unknown(0)),
                data: Vec::new(),
            });
        }

        // RFC 4271 Section 6.2: Validate OPEN message fields
        validate_version(version)?;
        validate_hold_time(hold_time)?;
        validate_bgp_identifier(bgp_identifier)?;

        let optional_params = match optional_params_len {
            0 => {
                vec![]
            }
            _ => read_optional_parameters(bytes[10..10 + optional_params_len as usize].to_vec()),
        };

        Ok(OpenMessage {
            version,
            asn,
            hold_time,
            bgp_identifier,
            optional_params_len,
            optional_params,
        })
    }
}

impl Message for OpenMessage {
    fn kind(&self) -> MessageType {
        MessageType::OPEN
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Version
        bytes.push(self.version);

        // ASN
        bytes.extend_from_slice(&self.asn.to_be_bytes());

        // Hold time
        bytes.extend_from_slice(&self.hold_time.to_be_bytes());

        // BGP identifier
        bytes.extend_from_slice(&self.bgp_identifier.to_be_bytes());

        // Optional parameters length
        bytes.push(self.optional_params_len);

        // Optional parameters (if any)
        for param in &self.optional_params {
            bytes.extend_from_slice(&param.to_bytes());
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC2858
    const CAPABILITY_MP_EXTENSION_PARAM: &[u8] = &[
        0x02, // OptionalParam type
        0x06, // OptionalParam length
        0x01, // Capability code
        0x04, // Capability length
        // Capability value
        0x00, 0x01, // AFI
        0x00, // Reserved
        0x01, // SAFI
    ];
    const CAPABILITY_UNASSIGNED_PARAM: &[u8] = &[
        0x02, // OptionalParam type
        0x0e, // OptionalParam length
        10,   // Capability code (Unassigned)
        0x05, // Capability length
        0x01, 0x02, 0x03, 0x04, 0x05, // Capability value
    ];
    const UNKNOWN_TYPE_PARAM: &[u8] = &[
        200,  // OptionalParam type (Unassigned)
        0x07, // OptionalParam length
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // Capability value
    ];

    #[test]
    fn test_from_bytes() {
        let message: &[u8] = &[
            0x04, // Version
            0x04, 0xd2, // ASN
            0x00, 0x0a, // Hold time
            0x0a, 0x0a, 0x0a, 0x0a, // BGP identififer
            0x00, // Optional parameters length
        ];

        let open_message = OpenMessage::from_bytes(message.to_vec()).unwrap();
        assert_eq!(open_message.version, BGP_VERSION);
        assert_eq!(open_message.asn, 1234);
        assert_eq!(open_message.hold_time, 10);
        assert_eq!(open_message.bgp_identifier, 168430090);
        assert_eq!(open_message.optional_params_len, 0);
    }

    #[test]
    fn test_from_bytes_with_optional_param() {
        let message: Vec<u8> = [
            &[
                0x04, // Version
                0x04, 0xd2, // ASN
                0x00, 0x0a, // Hold time
                0x0a, 0x0a, 0x0a, 0x0a, // BGP identififer
                0x08, // Optional parameters length
            ],
            CAPABILITY_MP_EXTENSION_PARAM,
        ]
        .concat();

        let open_message = OpenMessage::from_bytes(message.to_vec()).unwrap();
        assert_eq!(open_message.version, BGP_VERSION);
        assert_eq!(open_message.asn, 1234);
        assert_eq!(open_message.hold_time, 10);
        assert_eq!(open_message.bgp_identifier, 168430090);
        assert_eq!(open_message.optional_params_len, 8);
        assert_eq!(
            open_message.optional_params,
            vec![OptionalParam {
                param_type: OptionalParamTypes::Capabilities,
                param_len: 6,
                param_value: ParamVal::Capability(Capability {
                    code: BgpCapabiltyCode::Multiprotocol,
                    len: 4,
                    val: vec![0x00, 0x01, 0x00, 0x01],
                }),
            }]
        );
    }

    #[test]
    fn test_from_bytes_with_unknown_optional_param() {
        let message: Vec<u8> = [
            &[
                0x04, // Version
                0x04, 0xd2, // ASN
                0x00, 0x0a, // Hold time
                0x0a, 0x0a, 0x0a, 0x0a, // BGP identififer
                9,    // Optional parameters length
            ],
            UNKNOWN_TYPE_PARAM,
        ]
        .concat();

        let open_message = OpenMessage::from_bytes(message.to_vec()).unwrap();
        assert_eq!(open_message.version, BGP_VERSION);
        assert_eq!(open_message.asn, 1234);
        assert_eq!(open_message.hold_time, 10);
        assert_eq!(open_message.bgp_identifier, 168430090);
        assert_eq!(open_message.optional_params_len, 9);
        assert_eq!(
            open_message.optional_params,
            vec![OptionalParam {
                param_type: OptionalParamTypes::Unknown(200),
                param_len: 7,
                // Read the raw bytes for the optional param with an unknown type.
                param_value: ParamVal::Unknown(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,]),
            },]
        );
    }

    #[test]
    fn test_from_bytes_with_optional_params() {
        let message: Vec<u8> = [
            &[
                0x04, // Version
                0x27, 0x0f, // ASN
                0x00, 0x10, // Hold time
                0x0a, 0x0a, 0x0a, 0x0a, // BGP identififer
                26,   // Optional parameters length
            ],
            CAPABILITY_MP_EXTENSION_PARAM,
            UNKNOWN_TYPE_PARAM,
            CAPABILITY_UNASSIGNED_PARAM,
        ]
        .concat();

        let open_message = OpenMessage::from_bytes(message.to_vec()).unwrap();
        assert_eq!(open_message.version, BGP_VERSION);
        assert_eq!(open_message.asn, 9999);
        assert_eq!(open_message.hold_time, 16);
        assert_eq!(open_message.bgp_identifier, 168430090);
        assert_eq!(open_message.optional_params_len, 26);
        assert_eq!(
            open_message.optional_params,
            vec![
                OptionalParam {
                    param_type: OptionalParamTypes::Capabilities,
                    param_len: 6,
                    param_value: ParamVal::Capability(Capability {
                        code: BgpCapabiltyCode::Multiprotocol,
                        len: 4,
                        val: vec![0x00, 0x01, 0x00, 0x01],
                    }),
                },
                OptionalParam {
                    param_type: OptionalParamTypes::Unknown(200),
                    param_len: 7,
                    param_value: ParamVal::Unknown(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,]),
                },
                OptionalParam {
                    param_type: OptionalParamTypes::Capabilities,
                    param_len: 14,
                    param_value: ParamVal::Capability(Capability {
                        code: BgpCapabiltyCode::Unknown,
                        len: 5,
                        val: vec![0x01, 0x02, 0x03, 0x04, 0x05],
                    }),
                },
            ]
        );
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let message: &[u8] = &[
            0x04, 0x04, 0xd2, // ASN
            0x00, 0x0a, // Hold time
        ];

        match OpenMessage::from_bytes(message.to_vec()) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::OpenMessageError(OpenMessageError::Unknown(0))
                );
                assert_eq!(data, Vec::<u8>::new());
            }
            _ => panic!("Expected OPEN message error"),
        }
    }

    #[test]
    fn test_from_bytes_invalid_optional_params_length() {
        let test_cases: Vec<Vec<u8>> = vec![
            vec![
                0x04, // Version
                0x04, 0xd2, // ASN
                0x00, 0x0a, // Hold time
                0x0a, 0x0a, 0x0a, 0x0a, // BGP identififer
                0x08, // Optional parameters length
            ],
            vec![
                0x04, // Version
                0x04, 0xd2, // ASN
                0x00, 0x0a, // Hold time
                0x0a, 0x0a, 0x0a, 0x0a, // BGP identififer
                0x02, // Optional parameters length
                // Optional parameter
                100, 0x02, 0x01, 0x02,
            ],
            vec![
                0x04, // Version
                0x04, 0xd2, // ASN
                0x00, 0x0a, // Hold time
                0x0a, 0x0a, 0x0a, 0x0a, // BGP identififer
                0x06, // Optional parameters length
                // Optional parameter
                100, 0x02, 0x01, 0x02,
            ],
        ];

        for test_case in test_cases.iter() {
            match OpenMessage::from_bytes(test_case.to_vec()) {
                Err(ParserError::BgpError { error, data }) => {
                    assert_eq!(
                        error,
                        BgpError::OpenMessageError(OpenMessageError::Unknown(0))
                    );
                    assert_eq!(data, Vec::<u8>::new());
                }
                _ => panic!("Expected OPEN message error"),
            }
        }
    }

    #[test]
    fn test_read_optional_parameters_single() {
        let data: Vec<u8> = CAPABILITY_MP_EXTENSION_PARAM.to_vec();

        let result = read_optional_parameters(data);
        let expected = vec![OptionalParam {
            param_type: OptionalParamTypes::Capabilities,
            param_len: 6,
            param_value: ParamVal::Capability(Capability {
                code: BgpCapabiltyCode::Multiprotocol,
                len: 4,
                val: vec![0x00, 0x01, 0x00, 0x01],
            }),
        }];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_read_optional_parameters_multiple() {
        let data: Vec<u8> = [CAPABILITY_MP_EXTENSION_PARAM, CAPABILITY_UNASSIGNED_PARAM].concat();

        let result = read_optional_parameters(data);
        let expected = vec![
            OptionalParam {
                param_type: OptionalParamTypes::Capabilities,
                param_len: 6,
                param_value: ParamVal::Capability(Capability {
                    code: BgpCapabiltyCode::Multiprotocol,
                    len: 4,
                    val: vec![0x00, 0x01, 0x00, 0x01],
                }),
            },
            OptionalParam {
                param_type: OptionalParamTypes::Capabilities,
                param_len: 14,
                param_value: ParamVal::Capability(Capability {
                    code: BgpCapabiltyCode::Unknown,
                    len: 5,
                    val: vec![0x01, 0x02, 0x03, 0x04, 0x05],
                }),
            },
        ];

        assert_eq!(result, expected);
    }

    const TEST_OPEN_MESSAGE_BODY: &[u8] = &[
        0x04, // Version
        0xfd, 0xe9, // ASN: 65001
        0x00, 0xb4, // Hold time: 180
        0x01, 0x01, 0x01, 0x01, // BGP ID: 0x01010101
        0x00, // Optional params len
    ];

    #[test]
    fn test_open_message_encode_decode() {
        // Create an OpenMessage using new()
        let open_msg = OpenMessage::new(65001, 180, 0x01010101);

        // Encode to bytes
        let bytes = open_msg.to_bytes();

        assert_eq!(bytes, TEST_OPEN_MESSAGE_BODY);

        // Decode: parse the bytes back
        let parsed = OpenMessage::from_bytes(bytes).unwrap();
        assert_eq!(parsed.version, BGP_VERSION);
        assert_eq!(parsed.asn, 65001);
        assert_eq!(parsed.hold_time, 180);
        assert_eq!(parsed.bgp_identifier, 0x01010101);
        assert_eq!(parsed.optional_params_len, 0);
    }

    #[test]
    fn test_open_message_serialize() {
        // Create an OpenMessage using new()
        let open_msg = OpenMessage::new(65001, 180, 0x01010101);

        // Serialize to complete BGP message with header
        let message = open_msg.serialize();

        // Expected complete message: header + body
        let mut expected = Vec::new();
        // BGP header marker (16 bytes of 0xFF)
        expected.extend_from_slice(&[0xff; 16]);
        // Message length (19 byte header + body length)
        let total_length = 19u16 + TEST_OPEN_MESSAGE_BODY.len() as u16;
        expected.extend_from_slice(&total_length.to_be_bytes());
        // Message type (OPEN = 1)
        expected.push(0x01);
        // Message body
        expected.extend_from_slice(TEST_OPEN_MESSAGE_BODY);

        assert_eq!(message, expected);
        assert_eq!(message.len(), 19 + TEST_OPEN_MESSAGE_BODY.len());
    }

    #[test]
    fn test_from_bytes_unsupported_version() {
        let mut msg = TEST_OPEN_MESSAGE_BODY.to_vec();
        msg[0] = 0x03; // Version 3 (unsupported)

        match OpenMessage::from_bytes(msg) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber)
                );
                assert_eq!(data, vec![0x00, 0x04]); // Largest supported version
            }
            _ => panic!("Expected UnsupportedVersionNumber error"),
        }
    }

    #[test]
    fn test_from_bytes_unacceptable_hold_time() {
        let test_cases = vec![1, 2];

        for hold_time in test_cases {
            let mut msg = TEST_OPEN_MESSAGE_BODY.to_vec();
            msg[3] = 0x00;
            msg[4] = hold_time;

            match OpenMessage::from_bytes(msg) {
                Err(ParserError::BgpError { error, data }) => {
                    assert_eq!(
                        error,
                        BgpError::OpenMessageError(OpenMessageError::UnacceptedHoldTime),
                        "Failed for hold_time={}",
                        hold_time
                    );
                    assert_eq!(data, Vec::<u8>::new(), "Failed for hold_time={}", hold_time);
                }
                _ => panic!(
                    "Expected UnacceptedHoldTime error for hold_time={}",
                    hold_time
                ),
            }
        }
    }

    #[test]
    fn test_from_bytes_bad_bgp_identifier() {
        let test_cases = vec![
            ("zero", [0x00, 0x00, 0x00, 0x00]),      // 0.0.0.0
            ("broadcast", [0xff, 0xff, 0xff, 0xff]), // 255.255.255.255
            ("multicast", [0xe0, 0x00, 0x00, 0x01]), // 224.0.0.1
        ];

        for (name, bgp_id) in test_cases {
            let mut msg = TEST_OPEN_MESSAGE_BODY.to_vec();
            msg[5] = bgp_id[0];
            msg[6] = bgp_id[1];
            msg[7] = bgp_id[2];
            msg[8] = bgp_id[3];

            match OpenMessage::from_bytes(msg) {
                Err(ParserError::BgpError { error, data }) => {
                    assert_eq!(
                        error,
                        BgpError::OpenMessageError(OpenMessageError::BadBgpIdentifier),
                        "Failed for case: {}",
                        name
                    );
                    assert_eq!(data, Vec::<u8>::new(), "Failed for case: {}", name);
                }
                _ => panic!("Expected BadBgpIdentifier error for case: {}", name),
            }
        }
    }
}
