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
use super::msg_initiation::InformationTlv;

#[derive(Clone, Debug)]
pub struct TerminationMessage {
    pub information: Vec<InformationTlv>,
}

impl TerminationMessage {
    pub fn new(information: Vec<InformationTlv>) -> Self {
        Self { information }
    }

    pub const REASON_ADMIN_CLOSE: u16 = 0;
    pub const REASON_UNSPECIFIED: u16 = 1;
    pub const REASON_OUT_OF_RESOURCES: u16 = 2;
    pub const REASON_REDUNDANT_CONNECTION: u16 = 3;
    pub const REASON_PERMANENTLY_ADMIN_CLOSE: u16 = 4;

    pub fn new_with_reason(reason: u16) -> Self {
        let tlv = InformationTlv {
            info_type: reason,
            info_value: Vec::new(),
        };
        Self {
            information: vec![tlv],
        }
    }
}

impl Message for TerminationMessage {
    fn message_type(&self) -> MessageType {
        MessageType::Termination
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for tlv in &self.information {
            bytes.extend_from_slice(&tlv.to_bytes());
        }
        bytes
    }
}
