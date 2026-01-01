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
use super::types::InformationTlv;

#[derive(Clone, Debug)]
pub struct InitiationMessage {
    pub information: Vec<InformationTlv>,
}

impl InitiationMessage {
    pub fn new(information: Vec<InformationTlv>) -> Self {
        Self { information }
    }
}

impl Message for InitiationMessage {
    fn message_type(&self) -> MessageType {
        MessageType::Initiation
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for tlv in &self.information {
            bytes.extend_from_slice(&tlv.to_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initiation_message_serialize() {
        let tlvs = vec![
            InformationTlv::new_string(InformationTlv::SYS_NAME, "bgpgg".to_string()),
            InformationTlv::new_string(InformationTlv::SYS_DESCR, "bgpgg router".to_string()),
        ];
        let msg = InitiationMessage::new(tlvs);
        let serialized = msg.serialize();

        // Version
        assert_eq!(serialized[0], 3);
        // Type
        assert_eq!(serialized[5], MessageType::Initiation.as_u8());
    }
}
