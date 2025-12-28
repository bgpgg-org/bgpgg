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

pub(crate) const BGP_VERSION: u8 = 4;

#[derive(Debug, PartialEq)]
pub(crate) enum BgpCapabiltyCode {
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

impl BgpCapabiltyCode {
    pub(crate) fn as_u8(&self) -> u8 {
        match self {
            BgpCapabiltyCode::Multiprotocol => 1,
            BgpCapabiltyCode::RouteRefresh => 2,
            BgpCapabiltyCode::Unknown => 0,
        }
    }
}

// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11
#[derive(Debug, PartialEq)]
#[repr(u8)]
pub(crate) enum OptionalParamTypes {
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

impl OptionalParamTypes {
    pub(crate) fn as_u8(&self) -> u8 {
        match self {
            OptionalParamTypes::Capabilities => 2,
            OptionalParamTypes::Unknown(val) => *val,
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum ParamVal {
    Capability(Capability),
    Unknown(Vec<u8>),
}

impl ParamVal {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        match self {
            ParamVal::Capability(cap) => cap.to_bytes(),
            ParamVal::Unknown(data) => data.clone(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct Capability {
    pub(crate) code: BgpCapabiltyCode,
    pub(crate) len: u8,
    pub(crate) val: Vec<u8>,
}

impl Capability {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.code.as_u8());
        bytes.push(self.len);
        bytes.extend_from_slice(&self.val);
        bytes
    }
}

#[derive(Debug, PartialEq)]
pub struct OptionalParam {
    pub(crate) param_type: OptionalParamTypes,
    pub(crate) param_len: u8,
    pub(crate) param_value: ParamVal,
}

impl OptionalParam {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.param_type.as_u8());
        bytes.push(self.param_len);
        bytes.extend_from_slice(&self.param_value.to_bytes());
        bytes
    }
}
