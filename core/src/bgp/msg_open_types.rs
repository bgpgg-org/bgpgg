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

/// Graceful Restart capability tuple: (restart_time, restart_state, afi_safi_forwarding_list)
type GrCapabilityInfo = (u16, bool, Vec<(crate::bgp::multiprotocol::AfiSafi, bool)>);

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum BgpCapabiltyCode {
    Multiprotocol = 1,
    RouteRefresh = 2,
    GracefulRestart = 64,
    FourOctetAsn = 65,
    Unknown,
}

impl From<u8> for BgpCapabiltyCode {
    fn from(value: u8) -> Self {
        match value {
            1 => BgpCapabiltyCode::Multiprotocol,
            2 => BgpCapabiltyCode::RouteRefresh,
            64 => BgpCapabiltyCode::GracefulRestart,
            65 => BgpCapabiltyCode::FourOctetAsn,
            _ => BgpCapabiltyCode::Unknown,
        }
    }
}

impl BgpCapabiltyCode {
    pub(crate) fn as_u8(&self) -> u8 {
        match self {
            BgpCapabiltyCode::Multiprotocol => 1,
            BgpCapabiltyCode::RouteRefresh => 2,
            BgpCapabiltyCode::GracefulRestart => 64,
            BgpCapabiltyCode::FourOctetAsn => 65,
            BgpCapabiltyCode::Unknown => 0,
        }
    }
}

// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11
#[derive(Debug, PartialEq, Clone)]
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

#[derive(Debug, PartialEq, Clone)]
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

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Capability {
    pub(crate) code: BgpCapabiltyCode,
    pub(crate) len: u8,
    pub(crate) val: Vec<u8>,
}

/// Convert AfiSafi to capability bytes
/// Format: [AFI_HIGH, AFI_LOW, RESERVED, SAFI]
pub(crate) fn afi_safi_to_capability_bytes(
    afi_safi: &crate::bgp::multiprotocol::AfiSafi,
) -> Vec<u8> {
    let afi_bytes = (afi_safi.afi as u16).to_be_bytes();
    vec![afi_bytes[0], afi_bytes[1], 0x00, afi_safi.safi as u8]
}

impl Capability {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.code.as_u8());
        bytes.push(self.len);
        bytes.extend_from_slice(&self.val);
        bytes
    }

    /// Create a Route Refresh capability (RFC 2918)
    pub(crate) fn new_route_refresh() -> Self {
        Capability {
            code: BgpCapabiltyCode::RouteRefresh,
            len: 0,
            val: vec![],
        }
    }

    /// Create a Multiprotocol capability (RFC 4760)
    pub(crate) fn new_multiprotocol(afi_safi: &crate::bgp::multiprotocol::AfiSafi) -> Self {
        let val = afi_safi_to_capability_bytes(afi_safi);

        Capability {
            code: BgpCapabiltyCode::Multiprotocol,
            len: val.len() as u8,
            val,
        }
    }

    /// Create a Four-Octet ASN capability (RFC 6793)
    pub(crate) fn new_four_octet_asn(asn: u32) -> Self {
        Capability {
            code: BgpCapabiltyCode::FourOctetAsn,
            len: 4,
            val: asn.to_be_bytes().to_vec(),
        }
    }

    /// Extract the four-octet ASN value if this is a FourOctetAsn capability
    pub(crate) fn as_four_octet_asn(&self) -> Option<u32> {
        if matches!(self.code, BgpCapabiltyCode::FourOctetAsn) && self.val.len() == 4 {
            Some(u32::from_be_bytes([
                self.val[0],
                self.val[1],
                self.val[2],
                self.val[3],
            ]))
        } else {
            None
        }
    }

    /// Create a Graceful Restart capability (RFC 4724)
    /// restart_time: seconds (12 bits, max 4095)
    /// restart_state: R bit - if true, indicates router is restarting
    /// afi_safi_list: list of (AfiSafi, forwarding_state) tuples
    ///   forwarding_state: F bit - if true, forwarding state preserved
    pub(crate) fn new_graceful_restart(
        restart_time: u16,
        restart_state: bool,
        afi_safi_list: Vec<(crate::bgp::multiprotocol::AfiSafi, bool)>,
    ) -> Self {
        let mut val = Vec::new();

        // First 2 bytes: Restart Flags (4 bits) + Restart Time (12 bits)
        // R bit is bit 0 (MSB of first byte)
        let restart_flags = if restart_state { 0x80 } else { 0x00 };
        let restart_time_masked = restart_time & 0x0FFF; // 12 bits max
        let first_byte = restart_flags | ((restart_time_masked >> 8) as u8);
        let second_byte = (restart_time_masked & 0xFF) as u8;
        val.push(first_byte);
        val.push(second_byte);

        // Foreach AFI/SAFI: [AFI(2), SAFI(1), Flags(1)]
        for (afi_safi, forwarding_state) in afi_safi_list {
            let afi_bytes = (afi_safi.afi as u16).to_be_bytes();
            val.push(afi_bytes[0]);
            val.push(afi_bytes[1]);
            val.push(afi_safi.safi as u8);
            // F bit is bit 0 (MSB of flags byte)
            let flags = if forwarding_state { 0x80 } else { 0x00 };
            val.push(flags);
        }

        Capability {
            code: BgpCapabiltyCode::GracefulRestart,
            len: val.len() as u8,
            val,
        }
    }

    /// Extract Graceful Restart capability info if this is a GracefulRestart capability
    /// Returns (restart_time, restart_state, afi_safi_forwarding_list)
    pub(crate) fn as_graceful_restart(&self) -> Option<GrCapabilityInfo> {
        use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};

        if !matches!(self.code, BgpCapabiltyCode::GracefulRestart) || self.val.len() < 2 {
            return None;
        }

        // Parse restart flags and time (first 2 bytes)
        let first_byte = self.val[0];
        let second_byte = self.val[1];

        let restart_state = (first_byte & 0x80) != 0; // R bit
        let restart_time = (((first_byte & 0x0F) as u16) << 8) | (second_byte as u16);

        // Parse AFI/SAFI tuples (4 bytes each)
        let mut afi_safi_list = Vec::new();
        let mut offset = 2;
        while offset + 4 <= self.val.len() {
            let afi_bytes = [self.val[offset], self.val[offset + 1]];
            let afi_val = u16::from_be_bytes(afi_bytes);
            let safi_val = self.val[offset + 2];
            let flags = self.val[offset + 3];

            // Try to parse AFI/SAFI, skip if unknown
            if let (Ok(afi), Ok(safi)) = (Afi::try_from(afi_val), Safi::try_from(safi_val)) {
                let forwarding_state = (flags & 0x80) != 0; // F bit
                afi_safi_list.push((AfiSafi::new(afi, safi), forwarding_state));
            }

            offset += 4;
        }

        Some((restart_time, restart_state, afi_safi_list))
    }
}

#[derive(Debug, PartialEq, Clone)]
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

    /// Create an OptionalParam from a Capability
    pub(crate) fn new_capability(capability: Capability) -> Self {
        OptionalParam {
            param_type: OptionalParamTypes::Capabilities,
            param_len: 2 + capability.len, // code(1) + len(1) + val
            param_value: ParamVal::Capability(capability),
        }
    }

    /// Find and extract the four-octet ASN capability from a list of optional parameters
    pub(crate) fn find_four_octet_asn(params: &[OptionalParam]) -> Option<u32> {
        params.iter().find_map(|param| {
            if let ParamVal::Capability(cap) = &param.param_value {
                cap.as_four_octet_asn()
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};

    #[test]
    fn test_afi_safi_to_capability_bytes() {
        let cases = vec![
            (
                AfiSafi::new(Afi::Ipv4, Safi::Unicast),
                vec![0x00, 0x01, 0x00, 0x01],
            ),
            (
                AfiSafi::new(Afi::Ipv6, Safi::Unicast),
                vec![0x00, 0x02, 0x00, 0x01],
            ),
            (
                AfiSafi::new(Afi::Ipv4, Safi::Multicast),
                vec![0x00, 0x01, 0x00, 0x02],
            ),
        ];

        for (afi_safi, expected_bytes) in cases {
            let bytes = afi_safi_to_capability_bytes(&afi_safi);
            assert_eq!(bytes, expected_bytes, "{:?}", afi_safi);
        }
    }

    #[test]
    fn test_find_four_octet_asn() {
        // Test with four-octet ASN capability
        let cap = Capability::new_four_octet_asn(65536);
        let param = OptionalParam::new_capability(cap);
        assert_eq!(OptionalParam::find_four_octet_asn(&[param]), Some(65536));

        // Test with multiple capabilities including four-octet ASN
        let cap1 = Capability::new_route_refresh();
        let cap2 = Capability::new_four_octet_asn(4200000000);
        let cap3 = Capability::new_multiprotocol(&AfiSafi::new(Afi::Ipv4, Safi::Unicast));
        let params = vec![
            OptionalParam::new_capability(cap1),
            OptionalParam::new_capability(cap2),
            OptionalParam::new_capability(cap3),
        ];
        assert_eq!(
            OptionalParam::find_four_octet_asn(&params),
            Some(4200000000)
        );

        // Test without four-octet ASN capability
        let cap = Capability::new_route_refresh();
        let param = OptionalParam::new_capability(cap);
        assert_eq!(OptionalParam::find_four_octet_asn(&[param]), None);

        // Test with empty list
        assert_eq!(OptionalParam::find_four_octet_asn(&[]), None);
    }
}
