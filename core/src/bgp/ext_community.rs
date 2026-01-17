use std::net::Ipv4Addr;

// RFC 4360: BGP Extended Communities Attribute
// Extended community = 8 bytes
// Format: [Type (1 byte)][Subtype (1 byte)][Value (6 bytes)]

// Type field constants (high-order octet)
pub const TYPE_TWO_OCTET_AS: u8 = 0x00;
pub const TYPE_IPV4_ADDRESS: u8 = 0x01;
pub const TYPE_FOUR_OCTET_AS: u8 = 0x02;
pub const TYPE_OPAQUE: u8 = 0x03;
pub const TYPE_EVPN: u8 = 0x06;

// Subtype constants for Route Target / Route Origin
pub const SUBTYPE_ROUTE_TARGET: u8 = 0x02;
pub const SUBTYPE_ROUTE_ORIGIN: u8 = 0x03;
pub const SUBTYPE_LINK_BANDWIDTH: u8 = 0x04;

// Subtype constants for Opaque extended communities
pub const SUBTYPE_COLOR: u8 = 0x0B;
pub const SUBTYPE_ENCAPSULATION: u8 = 0x0C;

// Subtype constants for EVPN extended communities
pub const SUBTYPE_ROUTER_MAC: u8 = 0x03;

// Bit 6 of type indicates transitive (0) or non-transitive (1)
pub const TYPE_NON_TRANSITIVE_BIT: u8 = 0x40;

/// Calculate bit shift for extracting byte N from big-endian u64 (0 = leftmost/MSB)
const fn byte_shift(byte_index: u8) -> u8 {
    (7 - byte_index) * 8
}

/// Extract the type field from an extended community
pub const fn ext_type(extcomm: u64) -> u8 {
    (extcomm >> byte_shift(0)) as u8
}

/// Extract the subtype field from an extended community
pub const fn ext_subtype(extcomm: u64) -> u8 {
    (extcomm >> byte_shift(1)) as u8
}

/// Extract the 6-byte value field from an extended community
pub const fn ext_value(extcomm: u64) -> [u8; 6] {
    [
        (extcomm >> byte_shift(2)) as u8,
        (extcomm >> byte_shift(3)) as u8,
        (extcomm >> byte_shift(4)) as u8,
        (extcomm >> byte_shift(5)) as u8,
        (extcomm >> byte_shift(6)) as u8,
        (extcomm >> byte_shift(7)) as u8,
    ]
}

/// Check if an extended community is transitive across AS boundaries (RFC 4360 Section 2)
/// Returns true if the community should be propagated across eBGP sessions
pub const fn is_transitive(extcomm: u64) -> bool {
    let typ = ext_type(extcomm);
    (typ & TYPE_NON_TRANSITIVE_BIT) == 0
}

/// Create an extended community from two-octet AS format
/// Type 0x00: [Type][Subtype][AS (2 bytes)][Local (4 bytes)]
pub const fn from_two_octet_as(subtype: u8, asn: u16, local: u32) -> u64 {
    ((TYPE_TWO_OCTET_AS as u64) << byte_shift(0))
        | ((subtype as u64) << byte_shift(1))
        | ((asn as u64) << byte_shift(3))
        | (local as u64)
}

/// Create an extended community from IPv4 format
/// Type 0x01: [Type][Subtype][IPv4 (4 bytes)][Local (2 bytes)]
pub const fn from_ipv4(subtype: u8, ip: u32, local: u16) -> u64 {
    ((TYPE_IPV4_ADDRESS as u64) << byte_shift(0))
        | ((subtype as u64) << byte_shift(1))
        | ((ip as u64) << byte_shift(5))
        | (local as u64)
}

/// Create an extended community from four-octet AS format
/// Type 0x02: [Type][Subtype][AS (4 bytes)][Local (2 bytes)]
pub const fn from_four_octet_as(subtype: u8, asn: u32, local: u16) -> u64 {
    ((TYPE_FOUR_OCTET_AS as u64) << byte_shift(0))
        | ((subtype as u64) << byte_shift(1))
        | ((asn as u64) << byte_shift(5))
        | (local as u64)
}

/// Create a Color extended community (RFC 9012)
/// Type 0x03: [Type][Subtype][Reserved (2 bytes)][Color (4 bytes)]
pub const fn from_color(color: u32) -> u64 {
    ((TYPE_OPAQUE as u64) << byte_shift(0))
        | ((SUBTYPE_COLOR as u64) << byte_shift(1))
        | (color as u64)
}

/// Create an Encapsulation extended community (RFC 9012)
/// Type 0x03: [Type][Subtype][Reserved (2 bytes)][Tunnel Type (2 bytes)]
pub const fn from_encapsulation(tunnel_type: u16) -> u64 {
    ((TYPE_OPAQUE as u64) << byte_shift(0))
        | ((SUBTYPE_ENCAPSULATION as u64) << byte_shift(1))
        | (tunnel_type as u64)
}

/// Create a Router's MAC extended community (RFC 9012, EVPN)
/// Type 0x06: [Type][Subtype][MAC address (6 bytes)]
pub const fn from_router_mac(mac: [u8; 6]) -> u64 {
    ((TYPE_EVPN as u64) << byte_shift(0))
        | ((SUBTYPE_ROUTER_MAC as u64) << byte_shift(1))
        | ((mac[0] as u64) << byte_shift(2))
        | ((mac[1] as u64) << byte_shift(3))
        | ((mac[2] as u64) << byte_shift(4))
        | ((mac[3] as u64) << byte_shift(5))
        | ((mac[4] as u64) << byte_shift(6))
        | ((mac[5] as u64) << byte_shift(7))
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseExtCommunityError {
    InvalidFormat,
    InvalidPrefix,
    InvalidAsn,
    InvalidIpv4,
    InvalidLocal,
    InvalidHex,
    InvalidMac,
}

/// Parse an extended community from a string
/// Supported formats:
/// - "rt:65000:100" (Route Target, two-octet AS)
/// - "rt:192.168.1.1:100" (Route Target, IPv4)
/// - "rt:4200000000:100" (Route Target, four-octet AS)
/// - "ro:65000:100" (Route Origin, two-octet AS)
/// - "ro:192.168.1.1:100" (Route Origin, IPv4)
/// - "ro:4200000000:100" (Route Origin, four-octet AS)
/// - "color:100" (Color community, RFC 9012)
/// - "encapsulation:8" (Encapsulation community, RFC 9012)
/// - "router-mac:aa:bb:cc:dd:ee:ff" (Router's MAC community, RFC 9012)
/// - "0x0002FDE800000064" (raw hex, 16 hex digits)
pub fn parse_extended_community(s: &str) -> Result<u64, ParseExtCommunityError> {
    // Handle raw hex format
    if let Some(hex_str) = s.strip_prefix("0x") {
        return u64::from_str_radix(hex_str, 16).map_err(|_| ParseExtCommunityError::InvalidHex);
    }

    // Parse colon-separated format
    let parts: Vec<&str> = s.split(':').collect();

    // Handle color:VALUE format (2 parts)
    if parts.len() == 2 && parts[0] == "color" {
        let color: u32 = parts[1]
            .parse()
            .map_err(|_| ParseExtCommunityError::InvalidLocal)?;
        return Ok(from_color(color));
    }

    // Handle encapsulation:TYPE format (2 parts)
    if parts.len() == 2 && parts[0] == "encapsulation" {
        let tunnel_type: u16 = parts[1]
            .parse()
            .map_err(|_| ParseExtCommunityError::InvalidLocal)?;
        return Ok(from_encapsulation(tunnel_type));
    }

    // Handle router-mac:aa:bb:cc:dd:ee:ff format (7 parts)
    if parts.len() == 7 && parts[0] == "router-mac" {
        let mut mac = [0u8; 6];
        for (i, part) in parts[1..7].iter().enumerate() {
            mac[i] =
                u8::from_str_radix(part, 16).map_err(|_| ParseExtCommunityError::InvalidMac)?;
        }
        return Ok(from_router_mac(mac));
    }

    // Parse prefix:value:local format (3 parts)
    if parts.len() != 3 {
        return Err(ParseExtCommunityError::InvalidFormat);
    }

    let prefix = parts[0];
    let value_str = parts[1];
    let local_str = parts[2];

    // Determine subtype from prefix
    let subtype = match prefix {
        "rt" => SUBTYPE_ROUTE_TARGET,
        "ro" => SUBTYPE_ROUTE_ORIGIN,
        _ => return Err(ParseExtCommunityError::InvalidPrefix),
    };

    // Try to parse as IPv4 first (check for dots)
    if value_str.contains('.') {
        let ip: Ipv4Addr = value_str
            .parse()
            .map_err(|_| ParseExtCommunityError::InvalidIpv4)?;
        let local: u16 = local_str
            .parse()
            .map_err(|_| ParseExtCommunityError::InvalidLocal)?;
        return Ok(from_ipv4(subtype, u32::from(ip), local));
    }

    // Parse as ASN (either two-octet or four-octet)
    let asn: u32 = value_str
        .parse()
        .map_err(|_| ParseExtCommunityError::InvalidAsn)?;
    let local: u32 = local_str
        .parse()
        .map_err(|_| ParseExtCommunityError::InvalidLocal)?;

    // If ASN fits in 16 bits, use two-octet format
    if asn <= 65535 {
        Ok(from_two_octet_as(subtype, asn as u16, local))
    } else {
        // Local value must fit in 16 bits for four-octet AS format
        if local > 65535 {
            return Err(ParseExtCommunityError::InvalidLocal);
        }
        Ok(from_four_octet_as(subtype, asn, local as u16))
    }
}

/// Format an extended community as a human-readable string
pub fn format_extended_community(extcomm: u64) -> String {
    let typ = ext_type(extcomm);
    let subtype = ext_subtype(extcomm);
    let value_bytes = ext_value(extcomm);

    // Handle Opaque extended communities separately
    if typ == TYPE_OPAQUE {
        match subtype {
            SUBTYPE_COLOR => {
                // [Type][Subtype][Reserved (2 bytes)][Color (4 bytes)]
                let color = u32::from_be_bytes([
                    value_bytes[2],
                    value_bytes[3],
                    value_bytes[4],
                    value_bytes[5],
                ]);
                return format!("color:{}", color);
            }
            SUBTYPE_ENCAPSULATION => {
                // [Type][Subtype][Reserved (2 bytes)][Tunnel Type (2 bytes)]
                let tunnel_type = u16::from_be_bytes([value_bytes[4], value_bytes[5]]);
                return format!("encapsulation:{}", tunnel_type);
            }
            _ => {
                // Unknown opaque subtype, return raw hex
                return format!("0x{:016x}", extcomm);
            }
        }
    }

    // Handle EVPN extended communities
    if typ == TYPE_EVPN {
        match subtype {
            SUBTYPE_ROUTER_MAC => {
                // [Type][Subtype][MAC address (6 bytes)]
                return format!(
                    "router-mac:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    value_bytes[0],
                    value_bytes[1],
                    value_bytes[2],
                    value_bytes[3],
                    value_bytes[4],
                    value_bytes[5]
                );
            }
            _ => {
                // Unknown EVPN subtype, return raw hex
                return format!("0x{:016x}", extcomm);
            }
        }
    }

    // Determine prefix based on subtype for AS-specific types
    let prefix = match subtype {
        SUBTYPE_ROUTE_TARGET => "rt",
        SUBTYPE_ROUTE_ORIGIN => "ro",
        _ => {
            // Unknown subtype, return raw hex
            return format!("0x{:016x}", extcomm);
        }
    };

    match typ {
        TYPE_TWO_OCTET_AS => {
            // [Type][Subtype][AS (2 bytes)][Local (4 bytes)]
            let asn = u16::from_be_bytes([value_bytes[0], value_bytes[1]]);
            let local = u32::from_be_bytes([
                value_bytes[2],
                value_bytes[3],
                value_bytes[4],
                value_bytes[5],
            ]);
            format!("{}:{}:{}", prefix, asn, local)
        }
        TYPE_IPV4_ADDRESS => {
            // [Type][Subtype][IPv4 (4 bytes)][Local (2 bytes)]
            let ip = Ipv4Addr::new(
                value_bytes[0],
                value_bytes[1],
                value_bytes[2],
                value_bytes[3],
            );
            let local = u16::from_be_bytes([value_bytes[4], value_bytes[5]]);
            format!("{}:{}:{}", prefix, ip, local)
        }
        TYPE_FOUR_OCTET_AS => {
            // [Type][Subtype][AS (4 bytes)][Local (2 bytes)]
            let asn = u32::from_be_bytes([
                value_bytes[0],
                value_bytes[1],
                value_bytes[2],
                value_bytes[3],
            ]);
            let local = u16::from_be_bytes([value_bytes[4], value_bytes[5]]);
            format!("{}:{}:{}", prefix, asn, local)
        }
        _ => {
            // Unknown type, return raw hex
            format!("0x{:016x}", extcomm)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ext_type() {
        let extcomm = 0x0002FDE800000064u64; // Type=0x00, Subtype=0x02
        assert_eq!(ext_type(extcomm), 0x00);

        let extcomm2 = 0x0102C0A80101006Cu64; // Type=0x01
        assert_eq!(ext_type(extcomm2), 0x01);
    }

    #[test]
    fn test_ext_subtype() {
        let extcomm = 0x0002FDE800000064u64; // Type=0x00, Subtype=0x02
        assert_eq!(ext_subtype(extcomm), 0x02);

        let extcomm2 = 0x0003AAAABBBBCCCC_u64; // Subtype=0x03
        assert_eq!(ext_subtype(extcomm2), 0x03);
    }

    #[test]
    fn test_ext_value() {
        let extcomm = 0x0002FDE800000064u64;
        let value = ext_value(extcomm);
        assert_eq!(value, [0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]);
    }

    #[test]
    fn test_is_transitive() {
        // Transitive (bit 6 = 0)
        let transitive = 0x0002FDE800000064u64; // Type 0x00
        assert!(is_transitive(transitive));

        // Non-transitive (bit 6 = 1)
        let non_transitive = 0x4002FDE800000064u64; // Type 0x40
        assert!(!is_transitive(non_transitive));
    }

    #[test]
    fn test_from_two_octet_as() {
        let extcomm = from_two_octet_as(SUBTYPE_ROUTE_TARGET, 65000, 100);
        assert_eq!(extcomm, 0x0002FDE800000064u64);
        assert_eq!(ext_type(extcomm), TYPE_TWO_OCTET_AS);
        assert_eq!(ext_subtype(extcomm), SUBTYPE_ROUTE_TARGET);
    }

    #[test]
    fn test_from_ipv4() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let extcomm = from_ipv4(SUBTYPE_ROUTE_TARGET, u32::from(ip), 100);
        assert_eq!(extcomm, 0x0102C0A801010064u64);
        assert_eq!(ext_type(extcomm), TYPE_IPV4_ADDRESS);
        assert_eq!(ext_subtype(extcomm), SUBTYPE_ROUTE_TARGET);
    }

    #[test]
    fn test_from_four_octet_as() {
        let extcomm = from_four_octet_as(SUBTYPE_ROUTE_ORIGIN, 4200000000, 1);
        assert_eq!(extcomm, 0x0203FA56EA000001u64);
        assert_eq!(ext_type(extcomm), TYPE_FOUR_OCTET_AS);
        assert_eq!(ext_subtype(extcomm), SUBTYPE_ROUTE_ORIGIN);
    }

    #[test]
    fn test_parse_rt_two_octet_as() {
        let extcomm = parse_extended_community("rt:65000:100").unwrap();
        assert_eq!(extcomm, from_two_octet_as(SUBTYPE_ROUTE_TARGET, 65000, 100));
    }

    #[test]
    fn test_parse_rt_ipv4() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let extcomm = parse_extended_community("rt:192.168.1.1:100").unwrap();
        assert_eq!(extcomm, from_ipv4(SUBTYPE_ROUTE_TARGET, u32::from(ip), 100));
    }

    #[test]
    fn test_parse_rt_four_octet_as() {
        let extcomm = parse_extended_community("rt:4200000000:100").unwrap();
        assert_eq!(
            extcomm,
            from_four_octet_as(SUBTYPE_ROUTE_TARGET, 4200000000, 100)
        );
    }

    #[test]
    fn test_parse_ro_two_octet_as() {
        let extcomm = parse_extended_community("ro:65000:100").unwrap();
        assert_eq!(extcomm, from_two_octet_as(SUBTYPE_ROUTE_ORIGIN, 65000, 100));
    }

    #[test]
    fn test_parse_hex() {
        let extcomm = parse_extended_community("0x0002FDE800000064").unwrap();
        assert_eq!(extcomm, 0x0002FDE800000064u64);
    }

    #[test]
    fn test_parse_invalid_format() {
        assert_eq!(
            parse_extended_community("rt:65000"),
            Err(ParseExtCommunityError::InvalidFormat)
        );
        assert_eq!(
            parse_extended_community("invalid"),
            Err(ParseExtCommunityError::InvalidFormat)
        );
    }

    #[test]
    fn test_parse_invalid_prefix() {
        assert_eq!(
            parse_extended_community("xx:65000:100"),
            Err(ParseExtCommunityError::InvalidPrefix)
        );
    }

    #[test]
    fn test_parse_invalid_asn() {
        assert_eq!(
            parse_extended_community("rt:notanumber:100"),
            Err(ParseExtCommunityError::InvalidAsn)
        );
    }

    #[test]
    fn test_parse_invalid_ipv4() {
        assert_eq!(
            parse_extended_community("rt:999.999.999.999:100"),
            Err(ParseExtCommunityError::InvalidIpv4)
        );
    }

    #[test]
    fn test_format_two_octet_as_rt() {
        let extcomm = from_two_octet_as(SUBTYPE_ROUTE_TARGET, 65000, 100);
        assert_eq!(format_extended_community(extcomm), "rt:65000:100");
    }

    #[test]
    fn test_format_ipv4_rt() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let extcomm = from_ipv4(SUBTYPE_ROUTE_TARGET, u32::from(ip), 100);
        assert_eq!(format_extended_community(extcomm), "rt:192.168.1.1:100");
    }

    #[test]
    fn test_format_four_octet_as_ro() {
        let extcomm = from_four_octet_as(SUBTYPE_ROUTE_ORIGIN, 4200000000, 1);
        assert_eq!(format_extended_community(extcomm), "ro:4200000000:1");
    }

    #[test]
    fn test_format_unknown_subtype() {
        let extcomm = from_two_octet_as(0xFF, 65000, 100); // Unknown subtype
        assert_eq!(format_extended_community(extcomm), "0x00fffde800000064");
    }

    #[test]
    fn test_roundtrip_string_parsing() {
        let test_cases = vec![
            "rt:65000:100",
            "rt:192.168.1.1:100",
            "rt:4200000000:100",
            "ro:65000:200",
            "ro:10.0.0.1:50",
        ];

        for original in test_cases {
            let extcomm = parse_extended_community(original).unwrap();
            let formatted = format_extended_community(extcomm);
            assert_eq!(original, formatted);
        }
    }

    #[test]
    fn test_from_color() {
        let extcomm = from_color(100);
        assert_eq!(ext_type(extcomm), TYPE_OPAQUE);
        assert_eq!(ext_subtype(extcomm), SUBTYPE_COLOR);
        // Color should be in last 4 bytes
        let value = ext_value(extcomm);
        let color = u32::from_be_bytes([value[2], value[3], value[4], value[5]]);
        assert_eq!(color, 100);
        assert!(is_transitive(extcomm));
    }

    #[test]
    fn test_color_roundtrip() {
        let test_cases = vec!["color:0", "color:100", "color:999999", "color:4294967295"];

        for original in test_cases {
            let extcomm = parse_extended_community(original).unwrap();
            let formatted = format_extended_community(extcomm);
            assert_eq!(original, formatted);
        }
    }

    #[test]
    fn test_from_encapsulation() {
        let extcomm = from_encapsulation(8); // VXLAN
        assert_eq!(ext_type(extcomm), TYPE_OPAQUE);
        assert_eq!(ext_subtype(extcomm), SUBTYPE_ENCAPSULATION);
        // Tunnel type should be in last 2 bytes
        let value = ext_value(extcomm);
        let tunnel_type = u16::from_be_bytes([value[4], value[5]]);
        assert_eq!(tunnel_type, 8);
        assert!(is_transitive(extcomm));
    }

    #[test]
    fn test_encapsulation_roundtrip() {
        let test_cases = vec![
            "encapsulation:0",
            "encapsulation:8",  // VXLAN
            "encapsulation:15", // SR Policy
            "encapsulation:65535",
        ];

        for original in test_cases {
            let extcomm = parse_extended_community(original).unwrap();
            let formatted = format_extended_community(extcomm);
            assert_eq!(original, formatted);
        }
    }

    #[test]
    fn test_from_router_mac() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let extcomm = from_router_mac(mac);
        assert_eq!(ext_type(extcomm), TYPE_EVPN);
        assert_eq!(ext_subtype(extcomm), SUBTYPE_ROUTER_MAC);
        // MAC should be in value field
        let value = ext_value(extcomm);
        assert_eq!(value, mac);
        assert!(is_transitive(extcomm));
    }

    #[test]
    fn test_router_mac_roundtrip() {
        let test_cases = vec![
            "router-mac:00:00:00:00:00:00",
            "router-mac:aa:bb:cc:dd:ee:ff",
        ];

        for original in test_cases {
            let extcomm = parse_extended_community(original).unwrap();
            let formatted = format_extended_community(extcomm);
            assert_eq!(original, formatted);
        }
    }
}
