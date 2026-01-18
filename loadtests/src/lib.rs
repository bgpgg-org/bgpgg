pub mod receiver;
pub mod route_generator;
pub mod sender;

#[cfg(test)]
mod load_test;

// Re-export for convenience
pub use route_generator::calculate_expected_best_paths;

use bgpgg::bgp::msg::{BgpMessage, Message};
use bgpgg::bgp::msg_keepalive::KeepaliveMessage;
use bgpgg::bgp::msg_open::OpenMessage;
use bgpgg::bgp::msg_update::{NextHopAddr, UpdateMessage};
use bgpgg::bgp::msg_update_types::{AsPathSegment, AsPathSegmentType, Origin};
use bgpgg::net::{IpNetwork, Ipv4Net};
use bgpgg::rib::{Path, RouteSource};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Perform BGP handshake (OPEN + KEEPALIVE exchange)
pub async fn bgp_handshake(
    stream: &mut TcpStream,
    local_asn: u16,
    local_router_id: Ipv4Addr,
    peer_asn: u16,
    hold_time: u16,
) -> io::Result<()> {
    // Send OPEN
    let open = OpenMessage::new(local_asn, hold_time, u32::from(local_router_id));
    stream.write_all(&open.serialize()).await?;

    // Read peer's OPEN
    let msg = bgpgg::bgp::msg::read_bgp_message(&mut *stream)
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read OPEN: {:?}", e),
            )
        })?;

    match msg {
        BgpMessage::Open(peer_open) => {
            if peer_open.asn != peer_asn {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Expected ASN {}, got {}", peer_asn, peer_open.asn),
                ));
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected OPEN message",
            ));
        }
    }

    // Send KEEPALIVE
    let keepalive = KeepaliveMessage {};
    stream.write_all(&keepalive.serialize()).await?;

    // Read peer's KEEPALIVE
    let msg = bgpgg::bgp::msg::read_bgp_message(&mut *stream)
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read KEEPALIVE: {:?}", e),
            )
        })?;

    match msg {
        BgpMessage::Keepalive(_) => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected KEEPALIVE message",
        )),
    }
}

/// Generate sequential test routes starting from a base prefix
pub fn generate_test_routes(
    base_address: Ipv4Addr,
    count: usize,
    prefix_len: u8,
) -> Vec<IpNetwork> {
    let mut routes = Vec::with_capacity(count);
    let base = u32::from(base_address);

    // Calculate increment based on prefix length
    // For /24, increment by 256 (2^(32-24))
    let increment = 1u32 << (32 - prefix_len);

    for i in 0..count {
        let addr = base.wrapping_add((i as u32).wrapping_mul(increment));
        routes.push(IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::from(addr),
            prefix_length: prefix_len,
        }));
    }

    routes
}

/// Create an UPDATE message with the given routes
pub fn create_update_message(
    routes: Vec<IpNetwork>,
    next_hop: Ipv4Addr,
    as_path: Vec<u16>,
    origin: Origin,
    med: Option<u32>,
    local_pref: Option<u32>,
    communities: Vec<u32>,
) -> Vec<u8> {
    let as_path_segments = if as_path.is_empty() {
        vec![]
    } else {
        vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: as_path.len() as u8,
            asn_list: as_path,
        }]
    };

    let update = UpdateMessage::new(
        origin,
        as_path_segments,
        NextHopAddr::Ipv4(next_hop),
        routes,
        local_pref,
        med,
        false,
        communities,
        vec![],
        vec![],
    );

    update.serialize()
}

/// Transform a path to match what would be exported to an eBGP peer
/// (prepend local ASN, rewrite next_hop, remove local_pref and MED)
pub fn transform_path_for_ebgp_export(
    path: &Path,
    local_asn: u16,
    local_router_id: Ipv4Addr,
) -> Path {
    let mut exported = path.clone();

    // Prepend local ASN to AS_PATH
    if !exported.as_path.is_empty() {
        let first_segment = &exported.as_path[0];
        if first_segment.segment_type == AsPathSegmentType::AsSequence {
            // Prepend to existing AS_SEQUENCE
            let mut new_asn_list = vec![local_asn];
            new_asn_list.extend_from_slice(&first_segment.asn_list);
            exported.as_path[0] = AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: new_asn_list.len() as u8,
                asn_list: new_asn_list,
            };
        } else {
            // Create new AS_SEQUENCE with local ASN
            let mut new_segments = vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![local_asn],
            }];
            new_segments.extend_from_slice(&exported.as_path);
            exported.as_path = new_segments;
        }
    } else {
        // Empty AS_PATH, create new segment
        exported.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 1,
            asn_list: vec![local_asn],
        }];
    }

    // Rewrite next_hop to local router ID
    exported.next_hop = NextHopAddr::Ipv4(local_router_id);

    // Remove local_pref (not used in eBGP)
    exported.local_pref = None;

    // Remove MED (typically not propagated across AS boundaries)
    exported.med = None;

    exported
}

/// Convert proto::Path (from gRPC) to rib::Path for comparison
pub fn proto_path_to_rib_path(proto_path: &bgpgg::grpc::proto::Path) -> Result<Path, String> {
    // Convert origin
    let origin = match proto_path.origin {
        0 => Origin::IGP,
        1 => Origin::EGP,
        2 => Origin::INCOMPLETE,
        _ => return Err(format!("Invalid origin: {}", proto_path.origin)),
    };

    // Convert AS_PATH
    let as_path: Vec<AsPathSegment> = proto_path
        .as_path
        .iter()
        .map(|seg| {
            let segment_type = match seg.segment_type() {
                bgpgg::grpc::proto::AsPathSegmentType::AsSet => AsPathSegmentType::AsSet,
                bgpgg::grpc::proto::AsPathSegmentType::AsSequence => AsPathSegmentType::AsSequence,
            };
            AsPathSegment {
                segment_type,
                segment_len: seg.asns.len() as u8,
                asn_list: seg.asns.iter().map(|asn| *asn as u16).collect(),
            }
        })
        .collect();

    // Parse next hop
    let next_hop: Ipv4Addr = proto_path
        .next_hop
        .parse()
        .map_err(|_| format!("Invalid next_hop: {}", proto_path.next_hop))?;

    // Parse peer address for source
    let peer_ip: IpAddr = proto_path
        .peer_address
        .parse()
        .map_err(|_| format!("Invalid peer_address: {}", proto_path.peer_address))?;
    let source = RouteSource::Ebgp(peer_ip);

    // Convert communities
    let communities: Vec<u32> = proto_path.communities.clone();

    Ok(Path::from_attributes(
        origin,
        as_path,
        NextHopAddr::Ipv4(next_hop),
        source,
        proto_path.local_pref,
        proto_path.med,
        proto_path.atomic_aggregate,
        communities,
        vec![], // extended_communities
        vec![], // unknown_attrs not compared
    ))
}
