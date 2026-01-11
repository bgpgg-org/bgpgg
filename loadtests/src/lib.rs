pub mod receiver;
pub mod route_generator;
pub mod sender;

#[cfg(test)]
mod load_test;

use bgpgg::bgp::msg::{BgpMessage, Message};
use bgpgg::bgp::msg_keepalive::KeepAliveMessage;
use bgpgg::bgp::msg_open::OpenMessage;
use bgpgg::bgp::msg_update::UpdateMessage;
use bgpgg::bgp::msg_update_types::{AsPathSegment, AsPathSegmentType, Origin};
use bgpgg::net::{IpNetwork, Ipv4Net};
use std::io;
use std::net::Ipv4Addr;
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
    let keepalive = KeepAliveMessage {};
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
        BgpMessage::KeepAlive(_) => Ok(()),
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

    // Add NO_ADVERTISE community to prevent bgpgg from redistributing routes
    // This eliminates TCP backpressure from route redistribution in load tests
    const NO_ADVERTISE: u32 = 0xFFFFFF02;
    let mut all_communities = vec![NO_ADVERTISE];
    all_communities.extend(communities);

    let update = UpdateMessage::new(
        origin,
        as_path_segments,
        next_hop,
        routes,
        local_pref,
        med,
        false,
        all_communities,
        vec![],
    );

    update.serialize()
}
