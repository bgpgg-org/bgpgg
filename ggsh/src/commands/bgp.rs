// Copyright 2026 bgpgg Authors
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

use bgpgg::grpc::proto::{
    extended_community, route, AsPathSegmentType, BgpState, ExtendedCommunity, LargeCommunity,
    ListRoutesRequest, LsNlri, LsNlriType, LsProtocolId, Path, RibType,
};
use bgpgg::grpc::BgpClient;

pub async fn show_summary(client: &BgpClient) -> Result<(), Box<dyn std::error::Error>> {
    let routes = client.list_routes(ListRoutesRequest::default()).await?;
    let peers = client.get_peers().await?;

    let total_routes = routes.len();
    let total_paths: usize = routes.iter().map(|r| r.paths.len()).sum();
    let total_peers = peers.len();
    let established_peers = peers
        .iter()
        .filter(|p| p.state() == BgpState::Established)
        .count();

    println!("BGP Summary:");
    println!("  Total Routes:        {}", total_routes);
    println!("  Total Paths:         {}", total_paths);
    println!("  Total Peers:         {}", total_peers);
    println!("  Established Peers:   {}", established_peers);

    if !peers.is_empty() {
        println!();
        println!("{:<30} {:<10} {:<15}", "Neighbor", "AS", "State");
        println!("{}", "-".repeat(55));
        for peer in &peers {
            let asn_str = if peer.asn == 0 {
                "-".to_string()
            } else {
                peer.asn.to_string()
            };
            println!(
                "{:<30} {:<10} {:<15}",
                peer.address,
                asn_str,
                format_state(peer.state())
            );
        }
    }

    Ok(())
}

pub async fn show_info(client: &BgpClient) -> Result<(), Box<dyn std::error::Error>> {
    let (listen_addr, listen_port, num_routes) = client.get_server_info().await?;
    println!("BGP Server Information:");
    println!("  Listen Address: {}:{}", listen_addr, listen_port);
    println!("  Routes in RIB: {}", num_routes);
    Ok(())
}

pub async fn show_peers(client: &BgpClient) -> Result<(), Box<dyn std::error::Error>> {
    let peers = client.get_peers().await?;

    if peers.is_empty() {
        println!("No peers configured");
    } else {
        println!("{:<30} {:<10} {:<15}", "Address", "ASN", "State");
        println!("{}", "-".repeat(55));
        for peer in &peers {
            let asn_str = if peer.asn == 0 {
                "-".to_string()
            } else {
                peer.asn.to_string()
            };
            println!(
                "{:<30} {:<10} {:<15}",
                peer.address,
                asn_str,
                format_state(peer.state())
            );
        }
    }

    Ok(())
}

pub async fn show_peer(
    client: &BgpClient,
    address: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (peer_opt, stats_opt) = client.get_peer(address.to_string()).await?;

    match (peer_opt, stats_opt) {
        (Some(peer), Some(stats)) => {
            println!("Peer: {}", address);
            println!("  ASN:         {}", peer.asn);
            println!("  State:       {}", format_state(peer.state()));
            println!();
            println!("Statistics:");
            println!("  Messages Sent:");
            println!("    OPEN:         {}", stats.open_sent);
            println!("    KEEPALIVE:    {}", stats.keepalive_sent);
            println!("    UPDATE:       {}", stats.update_sent);
            println!("    NOTIFICATION: {}", stats.notification_sent);
            println!("  Messages Received:");
            println!("    OPEN:         {}", stats.open_received);
            println!("    KEEPALIVE:    {}", stats.keepalive_received);
            println!("    UPDATE:       {}", stats.update_received);
            println!("    NOTIFICATION: {}", stats.notification_received);
        }
        _ => {
            eprintln!("Peer not found: {}", address);
        }
    }

    Ok(())
}

pub async fn show_peer_rib(
    client: &BgpClient,
    address: &str,
    direction: &str,
    afi: Option<u32>,
    safi: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let rib_type = if direction == "in" {
        RibType::AdjIn
    } else {
        RibType::AdjOut
    };

    let req = ListRoutesRequest {
        rib_type: Some(rib_type.into()),
        peer_address: Some(address.to_string()),
        afi,
        safi,
    };

    let routes = client.list_routes(req).await?;
    print_routes(&routes);
    Ok(())
}

pub async fn show_route(
    client: &BgpClient,
    prefix: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let routes = client.list_routes(ListRoutesRequest::default()).await?;

    let filtered: Vec<_> = if let Some(prefix) = prefix {
        routes
            .into_iter()
            .filter(|r| match &r.key {
                Some(route::Key::Prefix(p)) => p == prefix,
                _ => false,
            })
            .collect()
    } else {
        routes
    };

    print_routes(&filtered);
    Ok(())
}

pub async fn show_route_filtered(
    client: &BgpClient,
    afi: u32,
    safi: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = ListRoutesRequest {
        afi: Some(afi),
        safi,
        ..Default::default()
    };

    let routes = client.list_routes(req).await?;
    print_routes(&routes);
    Ok(())
}

fn print_routes(routes: &[bgpgg::grpc::proto::Route]) {
    if routes.is_empty() {
        println!("No routes");
        return;
    }

    for route in routes {
        let prefix_str = match &route.key {
            Some(route::Key::Prefix(p)) => p.clone(),
            Some(route::Key::LsNlri(nlri)) => format_ls_nlri(nlri),
            None => "unknown".to_string(),
        };

        let marker = if route.paths.len() > 1 { ">" } else { " " };
        println!("{} {}", marker, prefix_str);

        for (idx, path) in route.paths.iter().enumerate() {
            let best = if route.paths.len() > 1 && idx == 0 {
                " [best]"
            } else {
                ""
            };

            let mut via_parts = vec![format!("via {}", path.next_hop)];

            if let Some(locpref) = path.local_pref {
                via_parts.push(format!("lp {}", locpref));
            }
            if let Some(med) = path.med {
                via_parts.push(format!("med {}", med));
            }

            let as_path_str = format_as_path(&path.as_path);
            if as_path_str != "-" {
                via_parts.push(format!("path {}", as_path_str));
            }

            println!("    {}{}", via_parts.join("  "), best);

            let communities = format_communities(path);
            if !communities.is_empty() {
                println!("        communities: {}", communities);
            }
        }
    }

    println!("\nTotal routes: {}", routes.len());
}

fn format_state(state: BgpState) -> &'static str {
    match state {
        BgpState::Idle => "Idle",
        BgpState::Connect => "Connect",
        BgpState::Active => "Active",
        BgpState::OpenSent => "OpenSent",
        BgpState::OpenConfirm => "OpenConfirm",
        BgpState::Established => "Established",
    }
}

fn format_as_path(segments: &[bgpgg::grpc::proto::AsPathSegment]) -> String {
    if segments.is_empty() {
        return String::from("-");
    }

    segments
        .iter()
        .map(|seg| {
            let seg_type = AsPathSegmentType::try_from(seg.segment_type)
                .unwrap_or(AsPathSegmentType::AsSequence);
            match seg_type {
                AsPathSegmentType::AsSequence => seg
                    .asns
                    .iter()
                    .map(|asn| asn.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
                AsPathSegmentType::AsSet => {
                    format!(
                        "{{{}}}",
                        seg.asns
                            .iter()
                            .map(|asn| asn.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_ls_nlri(nlri: &LsNlri) -> String {
    let nlri_type = match LsNlriType::try_from(nlri.nlri_type) {
        Ok(LsNlriType::LsNode) => "Node",
        Ok(LsNlriType::LsLink) => "Link",
        Ok(LsNlriType::LsPrefixV4) => "PrefixV4",
        Ok(LsNlriType::LsPrefixV6) => "PrefixV6",
        _ => "Unknown",
    };
    let protocol = match LsProtocolId::try_from(nlri.protocol_id) {
        Ok(LsProtocolId::LsIsisL1) => "ISIS-L1",
        Ok(LsProtocolId::LsIsisL2) => "ISIS-L2",
        Ok(LsProtocolId::LsOspfv2) => "OSPFv2",
        Ok(LsProtocolId::LsDirect) => "Direct",
        Ok(LsProtocolId::LsStatic) => "Static",
        Ok(LsProtocolId::LsOspfv3) => "OSPFv3",
        _ => "?",
    };
    let node_info = nlri
        .local_node
        .as_ref()
        .map(|nd| {
            let asn = nd.as_number.map(|a| a.to_string()).unwrap_or_default();
            let rid = if nd.igp_router_id.len() == 4 {
                format!(
                    "{}.{}.{}.{}",
                    nd.igp_router_id[0],
                    nd.igp_router_id[1],
                    nd.igp_router_id[2],
                    nd.igp_router_id[3]
                )
            } else if !nd.igp_router_id.is_empty() {
                format!("{:?}", nd.igp_router_id)
            } else {
                String::new()
            };
            format!("AS{} {}", asn, rid)
        })
        .unwrap_or_default();
    format!("LS/{}/{} {}", nlri_type, protocol, node_info)
}

fn format_communities(path: &Path) -> String {
    let mut parts = Vec::new();

    for community in &path.communities {
        let formatted = match *community {
            0xFFFFFF01 => String::from("NO_EXPORT"),
            0xFFFFFF02 => String::from("NO_ADVERTISE"),
            0xFFFFFF03 => String::from("NO_EXPORT_SUBCONFED"),
            0xFFFFFF04 => String::from("NOPEER"),
            val => {
                let high = (val >> 16) as u16;
                let low = (val & 0xFFFF) as u16;
                format!("{}:{}", high, low)
            }
        };
        parts.push(formatted);
    }

    for ext in &path.extended_communities {
        parts.push(format_extended_community(ext));
    }

    for large in &path.large_communities {
        parts.push(format_large_community(large));
    }

    parts.join(" ")
}

fn format_extended_community(ext: &ExtendedCommunity) -> String {
    match &ext.community {
        Some(extended_community::Community::TwoOctetAs(ec)) => {
            let label = ext_subtype_label(ec.sub_type);
            format!("{}{}:{}", label, ec.asn, ec.local_admin)
        }
        Some(extended_community::Community::Ipv4Address(ec)) => {
            let label = ext_subtype_label(ec.sub_type);
            format!("{}{}:{}", label, ec.address, ec.local_admin)
        }
        Some(extended_community::Community::FourOctetAs(ec)) => {
            let label = ext_subtype_label(ec.sub_type);
            format!("{}{}:{}", label, ec.asn, ec.local_admin)
        }
        Some(extended_community::Community::LinkBandwidth(ec)) => {
            format!("lb:{}:{:.0}", ec.asn, ec.bandwidth)
        }
        Some(extended_community::Community::Color(ec)) => {
            format!("color:{}", ec.color)
        }
        Some(extended_community::Community::Encapsulation(ec)) => {
            format!("encap:{}", ec.tunnel_type)
        }
        Some(extended_community::Community::RouterMac(ec)) => {
            let mac = &ec.mac_address;
            if mac.len() == 6 {
                format!(
                    "mac:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                )
            } else {
                format!("mac:{:?}", mac)
            }
        }
        Some(extended_community::Community::Opaque(ec)) => {
            format!("opaque:{:?}", ec.value)
        }
        Some(extended_community::Community::Unknown(ec)) => {
            format!("ext:0x{:02x}:{:?}", ec.type_code, ec.value)
        }
        None => String::from("ext:?"),
    }
}

fn ext_subtype_label(sub_type: u32) -> &'static str {
    match sub_type {
        0x02 => "rt:",
        0x03 => "ro:",
        _ => "",
    }
}

fn format_large_community(lc: &LargeCommunity) -> String {
    format!("{}:{}:{}", lc.global_admin, lc.local_data_1, lc.local_data_2)
}
