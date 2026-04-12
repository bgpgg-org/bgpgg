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

use crate::util::{parse_afi, parse_safi};
use bgpgg::grpc::proto::{
    extended_community, route, AddPathSendMode, AdminState, AsPathSegment, AsPathSegmentType,
    BgpState, ExtendedCommunity, LargeCommunity, ListRoutesRequest, LsNlri, LsNlriType,
    LsProtocolId, Path, RibType, Route,
};
use bgpgg::grpc::BgpClient;

pub async fn show_summary(client: &BgpClient) -> Result<(), Box<dyn std::error::Error>> {
    let routes = client.list_routes(ListRoutesRequest::default()).await?;
    let peers = client.get_peers().await?;
    let (listen_addr, listen_port, _) = client.get_server_info().await?;

    let total_routes = routes.len();
    let total_paths: usize = routes.iter().map(|r| r.paths.len()).sum();
    let established_peers = peers
        .iter()
        .filter(|p| p.state() == BgpState::Established)
        .count();

    println!("BGP router listening on {}:{}", listen_addr, listen_port);
    println!("RIB entries {}, {} paths", total_routes, total_paths);
    println!("Peers {}, {} established", peers.len(), established_peers);

    if !peers.is_empty() {
        println!();
        println!(
            "{:<20} {:<12} {:>8} {:>8}  {:<15}",
            "Neighbor", "AS", "MsgRcvd", "MsgSent", "State/PfxRcd"
        );
        for peer in &peers {
            let asn_str = if peer.asn == 0 {
                "-".to_string()
            } else {
                peer.asn.to_string()
            };

            let (msg_sent, msg_rcvd) = match client.get_peer(peer.address.clone()).await {
                Ok((_, Some(stats))) => (
                    stats.open_sent
                        + stats.keepalive_sent
                        + stats.update_sent
                        + stats.notification_sent,
                    stats.open_received
                        + stats.keepalive_received
                        + stats.update_received
                        + stats.notification_received,
                ),
                _ => (0, 0),
            };

            let state_pfx = if peer.state() == BgpState::Established {
                "Established".to_string()
            } else {
                format_state(peer.state()).to_string()
            };

            println!(
                "{:<20} {:<12} {:>8} {:>8}  {}",
                peer.address, asn_str, msg_rcvd, msg_sent, state_pfx,
            );
        }
    }

    Ok(())
}

pub async fn show_info(client: &BgpClient) -> Result<(), Box<dyn std::error::Error>> {
    let (listen_addr, listen_port, num_routes) = client.get_server_info().await?;
    let peers = client.get_peers().await?;
    let established = peers
        .iter()
        .filter(|p| p.state() == BgpState::Established)
        .count();

    println!("BGP Daemon:");
    println!("  Listen:       {}:{}", listen_addr, listen_port);
    println!("  Routes:       {}", num_routes);
    println!(
        "  Peers:        {} configured, {} established",
        peers.len(),
        established
    );
    Ok(())
}

pub async fn show_peers(client: &BgpClient) -> Result<(), Box<dyn std::error::Error>> {
    let peers = client.get_peers().await?;

    if peers.is_empty() {
        println!("No peers configured");
    } else {
        println!(
            "{:<30} {:<10} {:<15} {:<8}",
            "Address", "ASN", "State", "Admin"
        );
        println!("{}", "-".repeat(65));
        for peer in &peers {
            let asn_str = if peer.asn == 0 {
                "-".to_string()
            } else {
                peer.asn.to_string()
            };
            println!(
                "{:<30} {:<10} {:<15} {:<8}",
                peer.address,
                asn_str,
                format_state(peer.state()),
                format_admin_state(peer.admin_state()),
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
            println!("  ASN:            {}", peer.asn);
            println!("  State:          {}", format_state(peer.state()));
            println!(
                "  Admin State:    {}",
                format_admin_state(peer.admin_state())
            );

            if !peer.import_policies.is_empty() {
                println!("  Import Policy:  {}", peer.import_policies.join(", "));
            }
            if !peer.export_policies.is_empty() {
                println!("  Export Policy:  {}", peer.export_policies.join(", "));
            }

            if let Some(config) = &peer.session_config {
                println!();
                println!("Session Config:");
                if let Some(passive) = config.passive_mode {
                    println!("  Passive:        {}", if passive { "yes" } else { "no" });
                }
                if let Some(port) = config.port {
                    println!("  Remote Port:    {}", port);
                }
                if let Some(iface) = &config.interface {
                    println!("  Interface:      {}", iface);
                }
                if let Some(rr) = config.rr_client {
                    if rr {
                        println!("  RR Client:      yes");
                    }
                }
                if let Some(rs) = config.rs_client {
                    if rs {
                        println!("  RS Client:      yes");
                    }
                }
                if let Some(nhs) = config.next_hop_self {
                    if nhs {
                        println!("  Next-Hop-Self:  yes");
                    }
                }
                if let Some(mode) = config.add_path_send {
                    let mode = AddPathSendMode::try_from(mode);
                    if matches!(mode, Ok(AddPathSendMode::AddPathSendAll)) {
                        println!("  Add-Path Send:  all");
                    }
                }
                if let Some(true) = config.add_path_receive {
                    println!("  Add-Path Recv:  yes");
                }
                if let Some(true) = config.graceful_shutdown {
                    println!("  Graceful Shutdown: yes");
                }
                if let Some(ttl) = config.ttl_min {
                    println!("  GTSM TTL Min:  {}", ttl);
                }
                if config.md5_key_file.is_some() {
                    println!("  TCP MD5:        enabled");
                }
                if let Some(true) = config.send_rpki_community {
                    println!("  RPKI Community: yes");
                }
                if !config.afi_safis.is_empty() {
                    let families: Vec<String> = config
                        .afi_safis
                        .iter()
                        .map(|af| format!("afi={} safi={}", af.afi, af.safi))
                        .collect();
                    println!("  AFI/SAFI:       {}", families.join(", "));
                }
            }

            println!();
            println!("Message Statistics:");
            println!(
                "  Sent:     OPEN={} KEEPALIVE={} UPDATE={} NOTIFICATION={}",
                stats.open_sent, stats.keepalive_sent, stats.update_sent, stats.notification_sent
            );
            println!(
                "  Received: OPEN={} KEEPALIVE={} UPDATE={} NOTIFICATION={}",
                stats.open_received,
                stats.keepalive_received,
                stats.update_received,
                stats.notification_received
            );
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

async fn show_route(
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

pub async fn show_bgp_route(
    client: &BgpClient,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    match args.first() {
        None => show_route(client, None).await,
        Some(arg) if arg.contains('/') => show_route(client, Some(arg)).await,
        Some(afi_str) => {
            let afi = parse_afi(Some(afi_str)).ok_or_else(|| {
                format!(
                    "unknown AFI or prefix '{}', expected: ipv4, ipv6, ls, or CIDR prefix",
                    afi_str
                )
            })?;
            let safi = parse_safi(args.get(1));
            show_route_filtered(client, afi, safi).await
        }
    }
}

async fn show_route_filtered(
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

fn print_routes(routes: &[Route]) {
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

            // Prefer link-local next-hop when available (IPv6 link-local peering)
            let next_hop_display = path
                .link_local_next_hop
                .as_deref()
                .unwrap_or(&path.next_hop);
            let mut via_parts = vec![format!("via {}", next_hop_display)];

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

fn format_admin_state(state: AdminState) -> &'static str {
    match state {
        AdminState::Up => "Up",
        AdminState::Down => "Down",
        AdminState::PrefixLimitExceeded => "PfxLimit",
    }
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

fn format_as_path(segments: &[AsPathSegment]) -> String {
    if segments.is_empty() {
        return String::from("-");
    }

    segments
        .iter()
        .map(|seg| {
            let seg_type = AsPathSegmentType::try_from(seg.segment_type).unwrap_or_default();
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
    format!(
        "{}:{}:{}",
        lc.global_admin, lc.local_data_1, lc.local_data_2
    )
}
