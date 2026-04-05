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

use bgpgg::grpc::proto::{
    add_route_request, remove_route_request, route, AddIpRouteRequest, AddLsRouteRequest,
    AddRouteRequest, AsPathSegment, AsPathSegmentType, ListRoutesRequest, LsNlri, LsNlriType,
    LsNodeAttribute, LsNodeDescriptor, LsProtocolId, Origin, RemoveRouteRequest,
};
use bgpgg::grpc::BgpClient;

use crate::{AddLsCommands, DelLsCommands, GlobalCommands, RibCommands};

pub async fn handle(addr: String, cmd: GlobalCommands) -> Result<(), Box<dyn std::error::Error>> {
    let client = BgpClient::connect(addr.clone())
        .await
        .map_err(|e| format!("Failed to connect to BGP daemon at {}: {}", addr, e))?;

    match cmd {
        GlobalCommands::Rib(rib_cmd) => match rib_cmd {
            RibCommands::Show => {
                let routes = client.list_routes(ListRoutesRequest::default()).await?;

                if routes.is_empty() {
                    println!("No routes in global RIB");
                } else {
                    println!(
                        "{:<20} {:<15} {:<20} {:<10} {:<15} {:<20}",
                        "Prefix", "Next Hop", "AS Path", "Origin", "Peer", "Communities"
                    );
                    println!("{}", "-".repeat(100));

                    for route in routes {
                        let prefix_str = match &route.key {
                            Some(route::Key::Prefix(p)) => p.clone(),
                            Some(route::Key::LsNlri(nlri)) => format_ls_nlri(nlri),
                            None => "unknown".to_string(),
                        };
                        for path in route.paths.iter() {
                            let as_path_str = format_as_path(&path.as_path);
                            let as_path_display = if as_path_str.len() > 20 {
                                format!("{}...", &as_path_str[..17])
                            } else {
                                as_path_str
                            };

                            let communities_str = if path.communities.is_empty() {
                                String::from("-")
                            } else {
                                format_communities(&path.communities)
                            };

                            println!(
                                "{:<20} {:<15} {:<20} {:<10} {:<15} {:<20}",
                                prefix_str,
                                path.next_hop,
                                as_path_display,
                                format_origin(path.origin()),
                                path.peer_address,
                                communities_str
                            );
                        }
                    }
                }
            }

            RibCommands::Add {
                prefix,
                nexthop,
                origin,
                as_path,
                local_pref,
                med,
                atomic_aggregate,
                community,
            } => {
                let origin_enum = parse_origin(&origin)?;
                let as_path_segments = parse_as_path(as_path)?;
                let communities_vec = parse_communities(community)?;

                let msg = client
                    .add_route(AddRouteRequest {
                        route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                            prefix: prefix.clone(),
                            next_hop: nexthop,
                            origin: origin_enum as i32,
                            as_path: as_path_segments,
                            local_pref,
                            med,
                            atomic_aggregate,
                            communities: communities_vec,
                            ..Default::default()
                        }))),
                    })
                    .await?;

                println!("{}", msg);
            }

            RibCommands::Del { prefix } => {
                let msg = client
                    .remove_route(RemoveRouteRequest {
                        key: Some(remove_route_request::Key::Prefix(prefix.clone())),
                    })
                    .await?;
                println!("{}", msg);
            }

            RibCommands::AddLs(ls_cmd) => match ls_cmd {
                AddLsCommands::Node {
                    asn,
                    router_id,
                    protocol,
                    identifier,
                    name,
                } => {
                    let protocol_id = parse_ls_protocol(&protocol)?;
                    let router_id_bytes = parse_router_id(&router_id)?;
                    let attribute = name.map(|node_name| bgpgg::grpc::proto::LsAttribute {
                        node: Some(LsNodeAttribute {
                            name: Some(node_name),
                            ..Default::default()
                        }),
                        ..Default::default()
                    });
                    let msg = client
                        .add_route(AddRouteRequest {
                            route: Some(add_route_request::Route::Ls(Box::new(
                                AddLsRouteRequest {
                                    nlri: Some(LsNlri {
                                        nlri_type: LsNlriType::LsNode as i32,
                                        protocol_id: protocol_id as i32,
                                        identifier,
                                        local_node: Some(LsNodeDescriptor {
                                            as_number: Some(asn),
                                            igp_router_id: router_id_bytes,
                                            ..Default::default()
                                        }),
                                        ..Default::default()
                                    }),
                                    attribute,
                                    next_hop: None,
                                },
                            ))),
                        })
                        .await?;
                    println!("{}", msg);
                }
            },

            RibCommands::DelLs(ls_cmd) => match ls_cmd {
                DelLsCommands::Node {
                    asn,
                    router_id,
                    protocol,
                    identifier,
                } => {
                    let protocol_id = parse_ls_protocol(&protocol)?;
                    let router_id_bytes = parse_router_id(&router_id)?;
                    let msg = client
                        .remove_route(RemoveRouteRequest {
                            key: Some(remove_route_request::Key::LsNlri(Box::new(LsNlri {
                                nlri_type: LsNlriType::LsNode as i32,
                                protocol_id: protocol_id as i32,
                                identifier,
                                local_node: Some(LsNodeDescriptor {
                                    as_number: Some(asn),
                                    igp_router_id: router_id_bytes,
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }))),
                        })
                        .await?;
                    println!("{}", msg);
                }
            },
        },

        GlobalCommands::Info => {
            let (listen_addr, listen_port, num_routes) = client.get_server_info().await?;
            println!("BGP Server Information:");
            println!("  Listen Address: {}:{}", listen_addr, listen_port);
            println!("  Routes in RIB: {}", num_routes);
        }

        GlobalCommands::Summary => {
            let routes = client.list_routes(ListRoutesRequest::default()).await?;
            let peers = client.get_peers().await?;

            let total_routes = routes.len();
            let total_paths: usize = routes.iter().map(|r| r.paths.len()).sum();
            let total_peers = peers.len();
            let established_peers = peers
                .iter()
                .filter(|p| p.state() == bgpgg::grpc::proto::BgpState::Established)
                .count();

            println!("BGP Summary:");
            println!("  Total Routes:        {}", total_routes);
            println!("  Total Paths:         {}", total_paths);
            println!("  Total Peers:         {}", total_peers);
            println!("  Established Peers:   {}", established_peers);
        }
    }

    Ok(())
}

fn format_origin(origin: Origin) -> &'static str {
    match origin {
        Origin::Igp => "IGP",
        Origin::Egp => "EGP",
        Origin::Incomplete => "INCOMPLETE",
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

fn format_communities(communities: &[u32]) -> String {
    communities
        .iter()
        .map(|c| {
            let high = (c >> 16) as u16;
            let low = (c & 0xFFFF) as u16;

            // Check for well-known communities
            match *c {
                0xFFFFFF01 => String::from("NO_EXPORT"),
                0xFFFFFF02 => String::from("NO_ADVERTISE"),
                0xFFFFFF03 => String::from("NO_EXPORT_SUBCONFED"),
                0xFFFFFF04 => String::from("NOPEER"),
                _ => format!("{}:{}", high, low),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_origin(origin: &str) -> Result<Origin, Box<dyn std::error::Error>> {
    match origin.to_lowercase().as_str() {
        "igp" => Ok(Origin::Igp),
        "egp" => Ok(Origin::Egp),
        "incomplete" => Ok(Origin::Incomplete),
        _ => Err(format!(
            "Invalid origin: {}. Must be 'igp', 'egp', or 'incomplete'",
            origin
        )
        .into()),
    }
}

fn parse_as_path(
    as_path: Option<String>,
) -> Result<Vec<AsPathSegment>, Box<dyn std::error::Error>> {
    let Some(as_path_str) = as_path else {
        return Ok(vec![]);
    };

    let asns: Result<Vec<u32>, _> = as_path_str
        .split_whitespace()
        .map(|s| s.parse::<u32>())
        .collect();

    let asns = asns.map_err(|e| format!("Invalid AS number in AS path: {}", e))?;

    if asns.is_empty() {
        return Ok(vec![]);
    }

    Ok(vec![AsPathSegment {
        segment_type: AsPathSegmentType::AsSequence.into(),
        asns,
    }])
}

fn parse_communities(communities: Vec<String>) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
    if communities.is_empty() {
        return Ok(vec![]);
    }

    communities
        .iter()
        .map(|c| {
            if let Ok(value) = c.parse::<u32>() {
                return Ok(value);
            }

            match c.to_uppercase().as_str() {
                "NO_EXPORT" => Ok(0xFFFFFF01),
                "NO_ADVERTISE" => Ok(0xFFFFFF02),
                "NO_EXPORT_SUBCONFED" => Ok(0xFFFFFF03),
                "NOPEER" => Ok(0xFFFFFF04),
                _ => {
                    let parts: Vec<&str> = c.split(':').collect();
                    if parts.len() != 2 {
                        return Err(format!(
                            "Invalid community format: {}. Expected ASN:VALUE or well-known name",
                            c
                        )
                        .into());
                    }

                    let high: u16 = parts[0]
                        .parse()
                        .map_err(|_| format!("Invalid AS number in community: {}", parts[0]))?;
                    let low: u16 = parts[1]
                        .parse()
                        .map_err(|_| format!("Invalid value in community: {}", parts[1]))?;

                    Ok(((high as u32) << 16) | (low as u32))
                }
            }
        })
        .collect()
}

fn parse_ls_protocol(protocol: &str) -> Result<LsProtocolId, Box<dyn std::error::Error>> {
    match protocol.to_lowercase().as_str() {
        "isis-l1" => Ok(LsProtocolId::LsIsisL1),
        "isis-l2" => Ok(LsProtocolId::LsIsisL2),
        "ospfv2" => Ok(LsProtocolId::LsOspfv2),
        "direct" => Ok(LsProtocolId::LsDirect),
        "static" => Ok(LsProtocolId::LsStatic),
        "ospfv3" => Ok(LsProtocolId::LsOspfv3),
        _ => Err(format!(
            "Invalid protocol: {}. Must be isis-l1, isis-l2, ospfv2, direct, static, or ospfv3",
            protocol
        )
        .into()),
    }
}

fn parse_router_id(router_id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let addr: std::net::Ipv4Addr = router_id
        .parse()
        .map_err(|_| format!("Invalid router ID: {}", router_id))?;
    Ok(addr.octets().to_vec())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_origin() {
        assert!(matches!(parse_origin("igp").unwrap(), Origin::Igp));
        assert!(matches!(parse_origin("IGP").unwrap(), Origin::Igp));
        assert!(matches!(parse_origin("egp").unwrap(), Origin::Egp));
        assert!(matches!(parse_origin("EGP").unwrap(), Origin::Egp));
        assert!(matches!(
            parse_origin("incomplete").unwrap(),
            Origin::Incomplete
        ));
        assert!(matches!(
            parse_origin("INCOMPLETE").unwrap(),
            Origin::Incomplete
        ));
        assert!(parse_origin("invalid").is_err());
    }

    #[test]
    fn test_parse_as_path() {
        let result = parse_as_path(None).unwrap();
        assert!(result.is_empty());

        let result = parse_as_path(Some("".to_string())).unwrap();
        assert!(result.is_empty());

        let result = parse_as_path(Some("100 200 300".to_string())).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].asns, vec![100, 200, 300]);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence as i32);

        assert!(parse_as_path(Some("100 invalid 300".to_string())).is_err());
    }

    #[test]
    fn test_parse_communities() {
        let result = parse_communities(vec![]).unwrap();
        assert!(result.is_empty());

        let result = parse_communities(vec!["65001:100".to_string()]).unwrap();
        assert_eq!(result, vec![0xFDE90064]);

        let result =
            parse_communities(vec!["65001:100".to_string(), "65001:200".to_string()]).unwrap();
        assert_eq!(result, vec![0xFDE90064, 0xFDE900C8]);

        let result = parse_communities(vec!["NO_EXPORT".to_string()]).unwrap();
        assert_eq!(result, vec![0xFFFFFF01]);

        let result = parse_communities(vec!["NO_ADVERTISE".to_string()]).unwrap();
        assert_eq!(result, vec![0xFFFFFF02]);

        let result =
            parse_communities(vec!["65001:100".to_string(), "NO_EXPORT".to_string()]).unwrap();
        assert_eq!(result, vec![0xFDE90064, 0xFFFFFF01]);

        let result = parse_communities(vec!["4259905636".to_string()]).unwrap();
        assert_eq!(result, vec![0xFDE90064]);

        assert!(parse_communities(vec!["invalid".to_string()]).is_err());
        assert!(parse_communities(vec!["65001:".to_string()]).is_err());
    }

    #[test]
    fn test_format_communities() {
        assert_eq!(format_communities(&[0x00010064]), "1:100");
        assert_eq!(format_communities(&[0xFDE90064]), "65001:100");
        assert_eq!(format_communities(&[0xFFFFFF01]), "NO_EXPORT");
        assert_eq!(format_communities(&[0xFFFFFF02]), "NO_ADVERTISE");
        assert_eq!(format_communities(&[0xFFFFFF03]), "NO_EXPORT_SUBCONFED");
        assert_eq!(format_communities(&[0xFFFFFF04]), "NOPEER");
        assert_eq!(
            format_communities(&[0xFDE90064, 0xFFFFFF01]),
            "65001:100 NO_EXPORT"
        );
    }

    #[test]
    fn test_format_origin() {
        assert_eq!(format_origin(Origin::Igp), "IGP");
        assert_eq!(format_origin(Origin::Egp), "EGP");
        assert_eq!(format_origin(Origin::Incomplete), "INCOMPLETE");
    }

    #[test]
    fn test_format_as_path() {
        assert_eq!(format_as_path(&[]), "-");

        let segments = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence.into(),
            asns: vec![100, 200, 300],
        }];
        assert_eq!(format_as_path(&segments), "100 200 300");

        let segments = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSet.into(),
            asns: vec![100, 200, 300],
        }];
        assert_eq!(format_as_path(&segments), "{100,200,300}");
    }

    #[test]
    fn test_parse_ls_protocol() {
        assert!(matches!(
            parse_ls_protocol("direct").unwrap(),
            LsProtocolId::LsDirect
        ));
        assert!(matches!(
            parse_ls_protocol("isis-l1").unwrap(),
            LsProtocolId::LsIsisL1
        ));
        assert!(matches!(
            parse_ls_protocol("ospfv2").unwrap(),
            LsProtocolId::LsOspfv2
        ));
        assert!(parse_ls_protocol("invalid").is_err());
    }

    #[test]
    fn test_parse_router_id() {
        assert_eq!(parse_router_id("10.0.0.1").unwrap(), vec![10, 0, 0, 1]);
        assert_eq!(
            parse_router_id("192.168.1.1").unwrap(),
            vec![192, 168, 1, 1]
        );
        assert!(parse_router_id("not-an-ip").is_err());
    }

    #[test]
    fn test_format_ls_nlri() {
        let nlri = LsNlri {
            nlri_type: LsNlriType::LsNode as i32,
            protocol_id: LsProtocolId::LsDirect as i32,
            identifier: 0,
            local_node: Some(LsNodeDescriptor {
                as_number: Some(65001),
                igp_router_id: vec![10, 0, 0, 1],
                ..Default::default()
            }),
            ..Default::default()
        };
        let formatted = format_ls_nlri(&nlri);
        assert!(formatted.contains("Node"));
        assert!(formatted.contains("Direct"));
        assert!(formatted.contains("65001"));
        assert!(formatted.contains("10.0.0.1"));
    }
}
