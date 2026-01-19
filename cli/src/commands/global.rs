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

use bgpgg::grpc::proto::{AsPathSegment, AsPathSegmentType, Origin};
use bgpgg::grpc::BgpClient;

use crate::{GlobalCommands, RibCommands};

pub async fn handle(addr: String, cmd: GlobalCommands) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = BgpClient::connect(addr.clone())
        .await
        .map_err(|e| format!("Failed to connect to BGP daemon at {}: {}", addr, e))?;

    match cmd {
        GlobalCommands::Rib(rib_cmd) => match rib_cmd {
            RibCommands::Show => {
                let routes = client.get_routes().await?;

                if routes.is_empty() {
                    println!("No routes in global RIB");
                } else {
                    println!(
                        "{:<20} {:<15} {:<20} {:<10} {:<15} {:<20}",
                        "Prefix", "Next Hop", "AS Path", "Origin", "Peer", "Communities"
                    );
                    println!("{}", "-".repeat(100));

                    for route in routes {
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
                                route.prefix,
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
                    .add_route(
                        prefix.clone(),
                        nexthop,
                        origin_enum,
                        as_path_segments,
                        local_pref,
                        med,
                        atomic_aggregate,
                        communities_vec,
                        vec![], // extended_communities
                        vec![], // large_communities
                    )
                    .await?;

                println!("{}", msg);
            }

            RibCommands::Del { prefix } => {
                let msg = client.remove_route(prefix.clone()).await?;
                println!("{}", msg);
            }
        },

        GlobalCommands::Info => {
            let (listen_addr, listen_port, num_routes) = client.get_server_info().await?;
            println!("BGP Server Information:");
            println!("  Listen Address: {}:{}", listen_addr, listen_port);
            println!("  Routes in RIB: {}", num_routes);
        }

        GlobalCommands::Summary => {
            let routes = client.get_routes().await?;
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
}
