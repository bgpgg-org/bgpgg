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

use bgpgg::grpc::proto::{AsPathSegmentType, Origin};
use bgpgg::grpc::BgpClient;

use crate::GlobalCommands;

pub async fn handle(addr: String, cmd: GlobalCommands) -> Result<(), Box<dyn std::error::Error>> {
    let client = BgpClient::connect(addr.clone())
        .await
        .map_err(|e| format!("Failed to connect to BGP daemon at {}: {}", addr, e))?;

    match cmd {
        GlobalCommands::Rib => {
            let routes = client.get_routes().await?;

            if routes.is_empty() {
                println!("No routes in global RIB");
            } else {
                for route in routes {
                    println!("Prefix: {}", route.prefix);
                    for (idx, path) in route.paths.iter().enumerate() {
                        if idx > 0 {
                            println!();
                        }
                        println!("  Path #{}:", idx + 1);
                        println!("    Origin:      {}", format_origin(path.origin()));
                        println!("    AS Path:     {}", format_as_path(&path.as_path));
                        println!("    Next Hop:    {}", path.next_hop);
                        println!("    Peer:        {}", path.peer_address);

                        if let Some(local_pref) = path.local_pref {
                            println!("    Local Pref:  {}", local_pref);
                        }

                        if let Some(med) = path.med {
                            println!("    MED:         {}", med);
                        }

                        if path.atomic_aggregate {
                            println!("    Atomic Aggregate: true");
                        }

                        if !path.communities.is_empty() {
                            println!("    Communities: {}", format_communities(&path.communities));
                        }
                    }
                    println!();
                }
            }
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
