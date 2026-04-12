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

use bgpgg::grpc::proto::RpkiValidation;
use bgpgg::grpc::BgpClient;

pub async fn show_caches(client: &BgpClient) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_rpki_caches().await?;

    if resp.caches.is_empty() {
        println!("No RPKI caches configured");
    } else {
        println!(
            "{:<25} {:<5} {:<10} {:<8} {:<10}",
            "Address", "Pref", "Transport", "Active", "VRPs"
        );
        println!("{}", "-".repeat(60));

        for cache in &resp.caches {
            println!(
                "{:<25} {:<5} {:<10} {:<8} {:<10}",
                cache.address,
                cache.preference,
                cache.transport,
                if cache.session_active { "yes" } else { "no" },
                cache.vrp_count,
            );
        }
    }
    println!("\nTotal VRPs in table: {}", resp.total_vrp_count);
    Ok(())
}

pub async fn show_roa(client: &BgpClient) -> Result<(), Box<dyn std::error::Error>> {
    // ROA table is not yet exposed via gRPC -- show cache summary instead
    let resp = client.list_rpki_caches().await?;
    println!("Total VRPs in table: {}", resp.total_vrp_count);
    println!("(Per-VRP listing not yet available via gRPC)");
    Ok(())
}

pub async fn show_validate(
    client: &BgpClient,
    prefix: &str,
    origin_as: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .get_rpki_validation(prefix.to_string(), origin_as)
        .await?;

    let state_str = match RpkiValidation::try_from(resp.validation) {
        Ok(RpkiValidation::RpkiValid) => "Valid",
        Ok(RpkiValidation::RpkiInvalid) => "Invalid",
        Ok(RpkiValidation::RpkiNotFound) => "NotFound",
        _ => "Unknown",
    };

    println!("Prefix:    {}", prefix);
    println!("Origin AS: {}", origin_as);
    println!("State:     {}", state_str);

    if !resp.covering_vrps.is_empty() {
        println!("\nCovering VRPs:");
        println!("{:<20} {:<12} {:<10}", "Prefix", "MaxLength", "Origin AS");
        println!("{}", "-".repeat(45));
        for vrp in &resp.covering_vrps {
            println!(
                "{:<20} {:<12} {:<10}",
                vrp.prefix, vrp.max_length, vrp.origin_as
            );
        }
    }

    Ok(())
}
