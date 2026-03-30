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

use bgpgg::grpc::proto::{AddRpkiCacheRequest, RpkiValidation};
use bgpgg::grpc::BgpClient;

use crate::RpkiCommands;

pub async fn handle(addr: String, cmd: RpkiCommands) -> Result<(), Box<dyn std::error::Error>> {
    let client = BgpClient::connect(addr.clone())
        .await
        .map_err(|e| format!("Failed to connect to BGP daemon at {}: {}", addr, e))?;

    match cmd {
        RpkiCommands::Add {
            address,
            preference,
            transport,
            ssh_username,
            ssh_private_key_file,
            ssh_known_hosts_file,
            retry_interval,
            refresh_interval,
            expire_interval,
        } => {
            let request = AddRpkiCacheRequest {
                address: address.clone(),
                preference: preference.map(|p| p as u32),
                transport,
                ssh_username,
                ssh_private_key_file,
                ssh_known_hosts_file,
                retry_interval,
                refresh_interval,
                expire_interval,
            };
            match client.add_rpki_cache(request).await {
                Ok(message) => println!("{}", message),
                Err(e) => eprintln!("Error: {}", e.message()),
            }
        }

        RpkiCommands::Del { address } => match client.remove_rpki_cache(address).await {
            Ok(message) => println!("{}", message),
            Err(e) => eprintln!("Error: {}", e.message()),
        },

        RpkiCommands::List => {
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
        }

        RpkiCommands::Validate { prefix, origin_as } => {
            let resp = client
                .get_rpki_validation(prefix.clone(), origin_as)
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
        }
    }

    Ok(())
}
