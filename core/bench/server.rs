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

use bgpgg::grpc::{proto::SessionConfig, BgpClient};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::process::{Child, Command};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub daemon_bin: String,
    pub daemon_args: Vec<String>,
    pub config_template: String,
    pub control: ControlConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ControlConfig {
    Grpc {
        endpoint: String,
    },
    Cli {
        get_routes_cmd: Vec<String>,
        routes_count_regex: String,
        get_peers_cmd: Vec<String>,
        peers_count_regex: String,
    },
}

pub struct Server {
    #[allow(dead_code)]
    daemon_process: Child,
    control: ControlMethod,
}

enum ControlMethod {
    Grpc(BgpClient),
    Cli {
        get_routes_cmd: Vec<String>,
        routes_count_regex: String,
        get_peers_cmd: Vec<String>,
        peers_count_regex: String,
    },
}

impl Server {
    pub async fn start(
        asn: u16,
        router_id: Ipv4Addr,
        bind_addr: String,
        grpc_port: u16,
        config: ServerConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Generate daemon config file
        let config_content = config
            .config_template
            .replace("{asn}", &asn.to_string())
            .replace("{router_id}", &router_id.to_string())
            .replace("{bind_addr}", &bind_addr)
            .replace("{port}", &bind_addr.split(':').last().unwrap())
            .replace("{grpc_port}", &grpc_port.to_string());

        let config_file = format!("/tmp/bgp_bench_hub_{}.toml", asn);
        std::fs::write(&config_file, config_content)?;

        // Spawn daemon with stderr redirected to avoid shutdown noise
        let args: Vec<String> = config
            .daemon_args
            .iter()
            .map(|arg| arg.replace("{config_file}", &config_file))
            .collect();

        let daemon_process = Command::new(&config.daemon_bin)
            .args(&args)
            .stderr(std::process::Stdio::null())
            .spawn()?;

        // Wait for daemon to be ready
        sleep(Duration::from_secs(2)).await;

        // Connect control method
        let control = match &config.control {
            ControlConfig::Grpc { endpoint } => {
                let endpoint = endpoint.replace("{grpc_port}", &grpc_port.to_string());
                let client = BgpClient::connect(endpoint).await?;
                ControlMethod::Grpc(client)
            }
            ControlConfig::Cli {
                get_routes_cmd,
                routes_count_regex,
                get_peers_cmd,
                peers_count_regex,
            } => ControlMethod::Cli {
                get_routes_cmd: get_routes_cmd.clone(),
                routes_count_regex: routes_count_regex.clone(),
                get_peers_cmd: get_peers_cmd.clone(),
                peers_count_regex: peers_count_regex.clone(),
            },
        };

        Ok(Self {
            daemon_process,
            control,
        })
    }

    pub async fn get_route_count(&self) -> Result<usize, Box<dyn std::error::Error>> {
        match &self.control {
            ControlMethod::Grpc(client) => {
                let routes = client.get_routes().await?;
                Ok(routes.len())
            }
            ControlMethod::Cli {
                get_routes_cmd,
                routes_count_regex,
                ..
            } => {
                let output = Command::new(&get_routes_cmd[0])
                    .args(&get_routes_cmd[1..])
                    .output()?;

                let stdout = String::from_utf8_lossy(&output.stdout);
                let re = regex::Regex::new(routes_count_regex)?;

                if let Some(cap) = re.captures(&stdout) {
                    if let Some(count_str) = cap.get(1) {
                        return Ok(count_str.as_str().parse()?);
                    }
                }

                Ok(0)
            }
        }
    }

    pub async fn get_peer_count(&self) -> Result<usize, Box<dyn std::error::Error>> {
        match &self.control {
            ControlMethod::Grpc(client) => {
                let peers = client.get_peers().await?;
                Ok(peers.len())
            }
            ControlMethod::Cli {
                get_peers_cmd,
                peers_count_regex,
                ..
            } => {
                let output = Command::new(&get_peers_cmd[0])
                    .args(&get_peers_cmd[1..])
                    .output()?;

                let stdout = String::from_utf8_lossy(&output.stdout);
                let re = regex::Regex::new(peers_count_regex)?;

                if let Some(cap) = re.captures(&stdout) {
                    if let Some(count_str) = cap.get(1) {
                        return Ok(count_str.as_str().parse()?);
                    }
                }

                Ok(0)
            }
        }
    }

    pub async fn add_peer(
        &mut self,
        addr: String,
        config: Option<SessionConfig>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match &mut self.control {
            ControlMethod::Grpc(client) => {
                client.add_peer(addr, config).await?;
                Ok(())
            }
            ControlMethod::Cli { .. } => Err("add_peer not supported for CLI control".into()),
        }
    }

    pub fn shutdown(mut self) {
        let _ = self.daemon_process.kill();
        let _ = self.daemon_process.wait();
    }
}
