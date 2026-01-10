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
    pub get_routes_cmd: Vec<String>,
    pub routes_count_regex: String,
}

pub struct Server {
    #[allow(dead_code)]
    daemon_process: Child,
    get_routes_cmd: Vec<String>,
    routes_count_regex: String,
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
        let bind_ip = bind_addr.split(':').next().unwrap();
        let bind_port = bind_addr.split(':').last().unwrap();
        let config_content = config
            .config_template
            .replace("{asn}", &asn.to_string())
            .replace("{router_id}", &router_id.to_string())
            .replace("{bind_addr}", &bind_addr)
            .replace("{bind_ip}", bind_ip)
            .replace("{port}", bind_port)
            .replace("{grpc_port}", &grpc_port.to_string());

        let config_file = format!("/tmp/bgp_bench_hub_{}.toml", asn);
        std::fs::write(&config_file, config_content)?;

        // Spawn daemon with stderr redirected to avoid shutdown noise
        let args: Vec<String> = config
            .daemon_args
            .iter()
            .map(|arg| {
                arg.replace("{config_file}", &config_file)
                    .replace("{grpc_port}", &grpc_port.to_string())
            })
            .collect();

        let daemon_process = Command::new(&config.daemon_bin)
            .args(&args)
            .stderr(std::process::Stdio::null())
            .spawn()?;

        // Wait for daemon to be ready
        sleep(Duration::from_secs(2)).await;

        // Substitute placeholders in CLI commands
        let get_routes_cmd: Vec<String> = config
            .get_routes_cmd
            .iter()
            .map(|arg| arg.replace("{grpc_port}", &grpc_port.to_string()))
            .collect();

        Ok(Self {
            daemon_process,
            get_routes_cmd,
            routes_count_regex: config.routes_count_regex,
        })
    }

    fn run_count_cmd(
        &self,
        cmd: &[String],
        regex: &str,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let output = Command::new(&cmd[0]).args(&cmd[1..]).output()?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        if !stderr.is_empty() {
            eprintln!("CLI stderr: {}", stderr);
        }
        if !output.status.success() {
            eprintln!("CLI failed with status: {:?}", output.status);
            eprintln!("CLI stdout: {}", stdout);
            return Ok(0);
        }

        let re = regex::Regex::new(regex)?;

        if let Some(cap) = re.captures(&stdout) {
            if let Some(count_str) = cap.get(1) {
                return Ok(count_str.as_str().parse()?);
            }
        }

        eprintln!("Regex '{}' didn't match stdout: {}", regex, stdout);
        Ok(0)
    }

    pub async fn get_route_count(&self) -> Result<usize, Box<dyn std::error::Error>> {
        self.run_count_cmd(&self.get_routes_cmd, &self.routes_count_regex)
    }

    pub fn shutdown(mut self) {
        let _ = self.daemon_process.kill();
        let _ = self.daemon_process.wait();
    }
}
