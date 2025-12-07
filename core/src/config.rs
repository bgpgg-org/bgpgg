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

use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub asn: u16,
    pub listen_addr: String,
    pub router_id: Ipv4Addr,
    #[serde(default = "default_grpc_listen_addr")]
    pub grpc_listen_addr: String,
    #[serde(default = "default_hold_time")]
    pub hold_time_secs: u64,
    #[serde(default = "default_connect_retry_time")]
    pub connect_retry_secs: u64,
}

fn default_grpc_listen_addr() -> String {
    "[::1]:50051".to_string()
}

fn default_hold_time() -> u64 {
    180
}

fn default_connect_retry_time() -> u64 {
    30 // RFC suggests 120s, but 30s is more practical
}

impl Config {
    /// Create a new configuration
    pub fn new(asn: u16, listen_addr: &str, router_id: Ipv4Addr, hold_time_secs: u64) -> Self {
        Config {
            asn,
            listen_addr: listen_addr.to_string(),
            router_id,
            grpc_listen_addr: "[::1]:50051".to_string(),
            hold_time_secs,
            connect_retry_secs: default_connect_retry_time(),
        }
    }

    /// Load configuration from a YAML file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&contents)?)
    }

    /// Get the local bind address for outgoing connections (IP with port 0)
    pub fn get_local_addr(&self) -> Result<SocketAddr, String> {
        let local_ip = self
            .listen_addr
            .split(':')
            .next()
            .ok_or_else(|| "invalid listen_addr format".to_string())?;

        format!("{}:0", local_ip)
            .parse()
            .map_err(|e| format!("failed to parse local bind address: {}", e))
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            asn: 65000,
            listen_addr: "127.0.0.1:179".to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            grpc_listen_addr: "[::1]:50051".to_string(),
            hold_time_secs: default_hold_time(),
            connect_retry_secs: default_connect_retry_time(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_yaml(name: &str, content: &str) -> String {
        let temp_file = std::env::temp_dir().join(name);
        let mut file = std::fs::File::create(&temp_file).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        temp_file.to_str().unwrap().to_string()
    }

    #[test]
    fn test_config_new() {
        let config = Config::new(65100, "192.168.1.1:179", Ipv4Addr::new(192, 168, 1, 1), 180);
        assert_eq!(config.asn, 65100);
        assert_eq!(config.listen_addr, "192.168.1.1:179");
        assert_eq!(config.router_id, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.hold_time_secs, 180);
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.asn, 65000);
        assert_eq!(config.listen_addr, "127.0.0.1:179");
        assert_eq!(config.router_id, Ipv4Addr::new(1, 1, 1, 1));
    }

    #[test]
    fn test_config_from_file() {
        let temp_file = write_temp_yaml(
            "test_config.yaml",
            "asn: 65200\nlisten_addr: \"10.0.0.1:179\"\nrouter_id: \"10.0.0.1\"\n",
        );

        let config = Config::from_file(&temp_file).unwrap();
        assert_eq!(config.asn, 65200);
        assert_eq!(config.listen_addr, "10.0.0.1:179");
        assert_eq!(config.router_id, Ipv4Addr::new(10, 0, 0, 1));

        std::fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn test_config_from_file_not_found() {
        let result = Config::from_file("/nonexistent/path.yaml");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_from_file_invalid_yaml() {
        let temp_file = write_temp_yaml(
            "test_config_invalid.yaml",
            "asn: not_a_number\nlisten_addr: \"10.0.0.1:179\"\n",
        );

        let result = Config::from_file(&temp_file);
        assert!(result.is_err());

        std::fs::remove_file(temp_file).unwrap();
    }
}
