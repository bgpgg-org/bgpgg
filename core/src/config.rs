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

use crate::net::bind_addr_from_ip;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Action to take when max prefix limit is reached
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MaxPrefixAction {
    /// Send CEASE notification and close the session
    Terminate,
    /// Discard new prefixes but keep the session
    Discard,
}

/// Max prefix limit configuration
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct MaxPrefixSetting {
    pub limit: u32,
    #[serde(default = "default_max_prefix_action")]
    pub action: MaxPrefixAction,
}

fn default_max_prefix_action() -> MaxPrefixAction {
    MaxPrefixAction::Terminate
}

/// Peer configuration in YAML config file.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerConfig {
    #[serde(default)]
    pub address: String,
    /// IdleHoldTime - delay before automatic restart (RFC 4271 8.1.1).
    /// None disables automatic restart. Some(0) = immediate restart. Some(n) = restart after n seconds.
    #[serde(default = "default_idle_hold_time")]
    pub idle_hold_time_secs: Option<u64>,
    #[serde(default = "default_damp_peer_oscillations")]
    pub damp_peer_oscillations: bool,
    #[serde(default = "default_allow_automatic_stop")]
    pub allow_automatic_stop: bool,
    #[serde(default = "default_passive_mode")]
    pub passive_mode: bool,
    /// DelayOpenTime - seconds to wait before sending OPEN (RFC 4271 8.1.1).
    /// None disables DelayOpen, Some(secs) enables it with given delay.
    #[serde(default)]
    pub delay_open_time_secs: Option<u64>,
    #[serde(default)]
    pub max_prefix: Option<MaxPrefixSetting>,
    /// SendNOTIFICATIONwithoutOPEN - allow sending NOTIFICATION before OPEN (RFC 4271 8.2.1.5).
    /// Default false: OPEN must be sent before NOTIFICATION.
    #[serde(default)]
    pub send_notification_without_open: bool,
    /// CollisionDetectEstablishedState - process collisions in Established state (RFC 4271 8.1.1).
    /// Default false: collision detection is ignored when peer is in Established state.
    #[serde(default)]
    pub collision_detect_established_state: bool,
    /// MinRouteAdvertisementIntervalTimer - minimum seconds between route advertisements (RFC 4271 9.2.1.1).
    /// Default: 30 seconds for eBGP, 5 seconds for iBGP (or disabled for iBGP).
    #[serde(default)]
    pub min_route_advertisement_interval_secs: Option<u64>,
}

fn default_idle_hold_time() -> Option<u64> {
    Some(30)
}

fn default_damp_peer_oscillations() -> bool {
    true
}

fn default_allow_automatic_stop() -> bool {
    true
}

fn default_passive_mode() -> bool {
    false
}

impl PeerConfig {
    /// Returns the DelayOpenTime as a Duration, or None if disabled.
    pub fn delay_open_time(&self) -> Option<Duration> {
        self.delay_open_time_secs.map(Duration::from_secs)
    }

    /// RFC 4271 8.1.2: AllowAutomaticStart is true if IdleHoldTimer is configured.
    pub fn allow_automatic_start(&self) -> bool {
        self.idle_hold_time_secs.is_some()
    }
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            idle_hold_time_secs: default_idle_hold_time(),
            damp_peer_oscillations: default_damp_peer_oscillations(),
            allow_automatic_stop: default_allow_automatic_stop(),
            passive_mode: default_passive_mode(),
            delay_open_time_secs: None,
            max_prefix: None,
            send_notification_without_open: false,
            collision_detect_established_state: false,
            min_route_advertisement_interval_secs: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BmpConfig {
    pub address: String,
}

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
    /// Accept connections from unconfigured peers (RFC 4271 8.1.1).
    /// Security implications: see RFC 4272.
    #[serde(default)]
    pub accept_unconfigured_peers: bool,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub bmp_servers: Vec<BmpConfig>,
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
    pub fn new(
        asn: u16,
        listen_addr: &str,
        router_id: Ipv4Addr,
        hold_time_secs: u64,
        accept_unconfigured_peers: bool,
    ) -> Self {
        Config {
            asn,
            listen_addr: listen_addr.to_string(),
            router_id,
            grpc_listen_addr: "[::1]:50051".to_string(),
            hold_time_secs,
            connect_retry_secs: default_connect_retry_time(),
            accept_unconfigured_peers,
            peers: Vec::new(),
            bmp_servers: Vec::new(),
        }
    }

    /// Load configuration from a YAML file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&contents)?)
    }

    /// Get the local bind address for outgoing connections (IP with port 0)
    pub fn local_addr(&self) -> Result<SocketAddr, String> {
        let local_ip = self
            .listen_addr
            .split(':')
            .next()
            .ok_or_else(|| "invalid listen_addr format".to_string())?;

        let ip: IpAddr = local_ip
            .parse()
            .map_err(|e| format!("failed to parse IP address: {}", e))?;

        Ok(bind_addr_from_ip(ip))
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
            accept_unconfigured_peers: false,
            peers: Vec::new(),
            bmp_servers: Vec::new(),
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
        let config = Config::new(
            65100,
            "192.168.1.1:179",
            Ipv4Addr::new(192, 168, 1, 1),
            180,
            false,
        );
        assert_eq!(config.asn, 65100);
        assert_eq!(config.listen_addr, "192.168.1.1:179");
        assert_eq!(config.router_id, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.hold_time_secs, 180);
        assert!(!config.accept_unconfigured_peers);

        let config = Config::new(
            65100,
            "192.168.1.1:179",
            Ipv4Addr::new(192, 168, 1, 1),
            180,
            true,
        );
        assert!(config.accept_unconfigured_peers);
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.asn, 65000);
        assert_eq!(config.listen_addr, "127.0.0.1:179");
        assert_eq!(config.router_id, Ipv4Addr::new(1, 1, 1, 1));
        assert!(!config.accept_unconfigured_peers);
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
        assert!(!config.accept_unconfigured_peers); // default

        std::fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn test_config_accept_unconfigured_peers_from_yaml() {
        let temp_file = write_temp_yaml(
            "test_config_unconfigured.yaml",
            "asn: 65200\nlisten_addr: \"10.0.0.1:179\"\nrouter_id: \"10.0.0.1\"\naccept_unconfigured_peers: true\n",
        );

        let config = Config::from_file(&temp_file).unwrap();
        assert!(config.accept_unconfigured_peers);

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
