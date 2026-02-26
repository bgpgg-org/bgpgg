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

/// Graceful Restart configuration (RFC 4724)
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct GracefulRestartConfig {
    /// Enable Graceful Restart (default: true)
    #[serde(default = "default_gr_enabled")]
    pub enabled: bool,
    /// Restart time in seconds (default: 120, max: 4095)
    #[serde(default = "default_gr_restart_time")]
    pub restart_time: u16,
}

fn default_gr_enabled() -> bool {
    true
}

fn default_gr_restart_time() -> u16 {
    120
}

impl Default for GracefulRestartConfig {
    fn default() -> Self {
        Self {
            enabled: default_gr_enabled(),
            restart_time: default_gr_restart_time(),
        }
    }
}

/// RFC 7911: ADD-PATH send mode
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddPathSend {
    /// Do not send multiple paths (default)
    #[default]
    Disabled,
    /// Send all paths for each prefix
    All,
}

/// Peer configuration in YAML config file.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct PeerConfig {
    /// Peer IP address (IPv4 or IPv6).
    #[serde(default)]
    pub address: String,
    /// Remote BGP port (default: 179).
    #[serde(default = "default_port")]
    pub port: u16,
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
    /// MinRouteAdvertisementIntervalTimer - minimum seconds between route advertisements (RFC 4271 9.2.1.1).
    /// Default: 30 seconds for eBGP, 5 seconds for iBGP (or disabled for iBGP).
    #[serde(default)]
    pub min_route_advertisement_interval_secs: Option<u64>,
    /// List of import policy names to apply (evaluated in order)
    #[serde(default)]
    pub import_policy: Vec<String>,
    /// List of export policy names to apply (evaluated in order)
    #[serde(default)]
    pub export_policy: Vec<String>,
    /// Graceful Restart configuration (RFC 4724)
    #[serde(default)]
    pub graceful_restart: GracefulRestartConfig,
    /// RFC 4456: Mark this peer as a route reflector client
    #[serde(default)]
    pub rr_client: bool,
    /// RFC 7947: Mark this peer as a route server client (transparency mode)
    #[serde(default)]
    pub rs_client: bool,
    /// RFC 4271 Section 6.3: Enforce first AS in AS_PATH matches peer AS (default: true)
    #[serde(default = "default_enforce_first_as")]
    pub enforce_first_as: bool,
    /// RFC 7911: ADD-PATH send mode for this peer
    #[serde(default)]
    pub add_path_send: AddPathSend,
    /// RFC 7911: Whether to accept multiple paths from this peer
    #[serde(default)]
    pub add_path_receive: bool,
    /// Expected peer ASN. When set, OPEN messages with mismatched ASN are rejected.
    #[serde(default)]
    pub asn: Option<u32>,
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

fn default_enforce_first_as() -> bool {
    true
}

fn default_port() -> u16 {
    179
}

impl PeerConfig {
    /// Returns the socket address (IP + port) for this peer.
    pub fn socket_addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        let ip: IpAddr = self.address.parse()?;
        Ok(SocketAddr::new(ip, self.port))
    }

    /// Returns the DelayOpenTime as a Duration, or None if disabled.
    pub fn delay_open_time(&self) -> Option<Duration> {
        self.delay_open_time_secs.map(Duration::from_secs)
    }

    /// RFC 4271 8.1.2: AllowAutomaticStart is true if IdleHoldTimer is configured.
    pub fn allow_automatic_start(&self) -> bool {
        self.idle_hold_time_secs.is_some()
    }

    /// Validate peer configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.rr_client && self.rs_client {
            return Err("Peer cannot be both rr-client and rs-client".to_string());
        }
        Ok(())
    }
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            port: default_port(),
            idle_hold_time_secs: default_idle_hold_time(),
            damp_peer_oscillations: default_damp_peer_oscillations(),
            allow_automatic_stop: default_allow_automatic_stop(),
            passive_mode: default_passive_mode(),
            delay_open_time_secs: None,
            max_prefix: None,
            send_notification_without_open: false,
            min_route_advertisement_interval_secs: None,
            import_policy: Vec::new(),
            export_policy: Vec::new(),
            graceful_restart: GracefulRestartConfig::default(),
            rr_client: false,
            rs_client: false,
            enforce_first_as: default_enforce_first_as(),
            add_path_send: AddPathSend::default(),
            add_path_receive: false,
            asn: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BmpConfig {
    pub address: String,
    /// Statistics reporting interval in seconds. 0 or None disables statistics.
    #[serde(default)]
    pub statistics_timeout: Option<u64>,
}

/// Container for all defined sets used in policy matching (YAML representation)
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DefinedSetsConfig {
    #[serde(default)]
    pub prefix_sets: Vec<PrefixSetConfig>,
    #[serde(default)]
    pub neighbor_sets: Vec<NeighborSetConfig>,
    #[serde(default)]
    pub as_path_sets: Vec<AsPathSetConfig>,
    #[serde(default)]
    pub community_sets: Vec<CommunitySetConfig>,
    #[serde(default)]
    pub ext_community_sets: Vec<ExtCommunitySetConfig>,
    #[serde(default)]
    pub large_community_sets: Vec<LargeCommunitySetConfig>,
}

/// Named prefix set with masklength range support (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrefixSetConfig {
    pub name: String,
    pub prefixes: Vec<PrefixMatchConfig>,
}

/// Prefix with optional masklength range (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrefixMatchConfig {
    /// CIDR prefix like "10.0.0.0/8"
    pub prefix: String,
    /// Optional masklength range: "exact", "21..24", or "10.." for "le 10"
    #[serde(default)]
    pub masklength_range: Option<String>,
}

/// Named neighbor (IP address) set (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NeighborSetConfig {
    pub name: String,
    pub neighbors: Vec<String>, // IpAddr as strings
}

/// Named AS path set with regex patterns (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AsPathSetConfig {
    pub name: String,
    pub patterns: Vec<String>, // Regex patterns
}

/// Named community set (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommunitySetConfig {
    pub name: String,
    pub communities: Vec<String>, // "65000:100" format or decimal
}

/// Named extended community set (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtCommunitySetConfig {
    pub name: String,
    pub ext_communities: Vec<String>, // "rt:65000:100" or hex format
}

/// Named large community set (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LargeCommunitySetConfig {
    pub name: String,
    pub large_communities: Vec<String>, // "GA:LD1:LD2" format
}

/// Enum wrapper for any defined set config type (used in management API)
#[derive(Debug, Clone)]
pub enum DefinedSetConfig {
    PrefixSet(PrefixSetConfig),
    NeighborSet(NeighborSetConfig),
    AsPathSet(AsPathSetConfig),
    CommunitySet(CommunitySetConfig),
    ExtCommunitySet(ExtCommunitySetConfig),
    LargeCommunitySet(LargeCommunitySetConfig),
}

impl DefinedSetConfig {
    pub fn name(&self) -> &str {
        match self {
            DefinedSetConfig::PrefixSet(c) => &c.name,
            DefinedSetConfig::NeighborSet(c) => &c.name,
            DefinedSetConfig::AsPathSet(c) => &c.name,
            DefinedSetConfig::CommunitySet(c) => &c.name,
            DefinedSetConfig::ExtCommunitySet(c) => &c.name,
            DefinedSetConfig::LargeCommunitySet(c) => &c.name,
        }
    }

    pub fn set_type(&self) -> crate::policy::DefinedSetType {
        match self {
            DefinedSetConfig::PrefixSet(_) => crate::policy::DefinedSetType::PrefixSet,
            DefinedSetConfig::NeighborSet(_) => crate::policy::DefinedSetType::NeighborSet,
            DefinedSetConfig::AsPathSet(_) => crate::policy::DefinedSetType::AsPathSet,
            DefinedSetConfig::CommunitySet(_) => crate::policy::DefinedSetType::CommunitySet,
            DefinedSetConfig::ExtCommunitySet(_) => crate::policy::DefinedSetType::ExtCommunitySet,
            DefinedSetConfig::LargeCommunitySet(_) => {
                crate::policy::DefinedSetType::LargeCommunitySet
            }
        }
    }
}

/// Named policy definition from YAML config
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyDefinitionConfig {
    pub name: String,
    pub statements: Vec<StatementConfig>,
}

/// Statement definition from YAML
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatementConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub conditions: ConditionsConfig,
    pub actions: ActionsConfig,
}

/// Conditions that must match for a statement to apply
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConditionsConfig {
    // Set-based conditions (OpenConfig style)
    #[serde(default)]
    pub match_prefix_set: Option<MatchSetRefConfig>,
    #[serde(default)]
    pub match_neighbor_set: Option<MatchSetRefConfig>,
    #[serde(default)]
    pub match_as_path_set: Option<MatchSetRefConfig>,
    #[serde(default)]
    pub match_community_set: Option<MatchSetRefConfig>,
    #[serde(default)]
    pub match_ext_community_set: Option<MatchSetRefConfig>,
    #[serde(default)]
    pub match_large_community_set: Option<MatchSetRefConfig>,

    // Direct conditions (backward compatibility)
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub neighbor: Option<String>,
    #[serde(default)]
    pub has_asn: Option<u32>,
    #[serde(default)]
    pub route_type: Option<String>, // "ebgp", "ibgp", "local"
    #[serde(default)]
    pub community: Option<String>, // Single community value
}

/// Reference to a defined set with match option
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MatchSetRefConfig {
    pub set_name: String,
    #[serde(default = "default_match_option")]
    pub match_option: MatchOptionConfig,
}

fn default_match_option() -> MatchOptionConfig {
    MatchOptionConfig::Any
}

/// Match option for set-based conditions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchOptionConfig {
    /// At least one element in the set must match
    Any,
    /// All elements in the set must match
    All,
    /// No elements in the set must match (invert)
    Invert,
}

/// Actions to apply when conditions match
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ActionsConfig {
    #[serde(default)]
    pub accept: Option<bool>,
    #[serde(default)]
    pub reject: Option<bool>,
    #[serde(default)]
    pub local_pref: Option<LocalPrefActionConfig>,
    #[serde(default)]
    pub med: Option<MedActionConfig>,
    #[serde(default)]
    pub community: Option<CommunityActionConfig>,
    #[serde(default)]
    pub ext_community: Option<ExtCommunityActionConfig>,
    #[serde(default)]
    pub large_community: Option<LargeCommunityActionConfig>,
}

/// Local preference action
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum LocalPrefActionConfig {
    /// Simple set: local-pref: 200
    Set(u32),
    /// Force override: local-pref: { value: 200, force: true }
    Force { value: u32, force: bool },
}

/// MED action
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MedActionConfig {
    /// Simple set: med: 100
    Set(u32),
    /// Remove: med: { remove: true }
    Remove { remove: bool },
}

/// Community action
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommunityActionConfig {
    /// Operation: "add", "remove", "replace"
    pub operation: String,
    /// Community values to add/remove/replace
    pub communities: Vec<String>,
}

/// Extended Community action
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtCommunityActionConfig {
    /// Operation: "add", "remove", "replace"
    pub operation: String,
    /// Extended community values to add/remove/replace
    pub ext_communities: Vec<String>,
}

/// Large Community action
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LargeCommunityActionConfig {
    /// Operation: "add", "remove", "replace"
    pub operation: String,
    /// Large community values to add/remove/replace (format: "GA:LD1:LD2")
    pub large_communities: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub asn: u32,
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    pub router_id: Ipv4Addr,
    #[serde(default = "default_grpc_listen_addr")]
    pub grpc_listen_addr: String,
    #[serde(default = "default_hold_time")]
    pub hold_time_secs: u64,
    #[serde(default = "default_connect_retry_time")]
    pub connect_retry_secs: u64,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub bmp_servers: Vec<BmpConfig>,
    /// BMP sysName (RFC 7854). Defaults to "bgpgg {router_id}".
    #[serde(default)]
    pub sys_name: Option<String>,
    /// BMP sysDescr (RFC 7854). Defaults to "bgpgg version {VERSION}".
    #[serde(default)]
    pub sys_descr: Option<String>,
    /// Log level: "error", "warn", "info" (default), "debug"
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Defined sets for policy matching
    #[serde(default)]
    pub defined_sets: DefinedSetsConfig,
    /// Policy definitions
    #[serde(default)]
    pub policy_definitions: Vec<PolicyDefinitionConfig>,
    /// RFC 4456: Cluster ID for route reflector. Defaults to router_id if not set.
    #[serde(default)]
    pub cluster_id: Option<Ipv4Addr>,
}

fn default_listen_addr() -> String {
    "0.0.0.0:179".to_string()
}

fn default_grpc_listen_addr() -> String {
    "127.0.0.1:50051".to_string()
}

fn default_hold_time() -> u64 {
    180
}

fn default_connect_retry_time() -> u64 {
    30 // RFC suggests 120s, but 30s is more practical
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    /// Create a new configuration
    pub fn new(asn: u32, listen_addr: &str, router_id: Ipv4Addr, hold_time_secs: u64) -> Self {
        Config {
            asn,
            listen_addr: listen_addr.to_string(),
            router_id,
            grpc_listen_addr: default_grpc_listen_addr(),
            hold_time_secs,
            connect_retry_secs: default_connect_retry_time(),
            peers: Vec::new(),
            bmp_servers: Vec::new(),
            sys_name: None,
            sys_descr: None,
            log_level: default_log_level(),
            defined_sets: DefinedSetsConfig::default(),
            policy_definitions: Vec::new(),
            cluster_id: None,
        }
    }

    /// RFC 4456: Get effective cluster_id (defaults to router_id)
    pub fn cluster_id(&self) -> Ipv4Addr {
        self.cluster_id.unwrap_or(self.router_id)
    }

    /// Get BMP sysName (RFC 7854). Returns configured value or default.
    pub fn sys_name(&self) -> String {
        self.sys_name
            .clone()
            .unwrap_or_else(|| format!("bgpgg {}", self.router_id))
    }

    /// Get BMP sysDescr (RFC 7854). Returns configured value or default.
    pub fn sys_descr(&self) -> String {
        self.sys_descr
            .clone()
            .unwrap_or_else(|| format!("bgpgg version {}", env!("CARGO_PKG_VERSION")))
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
            listen_addr: "0.0.0.0:179".to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            grpc_listen_addr: default_grpc_listen_addr(),
            hold_time_secs: default_hold_time(),
            connect_retry_secs: default_connect_retry_time(),
            peers: Vec::new(),
            bmp_servers: Vec::new(),
            sys_name: None,
            sys_descr: None,
            log_level: default_log_level(),
            defined_sets: DefinedSetsConfig::default(),
            policy_definitions: Vec::new(),
            cluster_id: None,
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
        assert_eq!(config.listen_addr, "0.0.0.0:179");
        assert_eq!(config.router_id, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(config.grpc_listen_addr, "127.0.0.1:50051");
    }

    #[test]
    fn test_config_from_file() {
        let temp_file = write_temp_yaml(
            "test_config.yaml",
            "asn: 65200\nlisten-addr: \"10.0.0.1:179\"\nrouter-id: \"10.0.0.1\"\n",
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

    #[test]
    fn test_cluster_id() {
        let mut config = Config::new(65000, "0.0.0.0:179", Ipv4Addr::new(10, 0, 0, 1), 180);
        // Defaults to router_id
        assert_eq!(config.cluster_id(), Ipv4Addr::new(10, 0, 0, 1));
        // Can be overridden
        config.cluster_id = Some(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(config.cluster_id(), Ipv4Addr::new(1, 2, 3, 4));
    }

    #[test]
    fn test_rr_and_rs_conflict() {
        // Valid: only rr_client
        let peer = PeerConfig {
            rr_client: true,
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        // Valid: only rs_client
        let peer = PeerConfig {
            rs_client: true,
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        // Invalid: both rr_client and rs_client
        let peer = PeerConfig {
            rr_client: true,
            rs_client: true,
            ..Default::default()
        };
        let result = peer.validate();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Peer cannot be both rr-client and rs-client"
        );

        // Valid: neither set
        let peer = PeerConfig::default();
        assert!(peer.validate().is_ok());
    }
}
