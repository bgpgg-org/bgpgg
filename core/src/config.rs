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

use crate::bgp::msg_open_types::LlgrEntry;
use crate::bgp::multiprotocol::{default_afi_safis, Afi, AfiSafi, Safi};
use crate::net::{bind_addr_from_ip, resolve_interface_index};
use crate::rpki::vrp::RpkiValidation;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tracing::error;

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

const MAX_LLGR_STALE_TIME: u32 = 0xFFFFFF; // 24-bit max

fn default_llgr_enabled() -> bool {
    true
}

/// RFC 9494: Long-Lived Graceful Restart configuration.
/// Used at both server level and per-peer level.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct LlgrConfig {
    /// Enable LLGR (default: true). Set to false to explicitly disable.
    #[serde(default = "default_llgr_enabled")]
    pub enabled: bool,
    /// Long-Lived Stale Time in seconds (24-bit max: 16777215)
    pub stale_time: Option<u32>,
    /// AFI/SAFIs to enable LLGR for. None = use default_afi_safis().
    #[serde(default)]
    pub afi_safis: Option<Vec<AfiSafi>>,
}

impl LlgrConfig {
    /// Convert to capability entries for OPEN message building.
    pub fn to_llgr_entries(&self) -> Vec<LlgrEntry> {
        let stale_time = self.stale_time.unwrap_or(0);
        let afi_safis = self.afi_safis.as_deref().unwrap_or(&[]);
        afi_safis
            .iter()
            .map(|afi_safi| LlgrEntry {
                afi_safi: *afi_safi,
                forwarding_preserved: false,
                stale_time,
            })
            .collect()
    }
}

/// Resolve LLGR config from server-level and peer-level settings.
/// - No server + no peer = disabled (None)
/// - Server + no peer = inherit server
/// - Peer enabled: false = disabled regardless of server
/// - Peer overrides server fields (stale_time, afi_safis)
pub fn get_peer_llgr(
    server_llgr: &Option<LlgrConfig>,
    peer_llgr: &Option<LlgrConfig>,
) -> Option<LlgrConfig> {
    let effective = match (server_llgr, peer_llgr) {
        (None, None) => return None,
        (Some(server), None) => server,
        (_, Some(peer)) => {
            if !peer.enabled {
                return None;
            }
            peer
        }
    };

    if !effective.enabled {
        return None;
    }

    Some(LlgrConfig {
        enabled: true,
        stale_time: effective.stale_time,
        afi_safis: Some(
            effective
                .afi_safis
                .clone()
                .unwrap_or_else(default_afi_safis),
        ),
    })
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

/// Per address-family configuration overrides.
/// Fields set to None inherit from the peer-level PeerConfig defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AfiSafiConfig {
    pub afi: Afi,
    pub safi: Safi,
    /// Override peer-level max_prefix for this family.
    #[serde(default)]
    pub max_prefix: Option<MaxPrefixSetting>,
    /// Override peer-level add_path_send for this family.
    #[serde(default)]
    pub add_path_send: Option<AddPathSend>,
}

impl AfiSafiConfig {
    /// Create a config entry with no overrides (just AFI/SAFI enablement).
    pub fn new(afi: Afi, safi: Safi) -> Self {
        Self {
            afi,
            safi,
            max_prefix: None,
            add_path_send: None,
        }
    }

    /// Return the plain AfiSafi for protocol-level use.
    pub fn afi_safi(&self) -> AfiSafi {
        AfiSafi::new(self.afi, self.safi)
    }
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
    /// Path to file containing TCP MD5 key (RFC 2385). File should be chmod 600.
    #[serde(default)]
    pub md5_key_file: Option<String>,
    /// Rewrite NEXT_HOP to local interface address when advertising to this peer.
    /// Useful for iBGP peers that lack a route to the original NEXT_HOP.
    #[serde(default)]
    pub next_hop_self: bool,
    /// RFC 8326: tag outbound routes with GRACEFUL_SHUTDOWN community (65535:0).
    /// Enable before taking the session down to let peers prefer alternate paths.
    #[serde(default)]
    pub graceful_shutdown: bool,
    /// RFC 5082: minimum inbound TTL for GTSM. None = disabled.
    /// 255 = directly connected peer, 254 = 1 hop away, etc.
    #[serde(default)]
    pub ttl_min: Option<u8>,
    /// Network interface for link-local IPv6 peers (e.g., "eth0").
    /// Required when address is a link-local IPv6 address (fe80::/10).
    #[serde(default)]
    pub interface: Option<String>,
    /// RFC 9494: Long-Lived Graceful Restart configuration
    #[serde(default)]
    pub llgr: Option<LlgrConfig>,
    /// RFC 8097: Attach RPKI Origin Validation State extended community on export
    #[serde(default)]
    pub send_rpki_community: bool,
    /// Additional AFI/SAFIs beyond default IPv4/IPv6 unicast (e.g. BGP-LS).
    /// Each entry can optionally override peer-level settings for that family.
    #[serde(default)]
    pub afi_safis: Vec<AfiSafiConfig>,
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

fn default_enhanced_rr_stale_ttl() -> Option<u64> {
    Some(360)
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

    /// Resolve the configured interface name to a kernel interface index.
    /// Returns None if no interface is configured.
    pub fn resolve_interface_index(&self) -> Option<io::Result<u32>> {
        self.interface
            .as_ref()
            .map(|iface| resolve_interface_index(iface))
    }

    /// Read MD5 key bytes from file, trimming whitespace/newlines.
    pub fn read_md5_key(&self) -> Option<Vec<u8>> {
        let path = self.md5_key_file.as_ref()?;
        match fs::read_to_string(path) {
            Ok(s) => Some(s.trim().as_bytes().to_vec()),
            Err(e) => {
                error!(peer_ip = %self.address, path = %path, error = %e, "failed to read MD5 key file");
                None
            }
        }
    }

    /// Extract plain AfiSafi list for protocol-level use (capability negotiation, etc.).
    pub fn afi_safi_list(&self) -> Vec<AfiSafi> {
        self.afi_safis.iter().map(|c| c.afi_safi()).collect()
    }

    /// Get the effective max_prefix setting for a given address family.
    /// Returns the per-family override if present, else the peer-level default.
    pub fn effective_max_prefix(&self, family: &AfiSafi) -> Option<MaxPrefixSetting> {
        self.afi_safis
            .iter()
            .find(|c| c.afi == family.afi && c.safi == family.safi)
            .and_then(|c| c.max_prefix)
            .or(self.max_prefix)
    }

    /// Validate peer configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.rr_client && self.rs_client {
            return Err("Peer cannot be both rr-client and rs-client".to_string());
        }
        // RFC 7947 2.3.2.2.2: Route server enforces send-only ADD-PATH mode with clients.
        if self.rs_client && self.add_path_receive {
            return Err(
                "rs-client peers must not use add-path-receive (route server uses send-only ADD-PATH mode per RFC 7947)".to_string(),
            );
        }
        if let Some(llgr) = &self.llgr {
            if let Some(stale_time) = llgr.stale_time {
                if stale_time > MAX_LLGR_STALE_TIME {
                    return Err(format!(
                        "LLGR stale_time {} exceeds 24-bit maximum ({})",
                        stale_time, MAX_LLGR_STALE_TIME
                    ));
                }
            }
            if llgr.enabled && !self.graceful_restart.enabled {
                return Err(
                    "LLGR requires graceful-restart to be enabled (RFC 9494 Section 4.5)"
                        .to_string(),
                );
            }
        }
        // Reject duplicate AFI/SAFI entries
        let mut seen = HashSet::new();
        for entry in &self.afi_safis {
            if !seen.insert((entry.afi, entry.safi)) {
                return Err(format!(
                    "duplicate afi-safis entry: {}/{}",
                    entry.afi, entry.safi
                ));
            }
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
            md5_key_file: None,
            next_hop_self: false,
            graceful_shutdown: false,
            ttl_min: None,
            interface: None,
            llgr: None,
            send_rpki_community: false,
            afi_safis: Vec::new(),
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

/// Transport type for RTR cache connections.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TransportType {
    #[default]
    Tcp,
    Ssh,
}

/// Configuration for an RPKI cache server (RTR, RFC 8210).
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RpkiCacheConfig {
    /// Address in "host:port" format (e.g. "127.0.0.1:8282").
    pub address: String,
    /// Preference tier. Lower values are preferred; only the lowest tier is active at startup.
    #[serde(default)]
    pub preference: u8,
    /// Transport type: "tcp" (default) or "ssh".
    #[serde(default)]
    pub transport: TransportType,
    /// SSH username (required when transport is "ssh").
    #[serde(default)]
    pub ssh_username: Option<String>,
    /// Path to SSH private key file (required when transport is "ssh").
    #[serde(default)]
    pub ssh_private_key_file: Option<String>,
    /// Path to OpenSSH known_hosts file. If omitted, host key is accepted without verification.
    #[serde(default)]
    pub ssh_known_hosts_file: Option<String>,
    /// Override cache-provided retry interval (seconds).
    #[serde(default)]
    pub retry_interval: Option<u64>,
    /// Override cache-provided refresh interval (seconds).
    #[serde(default)]
    pub refresh_interval: Option<u64>,
    /// Override cache-provided expire interval (seconds).
    #[serde(default)]
    pub expire_interval: Option<u64>,
}

impl RpkiCacheConfig {
    /// Convert transport config fields to runtime RtrTransport.
    /// Returns None with an error message if SSH fields are missing.
    pub fn to_rtr_transport(&self) -> Result<crate::rpki::manager::RtrTransport, String> {
        use crate::rpki::manager::{RtrTransport, SshTransport};
        match self.transport {
            TransportType::Tcp => Ok(RtrTransport::Tcp),
            TransportType::Ssh => {
                let username = self
                    .ssh_username
                    .as_ref()
                    .ok_or("SSH transport requires ssh-username")?;
                let private_key_file = self
                    .ssh_private_key_file
                    .as_ref()
                    .ok_or("SSH transport requires ssh-private-key-file")?;
                Ok(RtrTransport::Ssh(SshTransport {
                    username: username.clone(),
                    private_key_file: private_key_file.clone(),
                    known_hosts_file: self.ssh_known_hosts_file.clone(),
                }))
            }
        }
    }
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
    #[serde(default)]
    pub rpki_validation: Option<RpkiValidationConfig>,

    // Address family condition
    #[serde(default)]
    pub afi_safi: Option<String>,

    // BGP-LS conditions
    #[serde(default)]
    pub ls_nlri_type: Option<String>,
    #[serde(default)]
    pub ls_protocol_id: Option<String>,
    #[serde(default)]
    pub ls_instance_id: Option<u64>,
    #[serde(default)]
    pub ls_node_as: Option<u32>,
    #[serde(default)]
    pub ls_node_router_id: Option<String>,
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

/// RFC 6811: RPKI validation state for policy config
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RpkiValidationConfig {
    Valid,
    Invalid,
    NotFound,
}

impl From<RpkiValidationConfig> for RpkiValidation {
    fn from(config: RpkiValidationConfig) -> Self {
        match config {
            RpkiValidationConfig::Valid => RpkiValidation::Valid,
            RpkiValidationConfig::Invalid => RpkiValidation::Invalid,
            RpkiValidationConfig::NotFound => RpkiValidation::NotFound,
        }
    }
}

impl From<RpkiValidation> for RpkiValidationConfig {
    fn from(state: RpkiValidation) -> Self {
        match state {
            RpkiValidation::Valid => RpkiValidationConfig::Valid,
            RpkiValidation::Invalid => RpkiValidationConfig::Invalid,
            RpkiValidation::NotFound => RpkiValidationConfig::NotFound,
        }
    }
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
    #[serde(default)]
    pub set_rpki_state: Option<RpkiValidationConfig>,
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

/// BGP-LS operational configuration (RFC 9552).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BgpLsConfig {
    /// Maximum number of LS NLRIs in Loc-RIB. 0 = unlimited.
    #[serde(default)]
    pub max_ls_entries: u32,
    /// RFC 9552 Section 8.2.3: BGP-LS Instance-ID applied to locally originated NLRIs.
    #[serde(default)]
    pub instance_id: u64,
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
    /// RPKI cache servers for RTR (RFC 8210).
    #[serde(default)]
    pub rpki_caches: Vec<RpkiCacheConfig>,
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
    /// RFC 9494: Server-level LLGR configuration. Peers inherit this unless overridden.
    #[serde(default)]
    pub llgr: Option<LlgrConfig>,
    /// RFC 7313: Max seconds to retain stale routes after BoRR. None = no limit.
    #[serde(default = "default_enhanced_rr_stale_ttl")]
    pub enhanced_rr_stale_ttl: Option<u64>,
    /// BGP-LS operational configuration (RFC 9552).
    #[serde(default)]
    pub bgp_ls: BgpLsConfig,
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
            rpki_caches: Vec::new(),
            sys_name: None,
            sys_descr: None,
            log_level: default_log_level(),
            defined_sets: DefinedSetsConfig::default(),
            policy_definitions: Vec::new(),
            cluster_id: None,
            llgr: None,
            enhanced_rr_stale_ttl: default_enhanced_rr_stale_ttl(),
            bgp_ls: BgpLsConfig::default(),
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
            rpki_caches: Vec::new(),
            sys_name: None,
            sys_descr: None,
            log_level: default_log_level(),
            defined_sets: DefinedSetsConfig::default(),
            policy_definitions: Vec::new(),
            cluster_id: None,
            llgr: None,
            enhanced_rr_stale_ttl: default_enhanced_rr_stale_ttl(),
            bgp_ls: BgpLsConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs::{self, File};
    use std::io::Write;

    fn write_temp_yaml(name: &str, content: &str) -> String {
        let temp_file = env::temp_dir().join(name);
        let mut file = File::create(&temp_file).unwrap();
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

        fs::remove_file(temp_file).unwrap();
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

        fs::remove_file(temp_file).unwrap();
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
    fn test_peer_config_md5_key_file_deserialization() {
        let peer: PeerConfig =
            serde_yaml::from_str("address: \"10.0.0.1\"\nmd5-key-file: \"/etc/bgp/md5.key\"\n")
                .unwrap();
        assert_eq!(peer.md5_key_file, Some("/etc/bgp/md5.key".to_string()));

        // Default: None when not specified
        let peer: PeerConfig = serde_yaml::from_str("address: \"10.0.0.1\"\n").unwrap();
        assert!(peer.md5_key_file.is_none());
    }

    #[test]
    fn test_read_md5_key() {
        let temp_path = env::temp_dir().join("test_bgp_md5.key");
        let mut file = File::create(&temp_path).unwrap();
        writeln!(file, "my-secret-key").unwrap();

        let peer = PeerConfig {
            md5_key_file: Some(temp_path.to_str().unwrap().to_string()),
            ..Default::default()
        };

        let key = peer.read_md5_key().unwrap();
        assert_eq!(key, b"my-secret-key");

        // None when md5_key_file is not set
        let peer = PeerConfig::default();
        assert!(peer.read_md5_key().is_none());

        fs::remove_file(temp_path).unwrap();
    }

    #[test]
    fn test_read_md5_key_missing_file() {
        let peer = PeerConfig {
            md5_key_file: Some("/nonexistent/path/bgp_md5.key".to_string()),
            ..Default::default()
        };
        assert!(peer.read_md5_key().is_none());
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

    #[test]
    fn test_rs_client_rejects_add_path_receive() {
        // Valid: rs_client without add_path_receive
        let peer = PeerConfig {
            rs_client: true,
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        // Valid: add_path_receive without rs_client
        let peer = PeerConfig {
            add_path_receive: true,
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        // Invalid: rs_client with add_path_receive
        let peer = PeerConfig {
            rs_client: true,
            add_path_receive: true,
            ..Default::default()
        };
        let result = peer.validate();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "rs-client peers must not use add-path-receive (route server uses send-only ADD-PATH mode per RFC 7947)"
        );
    }

    #[test]
    fn test_llgr_stale_time_validation() {
        let cases = [
            (0, true),
            (3600, true),
            (0xFFFFFF, true),      // 24-bit max
            (0xFFFFFF + 1, false), // exceeds 24-bit
            (u32::MAX, false),
        ];
        for (stale_time, should_ok) in cases {
            let peer = PeerConfig {
                llgr: Some(LlgrConfig {
                    enabled: true,
                    stale_time: Some(stale_time),
                    afi_safis: None,
                }),
                ..Default::default()
            };
            assert_eq!(
                peer.validate().is_ok(),
                should_ok,
                "stale_time={stale_time} expected ok={should_ok}"
            );
        }
    }

    #[test]
    fn test_llgr_requires_graceful_restart() {
        // LLGR with GR enabled -> ok
        let peer = PeerConfig {
            llgr: Some(LlgrConfig {
                enabled: true,
                stale_time: Some(3600),
                afi_safis: None,
            }),
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        // LLGR with GR disabled -> error
        let peer = PeerConfig {
            graceful_restart: GracefulRestartConfig {
                enabled: false,
                ..Default::default()
            },
            llgr: Some(LlgrConfig {
                enabled: true,
                stale_time: Some(3600),
                afi_safis: None,
            }),
            ..Default::default()
        };
        let result = peer.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("LLGR requires graceful-restart"));
    }

    #[test]
    fn test_llgr_disabled_skips_gr_check() {
        // LLGR explicitly disabled with GR disabled -> ok (no conflict)
        let peer = PeerConfig {
            graceful_restart: GracefulRestartConfig {
                enabled: false,
                ..Default::default()
            },
            llgr: Some(LlgrConfig {
                enabled: false,
                stale_time: Some(3600),
                afi_safis: None,
            }),
            ..Default::default()
        };
        assert!(peer.validate().is_ok());
    }

    #[test]
    fn test_get_peer_llgr() {
        use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};

        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);

        // No server + no peer = disabled
        assert!(get_peer_llgr(&None, &None).is_none());

        // Server configured, no peer override = inherit
        let server = Some(LlgrConfig {
            enabled: true,
            stale_time: Some(3600),
            afi_safis: Some(vec![ipv4_unicast]),
        });
        let merged = get_peer_llgr(&server, &None).expect("should be enabled");
        assert_eq!(merged.stale_time, Some(3600));
        assert_eq!(merged.afi_safis, Some(vec![ipv4_unicast]));

        // Peer override with different stale_time
        let peer = Some(LlgrConfig {
            enabled: true,
            stale_time: Some(7200),
            afi_safis: Some(vec![ipv4_unicast]),
        });
        let merged = get_peer_llgr(&server, &peer).expect("should be enabled");
        assert_eq!(merged.stale_time, Some(7200));
        assert_eq!(merged.afi_safis, Some(vec![ipv4_unicast]));

        // Peer disabled overrides server
        let peer_disabled = Some(LlgrConfig {
            enabled: false,
            stale_time: None,
            afi_safis: None,
        });
        assert!(get_peer_llgr(&server, &peer_disabled).is_none());
    }

    #[test]
    fn test_llgr_yaml_deserialization() {
        use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};

        let yaml = r#"
llgr:
  stale-time: 3600
  afi-safis:
    - afi: 1
      safi: 1
    - afi: 2
      safi: 1
"#;
        #[derive(Deserialize)]
        struct Wrapper {
            llgr: Option<LlgrConfig>,
        }
        let wrapper: Wrapper = serde_yaml::from_str(yaml).unwrap();
        let llgr = wrapper.llgr.unwrap();
        assert!(llgr.enabled); // default true
        assert_eq!(llgr.stale_time, Some(3600));
        let afi_safis = llgr.afi_safis.unwrap();
        assert_eq!(afi_safis.len(), 2);
        assert_eq!(afi_safis[0], AfiSafi::new(Afi::Ipv4, Safi::Unicast));
        assert_eq!(afi_safis[1], AfiSafi::new(Afi::Ipv6, Safi::Unicast));
    }

    #[test]
    fn test_rpki_cache_config_tcp_default() {
        let yaml = r#"
address: "127.0.0.1:8282"
preference: 1
"#;
        let cfg: RpkiCacheConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.address, "127.0.0.1:8282");
        assert_eq!(cfg.preference, 1);
        assert_eq!(cfg.transport, TransportType::Tcp);
        assert!(cfg.ssh_username.is_none());
        assert!(cfg.ssh_private_key_file.is_none());
    }

    #[test]
    fn test_rpki_cache_config_ssh() {
        let yaml = r#"
address: "10.0.0.2:22"
preference: 5
transport: ssh
ssh-username: rpki
ssh-private-key-file: /etc/bgp/rpki_ssh.key
ssh-known-hosts-file: /etc/bgp/known_hosts
"#;
        let cfg: RpkiCacheConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.address, "10.0.0.2:22");
        assert_eq!(cfg.preference, 5);
        assert_eq!(cfg.transport, TransportType::Ssh);
        assert_eq!(cfg.ssh_username.as_deref(), Some("rpki"));
        assert_eq!(
            cfg.ssh_private_key_file.as_deref(),
            Some("/etc/bgp/rpki_ssh.key")
        );
        assert_eq!(
            cfg.ssh_known_hosts_file.as_deref(),
            Some("/etc/bgp/known_hosts")
        );
    }

    #[test]
    fn test_rpki_cache_config_ssh_no_known_hosts() {
        let yaml = r#"
address: "10.0.0.2:22"
transport: ssh
ssh-username: rpki
ssh-private-key-file: /etc/bgp/rpki_ssh.key
"#;
        let cfg: RpkiCacheConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.transport, TransportType::Ssh);
        assert!(cfg.ssh_known_hosts_file.is_none());
    }

    #[test]
    fn test_effective_max_prefix() {
        let cases = vec![
            // (per-family override, peer-level, expected limit)
            (Some(500), Some(1000), Some(500)), // per-family wins
            (None, Some(1000), Some(1000)),     // fallback to peer-level
            (Some(500), None, Some(500)),       // per-family only
            (None, None, None),                 // both absent
        ];
        for (family_limit, peer_limit, expected_limit) in cases {
            let config = PeerConfig {
                max_prefix: peer_limit.map(|limit| MaxPrefixSetting {
                    limit,
                    action: MaxPrefixAction::Terminate,
                }),
                afi_safis: vec![AfiSafiConfig {
                    afi: Afi::LinkState,
                    safi: Safi::LinkState,
                    max_prefix: family_limit.map(|limit| MaxPrefixSetting {
                        limit,
                        action: MaxPrefixAction::Terminate,
                    }),
                    add_path_send: None,
                }],
                ..Default::default()
            };
            let ls_family = AfiSafi::new(Afi::LinkState, Safi::LinkState);
            let effective = config.effective_max_prefix(&ls_family);
            assert_eq!(
                effective.map(|s| s.limit),
                expected_limit,
                "family_limit={family_limit:?}, peer_limit={peer_limit:?}"
            );
        }
    }

    #[test]
    fn test_effective_max_prefix_different_families() {
        let config = PeerConfig {
            max_prefix: Some(MaxPrefixSetting {
                limit: 1000,
                action: MaxPrefixAction::Terminate,
            }),
            afi_safis: vec![AfiSafiConfig {
                afi: Afi::LinkState,
                safi: Safi::LinkState,
                max_prefix: Some(MaxPrefixSetting {
                    limit: 5000,
                    action: MaxPrefixAction::Discard,
                }),
                add_path_send: None,
            }],
            ..Default::default()
        };
        // LS family uses override
        let ls = AfiSafi::new(Afi::LinkState, Safi::LinkState);
        let ls_setting = config.effective_max_prefix(&ls).unwrap();
        assert_eq!(ls_setting.limit, 5000);
        assert!(matches!(ls_setting.action, MaxPrefixAction::Discard));

        // IPv4 family falls back to peer-level
        let ipv4 = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        let ipv4_setting = config.effective_max_prefix(&ipv4).unwrap();
        assert_eq!(ipv4_setting.limit, 1000);
        assert!(matches!(ipv4_setting.action, MaxPrefixAction::Terminate));
    }

    #[test]
    fn test_afi_safi_list() {
        let config = PeerConfig {
            afi_safis: vec![
                AfiSafiConfig::new(Afi::LinkState, Safi::LinkState),
                AfiSafiConfig::new(Afi::Ipv4, Safi::Unicast),
            ],
            ..Default::default()
        };
        let list = config.afi_safi_list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], AfiSafi::new(Afi::LinkState, Safi::LinkState));
        assert_eq!(list[1], AfiSafi::new(Afi::Ipv4, Safi::Unicast));
    }

    #[test]
    fn test_validate_duplicate_afi_safis() {
        let config = PeerConfig {
            afi_safis: vec![
                AfiSafiConfig::new(Afi::LinkState, Safi::LinkState),
                AfiSafiConfig::new(Afi::LinkState, Safi::LinkState),
            ],
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate"));
    }

    #[test]
    fn test_afi_safi_config_yaml_deserialization() {
        // New format with per-family overrides
        let yaml = r#"
address: "10.0.0.1"
afi-safis:
  - afi: 16388
    safi: 71
    max-prefix:
      limit: 5000
      action: discard
  - afi: 1
    safi: 1
    add-path-send: all
"#;
        let config: PeerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.afi_safis.len(), 2);

        let ls = &config.afi_safis[0];
        assert_eq!(ls.afi, Afi::LinkState);
        assert_eq!(ls.safi, Safi::LinkState);
        assert_eq!(ls.max_prefix.unwrap().limit, 5000);
        assert!(matches!(
            ls.max_prefix.unwrap().action,
            MaxPrefixAction::Discard
        ));

        let ipv4 = &config.afi_safis[1];
        assert_eq!(ipv4.afi, Afi::Ipv4);
        assert_eq!(ipv4.safi, Safi::Unicast);
        assert!(matches!(ipv4.add_path_send, Some(AddPathSend::All)));
    }

    #[test]
    fn test_afi_safi_config_yaml_minimal() {
        // Backward-compatible: just afi/safi, no overrides
        let yaml = r#"
address: "10.0.0.1"
afi-safis:
  - afi: 16388
    safi: 71
"#;
        let config: PeerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.afi_safis.len(), 1);
        assert_eq!(config.afi_safis[0].afi, Afi::LinkState);
        assert!(config.afi_safis[0].max_prefix.is_none());
        assert!(config.afi_safis[0].add_path_send.is_none());
    }

    #[test]
    fn test_bgp_ls_config_default() {
        let config = Config::default();
        assert_eq!(config.bgp_ls.max_ls_entries, 0);
    }

    #[test]
    fn test_bgp_ls_config_yaml() {
        let yaml = r#"
asn: 65000
router-id: 1.1.1.1
bgp-ls:
  max-ls-entries: 50000
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.bgp_ls.max_ls_entries, 50000);
    }
}
