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
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tracing::error;

/// Error returned when an AFI or SAFI numeric value is unrecognized.
#[derive(Debug, Clone)]
pub struct AfiSafiError {
    pub kind: &'static str,
    pub value: u32,
}

impl fmt::Display for AfiSafiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown {}: {}", self.kind, self.value)
    }
}

impl std::error::Error for AfiSafiError {}

/// Address Family Identifier per IANA registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2,
    LinkState = 16388,
}

impl Serialize for Afi {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(*self as u16)
    }
}

impl<'de> Deserialize<'de> for Afi {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u16::deserialize(deserializer)?;
        Afi::try_from(value).map_err(|_| serde::de::Error::custom(format!("unknown AFI: {value}")))
    }
}

impl fmt::Display for Afi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Afi::Ipv4 => write!(f, "IPv4"),
            Afi::Ipv6 => write!(f, "IPv6"),
            Afi::LinkState => write!(f, "LinkState"),
        }
    }
}

impl TryFrom<u16> for Afi {
    type Error = AfiSafiError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Afi::Ipv4),
            2 => Ok(Afi::Ipv6),
            16388 => Ok(Afi::LinkState),
            _ => Err(AfiSafiError {
                kind: "AFI",
                value: value as u32,
            }),
        }
    }
}

impl std::str::FromStr for Afi {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ipv4" => Ok(Afi::Ipv4),
            "ipv6" => Ok(Afi::Ipv6),
            "ls" => Ok(Afi::LinkState),
            _ => Err(format!("expected ipv4|ipv6|ls, got '{}'", s)),
        }
    }
}

/// Subsequent Address Family Identifier per IANA registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Safi {
    Unicast = 1,
    Multicast = 2,
    MplsLabel = 4,
    LinkState = 71,
    LinkStateVpn = 72,
}

impl From<Safi> for u8 {
    fn from(safi: Safi) -> u8 {
        safi as u8
    }
}

impl Serialize for Safi {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for Safi {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u8::deserialize(deserializer)?;
        Safi::try_from(value)
            .map_err(|_| serde::de::Error::custom(format!("unknown SAFI: {value}")))
    }
}

impl fmt::Display for Safi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Safi::Unicast => write!(f, "Unicast"),
            Safi::Multicast => write!(f, "Multicast"),
            Safi::MplsLabel => write!(f, "MPLS-labeled"),
            Safi::LinkState => write!(f, "LinkState"),
            Safi::LinkStateVpn => write!(f, "LinkState-VPN"),
        }
    }
}

impl std::str::FromStr for Safi {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unicast" => Ok(Safi::Unicast),
            "multicast" => Ok(Safi::Multicast),
            "mpls-label" => Ok(Safi::MplsLabel),
            "link-state" => Ok(Safi::LinkState),
            "link-state-vpn" => Ok(Safi::LinkStateVpn),
            _ => Err(format!(
                "expected unicast|multicast|mpls-label|link-state|link-state-vpn, got '{}'",
                s
            )),
        }
    }
}

impl TryFrom<u8> for Safi {
    type Error = AfiSafiError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Safi::Unicast),
            2 => Ok(Safi::Multicast),
            4 => Ok(Safi::MplsLabel),
            71 => Ok(Safi::LinkState),
            72 => Ok(Safi::LinkStateVpn),
            _ => Err(AfiSafiError {
                kind: "SAFI",
                value: value as u32,
            }),
        }
    }
}

/// Combined AFI/SAFI for capability tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AfiSafi {
    pub afi: Afi,
    pub safi: Safi,
}

impl AfiSafi {
    pub fn new(afi: Afi, safi: Safi) -> Self {
        AfiSafi { afi, safi }
    }

    /// Try to construct from optional raw numeric AFI/SAFI values.
    /// Returns None if either is absent or unrecognized.
    pub fn from_raw(afi: Option<u32>, safi: Option<u32>) -> Option<Self> {
        let afi = Afi::try_from(afi? as u16).ok()?;
        let safi_val = safi.unwrap_or(1);
        let safi = Safi::try_from(safi_val as u8).ok()?;
        Some(AfiSafi { afi, safi })
    }
}

impl fmt::Display for AfiSafi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.afi, self.safi)
    }
}

/// Default AFI/SAFIs: IPv4 Unicast + IPv6 Unicast
pub fn default_afi_safis() -> Vec<AfiSafi> {
    vec![
        AfiSafi::new(Afi::Ipv4, Safi::Unicast),
        AfiSafi::new(Afi::Ipv6, Safi::Unicast),
    ]
}

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
    pub neighbors: Vec<String>,
}

/// Named AS path set with regex patterns (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AsPathSetConfig {
    pub name: String,
    pub patterns: Vec<String>,
}

/// Named community set (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommunitySetConfig {
    pub name: String,
    pub communities: Vec<String>,
}

/// Named extended community set (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtCommunitySetConfig {
    pub name: String,
    pub ext_communities: Vec<String>,
}

/// Named large community set (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LargeCommunitySetConfig {
    pub name: String,
    pub large_communities: Vec<String>,
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

    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub neighbor: Option<String>,
    #[serde(default)]
    pub has_asn: Option<u32>,
    #[serde(default)]
    pub route_type: Option<String>,
    #[serde(default)]
    pub community: Option<String>,
    #[serde(default)]
    pub rpki_validation: Option<RpkiValidationConfig>,

    #[serde(default)]
    pub afi_safi: Option<String>,

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
pub struct BgpConfig {
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
    30
}

fn default_log_level() -> String {
    "info".to_string()
}

impl BgpConfig {
    /// Create a new configuration
    pub fn new(asn: u32, listen_addr: &str, router_id: Ipv4Addr, hold_time_secs: u64) -> Self {
        BgpConfig {
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

    /// Load configuration from a rogg.conf file.
    pub fn from_conf_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        Self::from_conf_str(&contents)
    }

    /// Parse a rogg.conf string into a BgpConfig.
    pub fn from_conf_str(input: &str) -> Result<Self, Box<dyn std::error::Error>> {
        use crate::language::{self, Service};
        use crate::language_bgp::Setting;

        let root = language::parse(input)?;
        let Service::Bgp(bgp) = root.services.first().ok_or("missing 'service bgp' block")?;

        let mut config = BgpConfig::default();
        let mut has_asn = false;
        let mut has_router_id = false;

        for setting in &bgp.settings {
            match setting {
                Setting::Asn(val) => {
                    config.asn = *val;
                    has_asn = true;
                }
                Setting::RouterId(val) => {
                    config.router_id = *val;
                    has_router_id = true;
                }
                Setting::ListenAddr(val) => config.listen_addr = val.clone(),
                Setting::GrpcListenAddr(val) => config.grpc_listen_addr = val.clone(),
                Setting::LogLevel(val) => config.log_level = val.clone(),
                Setting::HoldTime(val) => config.hold_time_secs = *val,
                Setting::ConnectRetry(val) => config.connect_retry_secs = *val,
                Setting::ClusterId(val) => config.cluster_id = Some(*val),
                _ => {}
            }
        }

        if !has_asn {
            return Err("missing required field 'asn'".into());
        }
        if !has_router_id {
            return Err("missing required field 'router-id'".into());
        }

        for peer_block in &bgp.peers {
            config.peers.push(peer_config_from_block(peer_block));
        }

        Ok(config)
    }
}

impl Default for BgpConfig {
    fn default() -> Self {
        BgpConfig {
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

/// Build a PeerConfig from a typed PeerBlock.
fn peer_config_from_block(peer: &crate::language_bgp::PeerBlock) -> PeerConfig {
    use crate::language_bgp::Setting;

    let mut config = PeerConfig::default();
    for setting in &peer.settings {
        match setting {
            Setting::Address(val) => config.address = val.clone(),
            Setting::RemoteAs(val) => config.asn = Some(*val),
            Setting::Port(val) => config.port = *val,
            Setting::Interface(val) => config.interface = Some(val.clone()),
            Setting::Md5KeyFile(val) => config.md5_key_file = Some(val.clone()),
            Setting::TtlMin(val) => config.ttl_min = Some(*val),
            Setting::NextHopSelf(val) => config.next_hop_self = *val,
            Setting::Passive(val) => config.passive_mode = *val,
            Setting::RrClient(val) => config.rr_client = *val,
            Setting::RsClient(val) => config.rs_client = *val,
            Setting::GracefulShutdown(val) => config.graceful_shutdown = *val,
            _ => {}
        }
    }
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs::{self, File};
    use std::io::Write;

    #[test]
    fn test_config_new() {
        let config = BgpConfig::new(65100, "192.168.1.1:179", Ipv4Addr::new(192, 168, 1, 1), 180);
        assert_eq!(config.asn, 65100);
        assert_eq!(config.listen_addr, "192.168.1.1:179");
        assert_eq!(config.router_id, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.hold_time_secs, 180);
    }

    #[test]
    fn test_config_default() {
        let config = BgpConfig::default();
        assert_eq!(config.asn, 65000);
        assert_eq!(config.listen_addr, "0.0.0.0:179");
        assert_eq!(config.router_id, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(config.grpc_listen_addr, "127.0.0.1:50051");
    }

    #[test]
    fn test_cluster_id() {
        let mut config = BgpConfig::new(65000, "0.0.0.0:179", Ipv4Addr::new(10, 0, 0, 1), 180);
        assert_eq!(config.cluster_id(), Ipv4Addr::new(10, 0, 0, 1));
        config.cluster_id = Some(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(config.cluster_id(), Ipv4Addr::new(1, 2, 3, 4));
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
        let peer = PeerConfig {
            rr_client: true,
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        let peer = PeerConfig {
            rs_client: true,
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

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

        let peer = PeerConfig::default();
        assert!(peer.validate().is_ok());
    }

    #[test]
    fn test_rs_client_rejects_add_path_receive() {
        let peer = PeerConfig {
            rs_client: true,
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        let peer = PeerConfig {
            add_path_receive: true,
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        let peer = PeerConfig {
            rs_client: true,
            add_path_receive: true,
            ..Default::default()
        };
        let result = peer.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_llgr_stale_time_validation() {
        let cases = [
            (0, true),
            (3600, true),
            (0xFFFFFF, true),
            (0xFFFFFF + 1, false),
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
        let peer = PeerConfig {
            llgr: Some(LlgrConfig {
                enabled: true,
                stale_time: Some(3600),
                afi_safis: None,
            }),
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

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
        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);

        assert!(get_peer_llgr(&None, &None).is_none());

        let server = Some(LlgrConfig {
            enabled: true,
            stale_time: Some(3600),
            afi_safis: Some(vec![ipv4_unicast]),
        });
        let merged = get_peer_llgr(&server, &None).expect("should be enabled");
        assert_eq!(merged.stale_time, Some(3600));
        assert_eq!(merged.afi_safis, Some(vec![ipv4_unicast]));

        let peer = Some(LlgrConfig {
            enabled: true,
            stale_time: Some(7200),
            afi_safis: Some(vec![ipv4_unicast]),
        });
        let merged = get_peer_llgr(&server, &peer).expect("should be enabled");
        assert_eq!(merged.stale_time, Some(7200));
        assert_eq!(merged.afi_safis, Some(vec![ipv4_unicast]));

        let peer_disabled = Some(LlgrConfig {
            enabled: false,
            stale_time: None,
            afi_safis: None,
        });
        assert!(get_peer_llgr(&server, &peer_disabled).is_none());
    }

    #[test]
    fn test_effective_max_prefix() {
        let cases = vec![
            (Some(500), Some(1000), Some(500)),
            (None, Some(1000), Some(1000)),
            (Some(500), None, Some(500)),
            (None, None, None),
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
        let ls = AfiSafi::new(Afi::LinkState, Safi::LinkState);
        let ls_setting = config.effective_max_prefix(&ls).unwrap();
        assert_eq!(ls_setting.limit, 5000);
        assert!(matches!(ls_setting.action, MaxPrefixAction::Discard));

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
    fn test_bgp_ls_config_default() {
        let config = BgpConfig::default();
        assert_eq!(config.bgp_ls.max_ls_entries, 0);
    }

    #[test]
    fn test_from_conf_basic() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1
  listen-addr 127.0.0.1:179
  grpc-listen-addr 127.0.0.1:50051
  log-level debug
  hold-time 90
  connect-retry 10
}";
        let config = BgpConfig::from_conf_str(input).unwrap();
        assert_eq!(config.asn, 65001);
        assert_eq!(config.router_id, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(config.listen_addr, "127.0.0.1:179");
        assert_eq!(config.grpc_listen_addr, "127.0.0.1:50051");
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.hold_time_secs, 90);
        assert_eq!(config.connect_retry_secs, 10);
    }

    #[test]
    fn test_from_conf_defaults() {
        let input = "\
service bgp {
  asn 65001
  router-id 2.2.2.2
}";
        let config = BgpConfig::from_conf_str(input).unwrap();
        assert_eq!(config.asn, 65001);
        assert_eq!(config.router_id, Ipv4Addr::new(2, 2, 2, 2));
        assert_eq!(config.listen_addr, "0.0.0.0:179");
        assert_eq!(config.grpc_listen_addr, "127.0.0.1:50051");
        assert_eq!(config.hold_time_secs, 180);
    }

    #[test]
    fn test_from_conf_with_peers() {
        let input = "\
service bgp {
  asn 4242423930
  router-id 172.23.211.1

  peer peer1 {
    address fe80::ade0
    remote-as 4242423914
    interface peer1-us3
    md5-key-file /etc/bgp/peer1.key
    next-hop-self true
    port 1179
    ttl-min 254
  }

  peer upstream {
    address 10.0.0.1
    remote-as 65000
    passive true
    rr-client true
  }
}";
        let config = BgpConfig::from_conf_str(input).unwrap();
        assert_eq!(config.asn, 4242423930);
        assert_eq!(config.peers.len(), 2);

        let peer1 = &config.peers[0];
        assert_eq!(peer1.address, "fe80::ade0");
        assert_eq!(peer1.asn, Some(4242423914));
        assert_eq!(peer1.interface.as_deref(), Some("peer1-us3"));
        assert_eq!(peer1.md5_key_file.as_deref(), Some("/etc/bgp/peer1.key"));
        assert!(peer1.next_hop_self);
        assert_eq!(peer1.port, 1179);
        assert_eq!(peer1.ttl_min, Some(254));

        let upstream = &config.peers[1];
        assert_eq!(upstream.address, "10.0.0.1");
        assert_eq!(upstream.asn, Some(65000));
        assert!(upstream.passive_mode);
        assert!(upstream.rr_client);
    }

    #[test]
    fn test_from_conf_missing_service_bgp() {
        let result = BgpConfig::from_conf_str("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("service bgp"));
    }

    #[test]
    fn test_from_conf_unknown_service() {
        let input = "service ospf { router-id 1.1.1.1 }";
        let result = BgpConfig::from_conf_str(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown service"));
    }

    #[test]
    fn test_from_conf_missing_required() {
        let input = "service bgp { router-id 1.1.1.1 }";
        let result = BgpConfig::from_conf_str(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("asn"));

        let input = "service bgp { asn 65001 }";
        let result = BgpConfig::from_conf_str(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("router-id"));
    }

    #[test]
    fn test_from_conf_rejects_other_services() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1
}

service ospf {
  router-id 1.1.1.1
}";
        let result = BgpConfig::from_conf_str(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_afi_try_from() {
        assert_eq!(Afi::try_from(1).unwrap(), Afi::Ipv4);
        assert_eq!(Afi::try_from(2).unwrap(), Afi::Ipv6);
        assert_eq!(Afi::try_from(16388).unwrap(), Afi::LinkState);
        assert!(Afi::try_from(99).is_err());
    }

    #[test]
    fn test_safi_try_from() {
        assert_eq!(Safi::try_from(1).unwrap(), Safi::Unicast);
        assert_eq!(Safi::try_from(2).unwrap(), Safi::Multicast);
        assert_eq!(Safi::try_from(4).unwrap(), Safi::MplsLabel);
        assert_eq!(Safi::try_from(71).unwrap(), Safi::LinkState);
        assert_eq!(Safi::try_from(72).unwrap(), Safi::LinkStateVpn);
        assert!(Safi::try_from(99).is_err());
    }

    #[test]
    fn test_afi_safi_from_raw() {
        let result = AfiSafi::from_raw(Some(1), Some(1));
        assert_eq!(result, Some(AfiSafi::new(Afi::Ipv4, Safi::Unicast)));

        let result = AfiSafi::from_raw(Some(2), None);
        assert_eq!(result, Some(AfiSafi::new(Afi::Ipv6, Safi::Unicast)));

        assert!(AfiSafi::from_raw(None, Some(1)).is_none());
        assert!(AfiSafi::from_raw(Some(99), Some(1)).is_none());
    }

    #[test]
    fn test_afi_safi_display() {
        let afi_safi = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        assert_eq!(format!("{}", afi_safi), "IPv4/Unicast");
    }

    #[test]
    fn test_default_afi_safis() {
        let defaults = default_afi_safis();
        assert_eq!(defaults.len(), 2);
        assert_eq!(defaults[0], AfiSafi::new(Afi::Ipv4, Safi::Unicast));
        assert_eq!(defaults[1], AfiSafi::new(Afi::Ipv6, Safi::Unicast));
    }

    #[test]
    fn test_afi_safi_serde_roundtrip() {
        let cases = vec![
            AfiSafi::new(Afi::Ipv4, Safi::Unicast),
            AfiSafi::new(Afi::Ipv6, Safi::Unicast),
            AfiSafi::new(Afi::LinkState, Safi::LinkState),
        ];
        for afi_safi in cases {
            let json = serde_json::to_string(&afi_safi).unwrap();
            let parsed: AfiSafi = serde_json::from_str(&json).unwrap();
            assert_eq!(afi_safi, parsed);
        }
    }
}
