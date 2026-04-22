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

//! BGP-specific AST types and parsing for the rogg config language.
//!
//! ## Grammar (BGP scope)
//!
//! ```text
//! bgp_body     = (setting | peer | policy | prefix_list | bmp_server | rpki_cache)*
//! peer         = "peer" NAME '{' (setting | family)* '}'
//! family       = "family" AFI SAFI '{' family_dir* '}'
//! family_dir   = ("export" | "import") "policy" NAME
//! policy       = "policy" NAME '{' policy_rule* '}'
//! policy_rule  = "match" NAME ACTION | "default" ACTION
//! prefix_list  = "prefix-list" NAME '{' PREFIX* '}'
//! bmp_server   = "bmp-server" ADDR '{' bmp_directive* '}'
//! bmp_directive = "statistics-timeout" N
//! rpki_cache   = "rpki-cache" ADDR '{' rpki_directive* '}'
//! rpki_directive = "preference" N | "transport" ("tcp" | "ssh")
//!                | "ssh-username" NAME | "ssh-private-key-file" PATH
//!                | "ssh-known-hosts-file" PATH
//!                | "retry-interval" N | "refresh-interval" N | "expire-interval" N
//! setting      = KEY VALUE NEWLINE
//! ```

use std::fmt;
use std::net::Ipv4Addr;

use crate::bgp::{Afi, Safi, TransportType};
use crate::language::{
    expect_close_brace, expect_open_brace, expect_word, finish_statement, parse_err, peek_kind,
    skip_newlines, take_word, ParseError, Token, TokenKind,
};

/// Body of `service bgp { ... }`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BgpServiceBody {
    pub settings: Vec<Setting>,
    pub peers: Vec<PeerBlock>,
    pub policies: Vec<PolicyBlock>,
    pub prefix_lists: Vec<PrefixListBlock>,
    pub bmp_servers: Vec<BmpServerBlock>,
    pub rpki_caches: Vec<RpkiCacheBlock>,
}

/// Typed config setting. Values are parsed at parse time.
/// Boolean settings (next-hop-self, passive, etc.) take "true" or "false".
#[derive(Debug, Clone, PartialEq)]
pub enum Setting {
    Asn(u32),
    RouterId(Ipv4Addr),
    ListenAddr(String),
    GrpcListenAddr(String),
    LogLevel(String),
    HoldTime(u64),
    ConnectRetry(u64),
    ClusterId(Ipv4Addr),
    RemoteAs(u32),
    Port(u16),
    Interface(String),
    Md5KeyFile(String),
    TtlMin(u8),
    NextHopSelf(bool),
    Passive(bool),
    RrClient(bool),
    RsClient(bool),
    GracefulShutdown(bool),
    Originate(String),
}

/// `peer <ADDRESS> { ... }` block. The block header is the peer's IP address;
/// there is no separate symbolic name. Matches Cisco/FRR/Junos/GoBGP convention.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerBlock {
    pub address: String,
    pub settings: Vec<Setting>,
    pub families: Vec<FamilyBlock>,
}

/// `family <afi> <safi> { ... }` block.
#[derive(Debug, Clone, PartialEq)]
pub struct FamilyBlock {
    pub afi: Afi,
    pub safi: Safi,
    pub directives: Vec<FamilyDirective>,
}

/// Directive inside a family block.
#[derive(Debug, Clone, PartialEq)]
pub enum FamilyDirective {
    ExportPolicy(String),
    ImportPolicy(String),
}

/// `policy <name> { ... }` block.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyBlock {
    pub name: String,
    pub rules: Vec<PolicyRule>,
}

/// Rule inside a policy block.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyRule {
    Match { set_name: String, action: String },
    Default { action: String },
}

/// `prefix-list <name> { ... }` block.
#[derive(Debug, Clone, PartialEq)]
pub struct PrefixListBlock {
    pub name: String,
    pub prefixes: Vec<String>,
}

/// `bmp-server <ADDR> { ... }` block. Mirrors `conf::bgp::BmpConfig`.
#[derive(Debug, Clone, PartialEq)]
pub struct BmpServerBlock {
    pub address: String,
    pub statistics_timeout: Option<u64>,
}

/// `rpki-cache <ADDR> { ... }` block. Mirrors `conf::bgp::RpkiCacheConfig`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RpkiCacheBlock {
    pub address: String,
    pub preference: Option<u8>,
    pub transport: Option<TransportType>,
    pub ssh_username: Option<String>,
    pub ssh_private_key_file: Option<String>,
    pub ssh_known_hosts_file: Option<String>,
    pub retry_interval: Option<u64>,
    pub refresh_interval: Option<u64>,
    pub expire_interval: Option<u64>,
}

// ---- Display impls: output matches the parser grammar so
// `parse(node.to_string()) == Ok(node)` holds. Each impl uses a 2-space indent
// relative to its own opening; nesting types re-indent their children's output.

impl fmt::Display for Setting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Setting::Asn(v) => write!(f, "asn {}", v),
            Setting::RouterId(v) => write!(f, "router-id {}", v),
            Setting::ListenAddr(v) => write!(f, "listen-addr {}", v),
            Setting::GrpcListenAddr(v) => write!(f, "grpc-listen-addr {}", v),
            Setting::LogLevel(v) => write!(f, "log-level {}", v),
            Setting::HoldTime(v) => write!(f, "hold-time {}", v),
            Setting::ConnectRetry(v) => write!(f, "connect-retry {}", v),
            Setting::ClusterId(v) => write!(f, "cluster-id {}", v),
            Setting::RemoteAs(v) => write!(f, "remote-as {}", v),
            Setting::Port(v) => write!(f, "port {}", v),
            Setting::Interface(v) => write!(f, "interface {}", v),
            Setting::Md5KeyFile(v) => write!(f, "md5-key-file {}", v),
            Setting::TtlMin(v) => write!(f, "ttl-min {}", v),
            Setting::NextHopSelf(v) => write!(f, "next-hop-self {}", v),
            Setting::Passive(v) => write!(f, "passive {}", v),
            Setting::RrClient(v) => write!(f, "rr-client {}", v),
            Setting::RsClient(v) => write!(f, "rs-client {}", v),
            Setting::GracefulShutdown(v) => write!(f, "graceful-shutdown {}", v),
            Setting::Originate(v) => write!(f, "originate {}", v),
        }
    }
}

impl fmt::Display for FamilyDirective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FamilyDirective::ExportPolicy(name) => write!(f, "export policy {}", name),
            FamilyDirective::ImportPolicy(name) => write!(f, "import policy {}", name),
        }
    }
}

impl fmt::Display for PolicyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyRule::Match { set_name, action } => write!(f, "match {} {}", set_name, action),
            PolicyRule::Default { action } => write!(f, "default {}", action),
        }
    }
}

impl fmt::Display for FamilyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "family {} {} {{",
            self.afi.as_config_str(),
            self.safi.as_config_str()
        )?;
        for d in &self.directives {
            writeln!(f, "  {}", d)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for PolicyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "policy {} {{", self.name)?;
        for rule in &self.rules {
            writeln!(f, "  {}", rule)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for PrefixListBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "prefix-list {} {{", self.name)?;
        for prefix in &self.prefixes {
            writeln!(f, "  {}", prefix)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for BmpServerBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "bmp-server {} {{", self.address)?;
        if let Some(v) = self.statistics_timeout {
            writeln!(f, "  statistics-timeout {}", v)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for RpkiCacheBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "rpki-cache {} {{", self.address)?;
        if let Some(v) = self.preference {
            writeln!(f, "  preference {}", v)?;
        }
        if let Some(v) = &self.transport {
            writeln!(f, "  transport {}", v.as_config_str())?;
        }
        if let Some(v) = &self.ssh_username {
            writeln!(f, "  ssh-username {}", v)?;
        }
        if let Some(v) = &self.ssh_private_key_file {
            writeln!(f, "  ssh-private-key-file {}", v)?;
        }
        if let Some(v) = &self.ssh_known_hosts_file {
            writeln!(f, "  ssh-known-hosts-file {}", v)?;
        }
        if let Some(v) = self.retry_interval {
            writeln!(f, "  retry-interval {}", v)?;
        }
        if let Some(v) = self.refresh_interval {
            writeln!(f, "  refresh-interval {}", v)?;
        }
        if let Some(v) = self.expire_interval {
            writeln!(f, "  expire-interval {}", v)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for PeerBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "peer {} {{", self.address)?;
        for setting in &self.settings {
            writeln!(f, "  {}", setting)?;
        }
        for family in &self.families {
            writeln!(f)?;
            for line in family.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
        }
        write!(f, "}}")
    }
}

impl fmt::Display for BgpServiceBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "service bgp {{")?;
        let mut first = true;
        for setting in &self.settings {
            writeln!(f, "  {}", setting)?;
            first = false;
        }
        for peer in &self.peers {
            if !first {
                writeln!(f)?;
            }
            for line in peer.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for bmp in &self.bmp_servers {
            if !first {
                writeln!(f)?;
            }
            for line in bmp.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for rpki in &self.rpki_caches {
            if !first {
                writeln!(f)?;
            }
            for line in rpki.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for policy in &self.policies {
            if !first {
                writeln!(f)?;
            }
            for line in policy.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for plist in &self.prefix_lists {
            if !first {
                writeln!(f)?;
            }
            for line in plist.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        write!(f, "}}")
    }
}

impl Setting {
    /// Parse a typed Setting from a keyword and optional value word. Line-free;
    /// config-file callers attach line context, ggsh uses the message directly.
    pub fn parse(key: &str, value: Option<&str>) -> Result<Setting, String> {
        Ok(match key {
            "asn" => Setting::Asn(parse_value(key, value)?),
            "router-id" => Setting::RouterId(parse_value(key, value)?),
            "listen-addr" => Setting::ListenAddr(parse_value(key, value)?),
            "grpc-listen-addr" => Setting::GrpcListenAddr(parse_value(key, value)?),
            "log-level" => Setting::LogLevel(parse_value(key, value)?),
            "hold-time" => Setting::HoldTime(parse_value(key, value)?),
            "connect-retry" => Setting::ConnectRetry(parse_value(key, value)?),
            "cluster-id" => Setting::ClusterId(parse_value(key, value)?),
            "remote-as" => Setting::RemoteAs(parse_value(key, value)?),
            "port" => Setting::Port(parse_value(key, value)?),
            "interface" => Setting::Interface(parse_value(key, value)?),
            "md5-key-file" => Setting::Md5KeyFile(parse_value(key, value)?),
            "ttl-min" => Setting::TtlMin(parse_value(key, value)?),
            "next-hop-self" => Setting::NextHopSelf(parse_value(key, value)?),
            "passive" => Setting::Passive(parse_value(key, value)?),
            "rr-client" => Setting::RrClient(parse_value(key, value)?),
            "rs-client" => Setting::RsClient(parse_value(key, value)?),
            "graceful-shutdown" => Setting::GracefulShutdown(parse_value(key, value)?),
            "originate" => Setting::Originate(parse_value(key, value)?),
            other => return Err(format!("unknown setting '{}'", other)),
        })
    }
}

/// Parse a value of type `T` for the given keyword. `T`'s `FromStr` impl validates;
/// the Setting variant's inner type decides `T` via inference.
fn parse_value<T>(key: &str, value: Option<&str>) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    let val = value.ok_or_else(|| format!("{} requires a value", key))?;
    val.parse::<T>()
        .map_err(|err| format!("invalid {} '{}': {}", key, val, err))
}

pub(crate) fn parse_bgp_body(
    tokens: &[Token],
    pos: &mut usize,
) -> Result<BgpServiceBody, ParseError> {
    let mut body = BgpServiceBody::default();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(tokens[*pos].line, "unexpected '{'"));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "peer" => {
                let address = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "peer requires an address"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.peers.push(parse_peer_block(address, tokens, pos)?);
            }
            "policy" => {
                let name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "policy requires a name"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.policies.push(parse_policy_block(name, tokens, pos)?);
            }
            "prefix-list" => {
                let name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "prefix-list requires a name"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.prefix_lists
                    .push(parse_prefix_list_block(name, tokens, pos)?);
            }
            "bmp-server" => {
                let address = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "bmp-server requires an address"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.bmp_servers
                    .push(parse_bmp_server_block(address, tokens, pos)?);
            }
            "rpki-cache" => {
                let address = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "rpki-cache requires an address"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.rpki_caches
                    .push(parse_rpki_cache_block(address, tokens, pos)?);
            }
            _ => {
                let value = take_word(tokens, pos);
                finish_statement(tokens, pos)?;
                body.settings.push(
                    Setting::parse(&key, value.as_deref()).map_err(|msg| parse_err(line, msg))?,
                );
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    Ok(body)
}

fn unexpected_eof(tokens: &[Token], pos: usize) -> ParseError {
    parse_err(
        crate::language::current_line(tokens, pos),
        "unexpected end of input, expected '}'",
    )
}

fn parse_peer_block(
    address: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<PeerBlock, ParseError> {
    let mut settings = Vec::new();
    let mut families = Vec::new();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(tokens[*pos].line, "unexpected '{'"));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "family" => {
                let afi_str = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "family requires afi"))?
                    .0;
                let afi: Afi = afi_str.parse().map_err(|err| {
                    parse_err(line, format!("invalid afi '{}': {}", afi_str, err))
                })?;
                let safi_str = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "family requires safi"))?
                    .0;
                let safi: Safi = safi_str.parse().map_err(|err| {
                    parse_err(line, format!("invalid safi '{}': {}", safi_str, err))
                })?;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                families.push(parse_family_block(afi, safi, tokens, pos)?);
            }
            _ => {
                let value = take_word(tokens, pos);
                finish_statement(tokens, pos)?;
                settings.push(
                    Setting::parse(&key, value.as_deref()).map_err(|msg| parse_err(line, msg))?,
                );
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    Ok(PeerBlock {
        address,
        settings,
        families,
    })
}

fn parse_family_block(
    afi: Afi,
    safi: Safi,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<FamilyBlock, ParseError> {
    let mut directives = Vec::new();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(tokens[*pos].line, "unexpected '{' inside family"));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        let directive = match key.as_str() {
            "export" | "import" => {
                let sub = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, format!("{} requires 'policy'", key)))?
                    .0;
                if sub != "policy" {
                    return Err(parse_err(
                        line,
                        format!("{} requires 'policy', got '{}'", key, sub),
                    ));
                }
                let policy_name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, format!("{} policy requires a name", key)))?
                    .0;
                if key == "export" {
                    FamilyDirective::ExportPolicy(policy_name)
                } else {
                    FamilyDirective::ImportPolicy(policy_name)
                }
            }
            other => {
                return Err(parse_err(
                    line,
                    format!("unknown family directive '{}'", other),
                ));
            }
        };
        finish_statement(tokens, pos)?;
        directives.push(directive);
    }
    expect_close_brace(tokens, pos)?;
    Ok(FamilyBlock {
        afi,
        safi,
        directives,
    })
}

fn parse_policy_block(
    name: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<PolicyBlock, ParseError> {
    let mut rules = Vec::new();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(tokens[*pos].line, "unexpected '{' inside policy"));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        let rule = match key.as_str() {
            "match" => {
                let set_name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "match requires a set name"))?
                    .0;
                let action = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "match requires an action"))?
                    .0;
                PolicyRule::Match { set_name, action }
            }
            "default" => {
                let action = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "default requires an action"))?
                    .0;
                PolicyRule::Default { action }
            }
            other => {
                return Err(parse_err(line, format!("unknown policy rule '{}'", other)));
            }
        };
        finish_statement(tokens, pos)?;
        rules.push(rule);
    }
    expect_close_brace(tokens, pos)?;
    Ok(PolicyBlock { name, rules })
}

fn parse_prefix_list_block(
    name: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<PrefixListBlock, ParseError> {
    let mut prefixes = Vec::new();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(
                    tokens[*pos].line,
                    "unexpected '{' inside prefix-list",
                ));
            }
            _ => {}
        }
        let (prefix, _) = expect_word(tokens, pos)?;
        finish_statement(tokens, pos)?;
        prefixes.push(prefix);
    }
    expect_close_brace(tokens, pos)?;
    Ok(PrefixListBlock { name, prefixes })
}

/// Parse a scalar `key VALUE\n` line. `T` decides how the value is interpreted.
fn parse_scalar<T>(
    key: &str,
    line: usize,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<T, ParseError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    let value = expect_word(tokens, pos)
        .map_err(|_| parse_err(line, format!("{} requires a value", key)))?
        .0;
    let parsed = value
        .parse::<T>()
        .map_err(|err| parse_err(line, format!("invalid {} '{}': {}", key, value, err)))?;
    finish_statement(tokens, pos)?;
    Ok(parsed)
}

fn parse_bmp_server_block(
    address: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<BmpServerBlock, ParseError> {
    let mut block = BmpServerBlock {
        address,
        statistics_timeout: None,
    };
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(
                    tokens[*pos].line,
                    "unexpected '{' inside bmp-server",
                ));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "statistics-timeout" => {
                block.statistics_timeout = Some(parse_scalar(&key, line, tokens, pos)?);
            }
            other => {
                return Err(parse_err(
                    line,
                    format!("unknown bmp-server directive '{}'", other),
                ));
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    Ok(block)
}

fn parse_rpki_cache_block(
    address: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<RpkiCacheBlock, ParseError> {
    let mut block = RpkiCacheBlock {
        address,
        ..RpkiCacheBlock::default()
    };
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(
                    tokens[*pos].line,
                    "unexpected '{' inside rpki-cache",
                ));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "preference" => block.preference = Some(parse_scalar(&key, line, tokens, pos)?),
            "transport" => block.transport = Some(parse_scalar(&key, line, tokens, pos)?),
            "ssh-username" => block.ssh_username = Some(parse_scalar(&key, line, tokens, pos)?),
            "ssh-private-key-file" => {
                block.ssh_private_key_file = Some(parse_scalar(&key, line, tokens, pos)?);
            }
            "ssh-known-hosts-file" => {
                block.ssh_known_hosts_file = Some(parse_scalar(&key, line, tokens, pos)?);
            }
            "retry-interval" => block.retry_interval = Some(parse_scalar(&key, line, tokens, pos)?),
            "refresh-interval" => {
                block.refresh_interval = Some(parse_scalar(&key, line, tokens, pos)?);
            }
            "expire-interval" => {
                block.expire_interval = Some(parse_scalar(&key, line, tokens, pos)?);
            }
            other => {
                return Err(parse_err(
                    line,
                    format!("unknown rpki-cache directive '{}'", other),
                ));
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::{parse, Service};

    #[test]
    fn test_parse_bgp_basic() {
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
        let root = parse(input).unwrap();
        assert_eq!(root.services.len(), 1);

        let Service::Bgp(body) = &root.services[0];
        assert!(body.settings.contains(&Setting::Asn(65001)));
        assert!(body
            .settings
            .contains(&Setting::RouterId("1.1.1.1".parse().unwrap())));
        assert!(body
            .settings
            .contains(&Setting::ListenAddr("127.0.0.1:179".to_string())));
        assert!(body
            .settings
            .contains(&Setting::LogLevel("debug".to_string())));
        assert!(body.settings.contains(&Setting::HoldTime(90)));
        assert!(body.settings.contains(&Setting::ConnectRetry(10)));
    }

    #[test]
    fn test_parse_bgp_peers() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  peer fe80::ade0 {
    remote-as 4242423914
    interface peer1-us3
    md5-key-file /etc/bgp/peer1.key
    next-hop-self true
    port 1179
    ttl-min 254
  }

  peer 10.0.0.1 {
    remote-as 65000
    passive true
    rr-client true
  }
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert_eq!(body.peers.len(), 2);

        let peer1 = &body.peers[0];
        assert_eq!(peer1.address, "fe80::ade0");
        assert!(peer1.settings.contains(&Setting::RemoteAs(4242423914)));
        assert!(peer1.settings.contains(&Setting::NextHopSelf(true)));
        assert!(peer1.settings.contains(&Setting::Port(1179)));

        let upstream = &body.peers[1];
        assert_eq!(upstream.address, "10.0.0.1");
        assert!(upstream.settings.contains(&Setting::Passive(true)));
        assert!(upstream.settings.contains(&Setting::RrClient(true)));
    }

    #[test]
    fn test_parse_family() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  peer 10.0.0.1 {
    family ipv4 unicast {
      export policy mine-only
    }
    family ipv6 unicast {
      import policy allow-all
    }
  }
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        let peer = &body.peers[0];
        assert_eq!(peer.families.len(), 2);

        assert!(matches!(
            &peer.families[0].directives[0],
            FamilyDirective::ExportPolicy(name) if name == "mine-only"
        ));
        assert!(matches!(
            &peer.families[1].directives[0],
            FamilyDirective::ImportPolicy(name) if name == "allow-all"
        ));
    }

    #[test]
    fn test_parse_policy_and_prefix_list() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  policy mine-only {
    match my-prefixes accept
    default reject
  }

  prefix-list my-prefixes {
    172.23.211.0/27
    fd0d:fbde:bca5::/48
  }
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];

        let policy = &body.policies[0];
        assert_eq!(policy.name, "mine-only");
        assert!(matches!(
            &policy.rules[0],
            PolicyRule::Match { set_name, action } if set_name == "my-prefixes" && action == "accept"
        ));
        assert!(matches!(
            &policy.rules[1],
            PolicyRule::Default { action } if action == "reject"
        ));

        let prefix_list = &body.prefix_lists[0];
        assert_eq!(prefix_list.name, "my-prefixes");
        assert_eq!(
            prefix_list.prefixes,
            vec!["172.23.211.0/27", "fd0d:fbde:bca5::/48"]
        );
    }

    #[test]
    fn test_parse_originate() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1
  originate 172.23.211.0/27
  originate fd0d:fbde:bca5::/48
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert!(body
            .settings
            .contains(&Setting::Originate("172.23.211.0/27".to_string())));
        assert!(body
            .settings
            .contains(&Setting::Originate("fd0d:fbde:bca5::/48".to_string())));
    }

    #[test]
    fn test_parse_full_config() {
        let input = "\
service bgp {
  asn 4242423930
  router-id 172.23.211.1
  listen-addr [::]:179
  grpc-listen-addr [::]:50051
  log-level debug
  hold-time 90

  peer fe80::ade0 {
    interface peer1-us3
    remote-as 4242423914
    next-hop-self true
    md5-key-file /etc/bgp/peer1.key

    family ipv4 unicast {
      export policy mine-only
    }

    family ipv6 unicast {
      export policy mine-only
    }
  }

  originate 172.23.211.0/27
  originate fd0d:fbde:bca5::/48

  policy mine-only {
    match my-prefixes accept
    default reject
  }

  prefix-list my-prefixes {
    172.23.211.0/27
    fd0d:fbde:bca5::/48
  }
}";
        let root = parse(input).unwrap();
        assert_eq!(root.services.len(), 1);

        let Service::Bgp(body) = &root.services[0];

        assert!(body.settings.contains(&Setting::Asn(4242423930)));
        assert_eq!(body.peers.len(), 1);
        assert!(body
            .settings
            .contains(&Setting::Originate("172.23.211.0/27".to_string())));
        assert_eq!(body.policies.len(), 1);
        assert_eq!(body.prefix_lists.len(), 1);
        assert!(body.peers[0].settings.contains(&Setting::NextHopSelf(true)));
    }

    #[test]
    fn test_setting_parse_ok() {
        let cases = vec![
            ("asn", Some("65001"), Setting::Asn(65001)),
            (
                "router-id",
                Some("1.2.3.4"),
                Setting::RouterId("1.2.3.4".parse().unwrap()),
            ),
            (
                "cluster-id",
                Some("10.0.0.1"),
                Setting::ClusterId("10.0.0.1".parse().unwrap()),
            ),
            ("port", Some("179"), Setting::Port(179)),
            ("ttl-min", Some("254"), Setting::TtlMin(254)),
            ("hold-time", Some("90"), Setting::HoldTime(90)),
            ("next-hop-self", Some("true"), Setting::NextHopSelf(true)),
            ("passive", Some("false"), Setting::Passive(false)),
            ("rr-client", Some("true"), Setting::RrClient(true)),
            ("rs-client", Some("true"), Setting::RsClient(true)),
            (
                "graceful-shutdown",
                Some("true"),
                Setting::GracefulShutdown(true),
            ),
            (
                "interface",
                Some("eth0"),
                Setting::Interface("eth0".to_string()),
            ),
            (
                "md5-key-file",
                Some("/etc/bgp/x.key"),
                Setting::Md5KeyFile("/etc/bgp/x.key".to_string()),
            ),
            (
                "listen-addr",
                Some("[::]:179"),
                Setting::ListenAddr("[::]:179".to_string()),
            ),
            (
                "originate",
                Some("10.0.0.0/24"),
                Setting::Originate("10.0.0.0/24".to_string()),
            ),
        ];
        for (key, value, expected) in cases {
            let got = Setting::parse(key, value).unwrap();
            assert_eq!(got, expected, "for ({:?}, {:?})", key, value);
        }
    }

    #[test]
    fn test_setting_parse_errors() {
        let cases = vec![
            ("asn", None, "asn requires a value"),
            ("asn", Some("true"), "invalid asn 'true'"),
            ("asn", Some("foo"), "invalid asn 'foo'"),
            ("router-id", Some("300.0.0.0"), "invalid router-id"),
            ("port", Some("99999"), "invalid port"),
            ("next-hop-self", Some("yes"), "invalid next-hop-self 'yes'"),
            ("next-hop-self", None, "next-hop-self requires a value"),
            ("weird-key", Some("x"), "unknown setting 'weird-key'"),
            ("weird-key", None, "unknown setting 'weird-key'"),
        ];
        for (key, value, expected) in cases {
            let err = Setting::parse(key, value).unwrap_err();
            assert!(
                err.contains(expected),
                "for ({:?}, {:?}): expected {:?} in {:?}",
                key,
                value,
                expected,
                err
            );
        }
    }

    #[test]
    fn test_display_round_trip() {
        let cases = vec![
            "service bgp {\n  asn 65001\n  router-id 1.1.1.1\n}",
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1
  listen-addr 127.0.0.1:179
  grpc-listen-addr 127.0.0.1:50051
  log-level debug
  hold-time 90
  connect-retry 10
}",
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  peer fe80::ade0 {
    remote-as 4242423914
    interface peer1-us3
    md5-key-file /etc/bgp/peer1.key
    next-hop-self true
    port 1179
    ttl-min 254
  }

  peer 10.0.0.1 {
    remote-as 65000
    passive true
    rr-client true
  }
}",
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  peer 10.0.0.1 {
    family ipv4 unicast {
      export policy mine-only
    }

    family ipv6 unicast {
      import policy allow-all
    }
  }
}",
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1
  originate 172.23.211.0/27
  originate fd0d:fbde:bca5::/48

  policy mine-only {
    match my-prefixes accept
    default reject
  }

  prefix-list my-prefixes {
    172.23.211.0/27
    fd0d:fbde:bca5::/48
  }
}",
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  bmp-server 127.0.0.1:1790 {
    statistics-timeout 60
  }

  rpki-cache 10.0.0.1:323 {
    preference 1
    transport ssh
    ssh-username rtr-user
    ssh-private-key-file /etc/bgp/rtr.key
    retry-interval 60
  }
}",
        ];
        for input in cases {
            let root =
                parse(input).unwrap_or_else(|err| panic!("parse failed for {:?}: {}", input, err));
            let serialized = root.to_string();
            let reparsed = parse(&serialized).unwrap_or_else(|err| {
                panic!(
                    "reparse failed for {:?}:\nserialized:\n{}\nerror: {}",
                    input, serialized, err
                )
            });
            assert_eq!(
                root, reparsed,
                "round-trip mismatch for input {:?}\nserialized:\n{}",
                input, serialized
            );
        }
    }

    #[test]
    fn test_display_format() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  peer 10.0.0.1 {
    remote-as 65002
  }
}";
        let root = parse(input).unwrap();
        let out = root.to_string();
        // Check key structural elements without pinning exact whitespace counts.
        assert!(out.contains("service bgp {"));
        assert!(out.contains("  asn 65001"));
        assert!(out.contains("  router-id 1.1.1.1"));
        assert!(out.contains("  peer 10.0.0.1 {"));
        assert!(out.contains("    remote-as 65002"));
        assert!(out.ends_with("}\n"));
    }

    #[test]
    fn test_parse_invalid_afi_safi_rejected_at_parse_time() {
        let cases = vec![
            (
                "service bgp { peer x { family ipvv4 unicast { } } }",
                "invalid afi 'ipvv4'",
            ),
            (
                "service bgp { peer x { family ipv4 unicorn { } } }",
                "invalid safi 'unicorn'",
            ),
        ];
        for (input, expected) in cases {
            let err = parse(input).unwrap_err();
            assert!(
                err.message.contains(expected),
                "for {:?}: expected {:?} in {:?}",
                input,
                expected,
                err.message
            );
        }
    }

    #[test]
    fn test_parse_invalid_settings_carry_line() {
        // Errors from Setting::parse are wrapped with the keyword's line by the
        // recursive-descent parser.
        let cases = vec![
            ("service bgp { asn }", "asn requires a value"),
            ("service bgp { asn true }", "invalid asn 'true'"),
            ("service bgp { weird-key x }", "unknown setting 'weird-key'"),
            (
                "service bgp { peer x { weird-key x } }",
                "unknown setting 'weird-key'",
            ),
        ];
        for (input, expected) in cases {
            let err = parse(input).unwrap_err();
            assert!(
                err.message.contains(expected),
                "for {:?}: expected {:?} in {:?}",
                input,
                expected,
                err.message
            );
        }
    }

    #[test]
    fn test_parse_bmp_server() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  bmp-server 127.0.0.1:1790 {
    statistics-timeout 60
  }

  bmp-server [::1]:1790 {
  }
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert_eq!(body.bmp_servers.len(), 2);
        assert_eq!(body.bmp_servers[0].address, "127.0.0.1:1790");
        assert_eq!(body.bmp_servers[0].statistics_timeout, Some(60));
        assert_eq!(body.bmp_servers[1].address, "[::1]:1790");
        assert_eq!(body.bmp_servers[1].statistics_timeout, None);
    }

    #[test]
    fn test_parse_rpki_cache() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  rpki-cache 127.0.0.1:323 {
    preference 1
    transport tcp
    refresh-interval 3600
  }

  rpki-cache 10.0.0.1:323 {
    preference 2
    transport ssh
    ssh-username rtr-user
    ssh-private-key-file /etc/bgp/rtr.key
    ssh-known-hosts-file /etc/bgp/known_hosts
    retry-interval 60
    expire-interval 7200
  }
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert_eq!(body.rpki_caches.len(), 2);

        let first = &body.rpki_caches[0];
        assert_eq!(first.address, "127.0.0.1:323");
        assert_eq!(first.preference, Some(1));
        assert_eq!(first.transport, Some(TransportType::Tcp));
        assert_eq!(first.refresh_interval, Some(3600));

        let second = &body.rpki_caches[1];
        assert_eq!(second.preference, Some(2));
        assert_eq!(second.transport, Some(TransportType::Ssh));
        assert_eq!(second.ssh_username.as_deref(), Some("rtr-user"));
        assert_eq!(
            second.ssh_private_key_file.as_deref(),
            Some("/etc/bgp/rtr.key")
        );
        assert_eq!(second.retry_interval, Some(60));
        assert_eq!(second.expire_interval, Some(7200));
    }

    #[test]
    fn test_parse_bmp_server_unknown_directive() {
        let err =
            parse("service bgp { asn 1\n router-id 1.1.1.1\n bmp-server 127.0.0.1:1 { weird 1 } }")
                .unwrap_err();
        assert!(
            err.message.contains("unknown bmp-server directive 'weird'"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn test_parse_rpki_cache_unknown_directive() {
        let err =
            parse("service bgp { asn 1\n router-id 1.1.1.1\n rpki-cache 127.0.0.1:1 { weird 1 } }")
                .unwrap_err();
        assert!(
            err.message.contains("unknown rpki-cache directive 'weird'"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn test_parse_rpki_cache_invalid_transport() {
        let err = parse(
            "service bgp { asn 1\n router-id 1.1.1.1\n rpki-cache 127.0.0.1:1 { transport foo } }",
        )
        .unwrap_err();
        assert!(
            err.message.contains("invalid transport 'foo'"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn test_parse_trailing_tokens_rejected() {
        let cases = vec![
            (
                "service bgp { asn 65001 junk }",
                "unexpected trailing token",
            ),
            (
                "service bgp { peer 10.0.0.1 { remote-as 65001 junk } }",
                "unexpected trailing token",
            ),
            (
                "service bgp { peer x { family ipv4 unicast { export policy p extra } } }",
                "unexpected trailing token",
            ),
            (
                "service bgp { policy p { default reject extra } }",
                "unexpected trailing token",
            ),
            (
                "service bgp { prefix-list p { 10.0.0.0/24 extra } }",
                "unexpected trailing token",
            ),
        ];
        for (input, expected) in cases {
            let err = parse(input).unwrap_err();
            assert!(
                err.message.contains(expected),
                "for {:?}: expected {:?} in {:?}",
                input,
                expected,
                err.message
            );
        }
    }
}
