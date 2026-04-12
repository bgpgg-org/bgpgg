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
//! bgp_body     = (setting | peer | policy | prefix_list | announce)*
//! peer         = "peer" NAME '{' (setting | family)* '}'
//! family       = "family" AFI SAFI '{' family_dir* '}'
//! family_dir   = ("export" | "import") "policy" NAME
//! policy       = "policy" NAME '{' policy_rule* '}'
//! policy_rule  = "match" NAME "->" ACTION | "default" "->" ACTION
//! prefix_list  = "prefix-list" NAME '{' PREFIX* '}'
//! announce     = "announce" PREFIX
//! setting      = KEY VALUE? NEWLINE
//! ```

use crate::language::{current_line, parse_err, ParseError, Token, TokenKind};

/// Body of `service bgp { ... }`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BgpServiceBody {
    pub settings: Vec<Setting>,
    pub peers: Vec<PeerBlock>,
    pub policies: Vec<PolicyBlock>,
    pub prefix_lists: Vec<PrefixListBlock>,
}

/// Typed config setting. Values are parsed at parse time.
/// Flags (next-hop-self, passive, etc.) are unit variants — presence means enabled.
#[derive(Debug, Clone, PartialEq)]
pub enum Setting {
    Asn(u32),
    RouterId(std::net::Ipv4Addr),
    ListenAddr(String),
    GrpcListenAddr(String),
    LogLevel(String),
    HoldTime(u64),
    ConnectRetry(u64),
    ClusterId(std::net::Ipv4Addr),
    Address(String),
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
    Announce(String),
}

/// `peer <name> { ... }` block.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerBlock {
    pub name: String,
    pub settings: Vec<Setting>,
    pub families: Vec<FamilyBlock>,
}

/// `family <afi> <safi> { ... }` block.
#[derive(Debug, Clone, PartialEq)]
pub struct FamilyBlock {
    pub afi: String,
    pub safi: String,
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

/// Catch-all for unrecognized blocks/statements within a known scope.
#[derive(Debug, Clone, PartialEq)]
pub struct UnknownBlock {
    pub words: Vec<String>,
    pub children: Vec<UnknownBlock>,
}

fn parse_bool(keyword: &str, value: Option<&str>, line: usize) -> Result<bool, ParseError> {
    let val =
        value.ok_or_else(|| parse_err(line, format!("{} requires 'true' or 'false'", keyword)))?;
    match val {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(parse_err(
            line,
            format!("{}: expected 'true' or 'false', got '{}'", keyword, val),
        )),
    }
}

/// Parse a leaf statement (1-2 words) into a typed Setting and push onto the list.
fn parse_leaf_setting(
    words: &[String],
    line: usize,
    settings: &mut Vec<Setting>,
) -> Result<(), ParseError> {
    if words.is_empty() {
        return Ok(());
    }
    let keyword = words[0].as_str();
    let value = words.get(1).map(|s| s.as_str());
    let setting = match keyword {
        "asn" => {
            let val = value.ok_or_else(|| parse_err(line, "asn requires a value"))?;
            let asn = val
                .parse::<u32>()
                .map_err(|err| parse_err(line, format!("invalid asn '{}': {}", val, err)))?;
            Setting::Asn(asn)
        }
        "router-id" => {
            let val = value.ok_or_else(|| parse_err(line, "router-id requires a value"))?;
            let rid = val
                .parse::<std::net::Ipv4Addr>()
                .map_err(|err| parse_err(line, format!("invalid router-id '{}': {}", val, err)))?;
            Setting::RouterId(rid)
        }
        "listen-addr" => {
            let val = value.ok_or_else(|| parse_err(line, "listen-addr requires a value"))?;
            Setting::ListenAddr(val.to_string())
        }
        "grpc-listen-addr" => {
            let val = value.ok_or_else(|| parse_err(line, "grpc-listen-addr requires a value"))?;
            Setting::GrpcListenAddr(val.to_string())
        }
        "log-level" => {
            let val = value.ok_or_else(|| parse_err(line, "log-level requires a value"))?;
            Setting::LogLevel(val.to_string())
        }
        "hold-time" => {
            let val = value.ok_or_else(|| parse_err(line, "hold-time requires a value"))?;
            let secs = val
                .parse::<u64>()
                .map_err(|err| parse_err(line, format!("invalid hold-time '{}': {}", val, err)))?;
            Setting::HoldTime(secs)
        }
        "connect-retry" => {
            let val = value.ok_or_else(|| parse_err(line, "connect-retry requires a value"))?;
            let secs = val.parse::<u64>().map_err(|err| {
                parse_err(line, format!("invalid connect-retry '{}': {}", val, err))
            })?;
            Setting::ConnectRetry(secs)
        }
        "cluster-id" => {
            let val = value.ok_or_else(|| parse_err(line, "cluster-id requires a value"))?;
            let cid = val
                .parse::<std::net::Ipv4Addr>()
                .map_err(|err| parse_err(line, format!("invalid cluster-id '{}': {}", val, err)))?;
            Setting::ClusterId(cid)
        }
        "address" => {
            let val = value.ok_or_else(|| parse_err(line, "address requires a value"))?;
            Setting::Address(val.to_string())
        }
        "remote-as" => {
            let val = value.ok_or_else(|| parse_err(line, "remote-as requires a value"))?;
            let asn = val
                .parse::<u32>()
                .map_err(|err| parse_err(line, format!("invalid remote-as '{}': {}", val, err)))?;
            Setting::RemoteAs(asn)
        }
        "port" => {
            let val = value.ok_or_else(|| parse_err(line, "port requires a value"))?;
            let port = val
                .parse::<u16>()
                .map_err(|err| parse_err(line, format!("invalid port '{}': {}", val, err)))?;
            Setting::Port(port)
        }
        "interface" => {
            let val = value.ok_or_else(|| parse_err(line, "interface requires a value"))?;
            Setting::Interface(val.to_string())
        }
        "md5-key-file" => {
            let val = value.ok_or_else(|| parse_err(line, "md5-key-file requires a value"))?;
            Setting::Md5KeyFile(val.to_string())
        }
        "ttl-min" => {
            let val = value.ok_or_else(|| parse_err(line, "ttl-min requires a value"))?;
            let ttl = val
                .parse::<u8>()
                .map_err(|err| parse_err(line, format!("invalid ttl-min '{}': {}", val, err)))?;
            Setting::TtlMin(ttl)
        }
        "next-hop-self" => Setting::NextHopSelf(parse_bool(keyword, value, line)?),
        "passive" => Setting::Passive(parse_bool(keyword, value, line)?),
        "rr-client" => Setting::RrClient(parse_bool(keyword, value, line)?),
        "rs-client" => Setting::RsClient(parse_bool(keyword, value, line)?),
        "graceful-shutdown" => Setting::GracefulShutdown(parse_bool(keyword, value, line)?),
        "announce" => {
            let val = value.ok_or_else(|| parse_err(line, "announce requires a prefix"))?;
            Setting::Announce(val.to_string())
        }
        _ => return Err(parse_err(line, format!("unknown setting '{}'", keyword))),
    };
    settings.push(setting);
    Ok(())
}

pub(crate) fn parse_bgp_body(
    tokens: &[Token],
    pos: &mut usize,
) -> Result<BgpServiceBody, ParseError> {
    let mut body = BgpServiceBody::default();
    let mut words: Vec<String> = Vec::new();
    let mut start_line = 0;

    while *pos < tokens.len() {
        let token = &tokens[*pos];
        match &token.kind {
            TokenKind::Word(word) => {
                if words.is_empty() {
                    start_line = token.line;
                }
                words.push(word.clone());
                *pos += 1;
            }
            TokenKind::OpenBrace => {
                if words.is_empty() {
                    return Err(parse_err(token.line, "unexpected '{'"));
                }
                *pos += 1;
                match words[0].as_str() {
                    "peer" => {
                        let name = words
                            .get(1)
                            .ok_or_else(|| parse_err(start_line, "peer requires a name"))?
                            .clone();
                        let peer = parse_peer_block(name, tokens, pos)?;
                        body.peers.push(peer);
                    }
                    "policy" => {
                        let name = words
                            .get(1)
                            .ok_or_else(|| parse_err(start_line, "policy requires a name"))?
                            .clone();
                        let policy = parse_policy_block(name, tokens, pos)?;
                        body.policies.push(policy);
                    }
                    "prefix-list" => {
                        let name = words
                            .get(1)
                            .ok_or_else(|| parse_err(start_line, "prefix-list requires a name"))?
                            .clone();
                        let prefix_list = parse_prefix_list_block(name, tokens, pos)?;
                        body.prefix_lists.push(prefix_list);
                    }
                    _ => {
                        return Err(parse_err(
                            start_line,
                            format!("unknown block '{}' in service bgp", words[0]),
                        ));
                    }
                }
                words.clear();
            }
            TokenKind::CloseBrace => {
                if !words.is_empty() {
                    parse_leaf_setting(&words, start_line, &mut body.settings)?;
                    words.clear();
                }
                *pos += 1;
                return Ok(body);
            }
            TokenKind::Newline => {
                if !words.is_empty() {
                    parse_leaf_setting(&words, start_line, &mut body.settings)?;
                    words.clear();
                }
                *pos += 1;
            }
        }
    }

    Err(parse_err(
        current_line(tokens, *pos),
        "unexpected end of input, expected '}'",
    ))
}

fn parse_peer_block(
    name: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<PeerBlock, ParseError> {
    let mut settings = Vec::new();
    let mut families = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut start_line = 0;

    while *pos < tokens.len() {
        let token = &tokens[*pos];
        match &token.kind {
            TokenKind::Word(word) => {
                if words.is_empty() {
                    start_line = token.line;
                }
                words.push(word.clone());
                *pos += 1;
            }
            TokenKind::OpenBrace => {
                if words.is_empty() {
                    return Err(parse_err(token.line, "unexpected '{'"));
                }
                *pos += 1;
                match words[0].as_str() {
                    "family" => {
                        let afi = words
                            .get(1)
                            .ok_or_else(|| parse_err(start_line, "family requires afi"))?
                            .clone();
                        let safi = words
                            .get(2)
                            .ok_or_else(|| parse_err(start_line, "family requires safi"))?
                            .clone();
                        let family = parse_family_block(afi, safi, tokens, pos)?;
                        families.push(family);
                    }
                    _ => {
                        return Err(parse_err(
                            start_line,
                            format!("unknown block '{}' in peer", words[0]),
                        ));
                    }
                }
                words.clear();
            }
            TokenKind::CloseBrace => {
                if !words.is_empty() {
                    parse_leaf_setting(&words, start_line, &mut settings)?;
                    words.clear();
                }
                *pos += 1;
                return Ok(PeerBlock {
                    name,
                    settings,
                    families,
                });
            }
            TokenKind::Newline => {
                if !words.is_empty() {
                    parse_leaf_setting(&words, start_line, &mut settings)?;
                    words.clear();
                }
                *pos += 1;
            }
        }
    }

    Err(parse_err(
        current_line(tokens, *pos),
        "unexpected end of input, expected '}'",
    ))
}

fn parse_family_block(
    afi: String,
    safi: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<FamilyBlock, ParseError> {
    let mut directives = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut start_line = 0;

    while *pos < tokens.len() {
        let token = &tokens[*pos];
        match &token.kind {
            TokenKind::Word(word) => {
                if words.is_empty() {
                    start_line = token.line;
                }
                words.push(word.clone());
                *pos += 1;
            }
            TokenKind::OpenBrace => {
                return Err(parse_err(token.line, "unexpected '{' inside family"));
            }
            TokenKind::CloseBrace => {
                if !words.is_empty() {
                    directives.push(parse_family_directive(&words, start_line)?);
                    words.clear();
                }
                *pos += 1;
                return Ok(FamilyBlock {
                    afi,
                    safi,
                    directives,
                });
            }
            TokenKind::Newline => {
                if !words.is_empty() {
                    directives.push(parse_family_directive(&words, start_line)?);
                    words.clear();
                }
                *pos += 1;
            }
        }
    }

    Err(parse_err(
        current_line(tokens, *pos),
        "unexpected end of input, expected '}'",
    ))
}

fn parse_family_directive(words: &[String], line: usize) -> Result<FamilyDirective, ParseError> {
    if words.len() == 3 && words[1] == "policy" {
        match words[0].as_str() {
            "export" => return Ok(FamilyDirective::ExportPolicy(words[2].clone())),
            "import" => return Ok(FamilyDirective::ImportPolicy(words[2].clone())),
            _ => {}
        }
    }
    Err(parse_err(
        line,
        format!("unknown family directive '{}'", words.join(" ")),
    ))
}

fn parse_policy_block(
    name: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<PolicyBlock, ParseError> {
    let mut rules = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut start_line = 0;

    while *pos < tokens.len() {
        let token = &tokens[*pos];
        match &token.kind {
            TokenKind::Word(word) => {
                if words.is_empty() {
                    start_line = token.line;
                }
                words.push(word.clone());
                *pos += 1;
            }
            TokenKind::OpenBrace => {
                return Err(parse_err(token.line, "unexpected '{' inside policy"));
            }
            TokenKind::CloseBrace => {
                if !words.is_empty() {
                    rules.push(parse_policy_rule(&words, start_line)?);
                    words.clear();
                }
                *pos += 1;
                return Ok(PolicyBlock { name, rules });
            }
            TokenKind::Newline => {
                if !words.is_empty() {
                    rules.push(parse_policy_rule(&words, start_line)?);
                    words.clear();
                }
                *pos += 1;
            }
        }
    }

    Err(parse_err(
        current_line(tokens, *pos),
        "unexpected end of input, expected '}'",
    ))
}

fn parse_policy_rule(words: &[String], line: usize) -> Result<PolicyRule, ParseError> {
    if words.len() == 3 && words[0] == "match" {
        return Ok(PolicyRule::Match {
            set_name: words[1].clone(),
            action: words[2].clone(),
        });
    }
    if words.len() == 2 && words[0] == "default" {
        return Ok(PolicyRule::Default {
            action: words[1].clone(),
        });
    }
    Err(parse_err(
        line,
        format!("unknown policy rule '{}'", words.join(" ")),
    ))
}

fn parse_prefix_list_block(
    name: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<PrefixListBlock, ParseError> {
    let mut prefixes = Vec::new();
    let mut words: Vec<String> = Vec::new();

    while *pos < tokens.len() {
        let token = &tokens[*pos];
        match &token.kind {
            TokenKind::Word(word) => {
                words.push(word.clone());
                *pos += 1;
            }
            TokenKind::OpenBrace => {
                return Err(parse_err(token.line, "unexpected '{' inside prefix-list"));
            }
            TokenKind::CloseBrace => {
                if !words.is_empty() {
                    prefixes.push(words.join(" "));
                    words.clear();
                }
                *pos += 1;
                return Ok(PrefixListBlock { name, prefixes });
            }
            TokenKind::Newline => {
                if !words.is_empty() {
                    prefixes.push(words.join(" "));
                    words.clear();
                }
                *pos += 1;
            }
        }
    }

    Err(parse_err(
        current_line(tokens, *pos),
        "unexpected end of input, expected '}'",
    ))
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

  peer kioubit {
    address fe80::ade0
    remote-as 4242423914
    interface kioubit-us3
    md5-key-file /etc/bgp/kioubit.key
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
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert_eq!(body.peers.len(), 2);

        let kioubit = &body.peers[0];
        assert_eq!(kioubit.name, "kioubit");
        assert!(kioubit
            .settings
            .contains(&Setting::Address("fe80::ade0".to_string())));
        assert!(kioubit.settings.contains(&Setting::RemoteAs(4242423914)));
        assert!(kioubit.settings.contains(&Setting::NextHopSelf(true)));
        assert!(kioubit.settings.contains(&Setting::Port(1179)));

        let upstream = &body.peers[1];
        assert_eq!(upstream.name, "upstream");
        assert!(upstream.settings.contains(&Setting::Passive(true)));
        assert!(upstream.settings.contains(&Setting::RrClient(true)));
    }

    #[test]
    fn test_parse_family() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  peer test {
    address 10.0.0.1
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
    fn test_parse_announce() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1
  announce 172.23.211.0/27
  announce fd0d:fbde:bca5::/48
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert!(body
            .settings
            .contains(&Setting::Announce("172.23.211.0/27".to_string())));
        assert!(body
            .settings
            .contains(&Setting::Announce("fd0d:fbde:bca5::/48".to_string())));
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

  peer kioubit {
    address fe80::ade0
    interface kioubit-us3
    remote-as 4242423914
    next-hop-self true
    md5-key-file /etc/bgp/kioubit.key

    family ipv4 unicast {
      export policy mine-only
    }

    family ipv6 unicast {
      export policy mine-only
    }
  }

  announce 172.23.211.0/27
  announce fd0d:fbde:bca5::/48

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
            .contains(&Setting::Announce("172.23.211.0/27".to_string())));
        assert_eq!(body.policies.len(), 1);
        assert_eq!(body.prefix_lists.len(), 1);
        assert!(body.peers[0].settings.contains(&Setting::NextHopSelf(true)));
    }
}
