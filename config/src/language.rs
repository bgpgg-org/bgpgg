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

//! Lexer and parser for the rogg config language.
//!
//! ## Syntax
//!
//! ```text
//! config    = statement*
//! statement = WORD+ ( '{' statement* '}' | NEWLINE )
//! WORD      = non-whitespace chars excluding '{' and '}'
//! ```
//!
//! `#` starts a line comment, stripped before tokenization.
//!
//! The parser is context-sensitive: it recognizes rogg keywords and produces
//! a typed AST. Each scope (root, BGP body, peer body, etc.) has its own
//! parse function with a keyword dispatch table.
//!
//! ## Pipeline
//!
//! ```text
//! source text -> tokenize() -> Vec<Token> -> parse() -> Root (typed AST)
//! ```
//!
//! ## Example
//!
//! ```text
//! service bgp {
//!   asn 65001
//!   peer myPeer {
//!     address fe80::ade0
//!     remote-as 4242423914
//!   }
//! }
//! ```

use std::fmt;

/// Root of the parsed config file.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Root {
    pub services: Vec<Service>,
}

/// A `service <kind> { ... }` block.
#[derive(Debug, Clone, PartialEq)]
pub enum Service {
    Bgp(BgpServiceBody),
}

/// Body of `service bgp { ... }`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BgpServiceBody {
    pub settings: Vec<Setting>,
    pub peers: Vec<PeerBlock>,
    pub policies: Vec<PolicyBlock>,
    pub prefix_lists: Vec<PrefixListBlock>,
    pub announces: Vec<Announce>,
}

/// Leaf config statement. Value is None for boolean flags like `next-hop-self`.
#[derive(Debug, Clone, PartialEq)]
pub struct Setting {
    pub key: SettingKey,
    pub value: Option<String>,
}

/// Known config keywords for leaf statements.
#[derive(Debug, Clone, PartialEq)]
pub enum SettingKey {
    Asn,
    RouterId,
    ListenAddr,
    GrpcListenAddr,
    LogLevel,
    HoldTime,
    ConnectRetry,
    ClusterId,
    Address,
    RemoteAs,
    Port,
    Interface,
    Md5KeyFile,
    TtlMin,
    NextHopSelf,
    Passive,
    RrClient,
    RsClient,
    GracefulShutdown,
    Unknown(String),
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

/// `announce <prefix>` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Announce {
    pub prefix: String,
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

impl Setting {
    /// Get the value as a string slice, if present.
    pub fn value_str(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl BgpServiceBody {
    pub fn setting(&self, key: SettingKey) -> Option<&Setting> {
        self.settings.iter().find(|s| s.key == key)
    }
}

impl PeerBlock {
    pub fn setting(&self, key: SettingKey) -> Option<&Setting> {
        self.settings.iter().find(|s| s.key == key)
    }
}

fn classify_keyword(word: &str) -> SettingKey {
    match word {
        "asn" => SettingKey::Asn,
        "router-id" => SettingKey::RouterId,
        "listen-addr" => SettingKey::ListenAddr,
        "grpc-listen-addr" => SettingKey::GrpcListenAddr,
        "log-level" => SettingKey::LogLevel,
        "hold-time" => SettingKey::HoldTime,
        "connect-retry" => SettingKey::ConnectRetry,
        "cluster-id" => SettingKey::ClusterId,
        "address" => SettingKey::Address,
        "remote-as" => SettingKey::RemoteAs,
        "port" => SettingKey::Port,
        "interface" => SettingKey::Interface,
        "md5-key-file" => SettingKey::Md5KeyFile,
        "ttl-min" => SettingKey::TtlMin,
        "next-hop-self" => SettingKey::NextHopSelf,
        "passive" => SettingKey::Passive,
        "rr-client" => SettingKey::RrClient,
        "rs-client" => SettingKey::RsClient,
        "graceful-shutdown" => SettingKey::GracefulShutdown,
        other => SettingKey::Unknown(other.to_string()),
    }
}

/// Parse error with line number and description.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

fn parse_err(line: usize, message: impl Into<String>) -> ParseError {
    ParseError {
        line,
        message: message.into(),
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Token {
    kind: TokenKind,
    line: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum TokenKind {
    Word(String),
    OpenBrace,
    CloseBrace,
    Newline,
}

const CHAR_OPENING_BRACE: char = '{';
const CHAR_CLOSING_BRACE: char = '}';
const CHAR_COMMENT: char = '#';

/// Lexer. Produces a token stream from source text.
fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();

    for (line_idx, line) in input.lines().enumerate() {
        let line_num = line_idx + 1;

        let line = match line.find(CHAR_COMMENT) {
            Some(pos) => &line[..pos],
            None => line,
        };

        let mut chars = line.chars().peekable();
        while let Some(&ch) = chars.peek() {
            if ch.is_whitespace() {
                chars.next();
                continue;
            }
            if ch == CHAR_OPENING_BRACE {
                tokens.push(Token {
                    kind: TokenKind::OpenBrace,
                    line: line_num,
                });
                chars.next();
            } else if ch == CHAR_CLOSING_BRACE {
                tokens.push(Token {
                    kind: TokenKind::CloseBrace,
                    line: line_num,
                });
                chars.next();
            } else {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || c == CHAR_OPENING_BRACE || c == CHAR_CLOSING_BRACE {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                tokens.push(Token {
                    kind: TokenKind::Word(word),
                    line: line_num,
                });
            }
        }

        tokens.push(Token {
            kind: TokenKind::Newline,
            line: line_num,
        });
    }

    tokens
}

fn current_line(tokens: &[Token], pos: usize) -> usize {
    if pos < tokens.len() {
        tokens[pos].line
    } else {
        tokens.last().map(|t| t.line).unwrap_or(0)
    }
}

/// Classify a leaf statement into a setting.
/// 1 word -> flag (value=None), 2 words -> key-value, 3+ words -> unknown block.
fn flush_leaf(words: &[String], settings: &mut Vec<Setting>, unknown: &mut Vec<UnknownBlock>) {
    match words.len() {
        0 => {}
        1 => settings.push(Setting {
            key: classify_keyword(&words[0]),
            value: None,
        }),
        2 => settings.push(Setting {
            key: classify_keyword(&words[0]),
            value: Some(words[1].clone()),
        }),
        _ => unknown.push(UnknownBlock {
            words: words.to_vec(),
            children: vec![],
        }),
    }
}

/// Parse rogg config text into a typed AST.
pub fn parse(input: &str) -> Result<Root, ParseError> {
    let tokens = tokenize(input);
    let mut pos = 0;
    parse_root(&tokens, &mut pos)
}

fn parse_root(tokens: &[Token], pos: &mut usize) -> Result<Root, ParseError> {
    let mut root = Root::default();
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
                if words[0] != "service" {
                    return Err(parse_err(
                        start_line,
                        format!("unknown top-level block '{}'", words[0]),
                    ));
                }
                if words.len() < 2 {
                    return Err(parse_err(start_line, "service requires a name"));
                }
                if words[1] != "bgp" {
                    return Err(parse_err(
                        start_line,
                        format!("unknown service '{}'", words[1]),
                    ));
                }
                *pos += 1;
                let body = parse_bgp_body(tokens, pos)?;
                root.services.push(Service::Bgp(body));
                words.clear();
            }
            TokenKind::CloseBrace => {
                return Err(parse_err(token.line, "unexpected '}'"));
            }
            TokenKind::Newline => {
                if !words.is_empty() {
                    return Err(parse_err(
                        start_line,
                        format!("unexpected statement '{}' at root level", words.join(" ")),
                    ));
                }
                *pos += 1;
            }
        }
    }

    if !words.is_empty() {
        return Err(parse_err(
            start_line,
            format!("unexpected statement '{}' at root level", words.join(" ")),
        ));
    }

    Ok(root)
}

fn parse_bgp_body(tokens: &[Token], pos: &mut usize) -> Result<BgpServiceBody, ParseError> {
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
                    flush_bgp_leaf(&mut body, &words);
                    words.clear();
                }
                *pos += 1;
                return Ok(body);
            }
            TokenKind::Newline => {
                if !words.is_empty() {
                    flush_bgp_leaf(&mut body, &words);
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

fn flush_bgp_leaf(body: &mut BgpServiceBody, words: &[String]) {
    if words.len() >= 2 && words[0] == "announce" {
        body.announces.push(Announce {
            prefix: words[1].clone(),
        });
        return;
    }
    flush_leaf(words, &mut body.settings, &mut Vec::new());
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
                    flush_leaf(&words, &mut settings, &mut Vec::new());
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
                    flush_leaf(&words, &mut settings, &mut Vec::new());
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
    if words.len() == 4 && words[0] == "match" && words[2] == "->" {
        return Ok(PolicyRule::Match {
            set_name: words[1].clone(),
            action: words[3].clone(),
        });
    }
    if words.len() == 3 && words[0] == "default" && words[1] == "->" {
        return Ok(PolicyRule::Default {
            action: words[2].clone(),
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

    #[test]
    fn test_parse_empty() {
        let root = parse("").unwrap();
        assert!(root.services.is_empty());

        let root = parse("  \n\n  ").unwrap();
        assert!(root.services.is_empty());

        let root = parse("# just comments\n# nothing else").unwrap();
        assert!(root.services.is_empty());
    }

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
        assert_eq!(
            body.setting(SettingKey::Asn).unwrap().value_str(),
            Some("65001")
        );
        assert_eq!(
            body.setting(SettingKey::RouterId).unwrap().value_str(),
            Some("1.1.1.1")
        );
        assert_eq!(
            body.setting(SettingKey::ListenAddr).unwrap().value_str(),
            Some("127.0.0.1:179")
        );
        assert_eq!(
            body.setting(SettingKey::LogLevel).unwrap().value_str(),
            Some("debug")
        );
        assert_eq!(
            body.setting(SettingKey::HoldTime).unwrap().value_str(),
            Some("90")
        );
        assert_eq!(
            body.setting(SettingKey::ConnectRetry).unwrap().value_str(),
            Some("10")
        );
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
    next-hop-self
    port 1179
    ttl-min 254
  }

  peer upstream {
    address 10.0.0.1
    remote-as 65000
    passive
    rr-client
  }
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert_eq!(body.peers.len(), 2);

        let kioubit = &body.peers[0];
        assert_eq!(kioubit.name, "kioubit");
        assert_eq!(
            kioubit.setting(SettingKey::Address).unwrap().value_str(),
            Some("fe80::ade0")
        );
        assert_eq!(
            kioubit.setting(SettingKey::RemoteAs).unwrap().value_str(),
            Some("4242423914")
        );
        assert!(kioubit.setting(SettingKey::NextHopSelf).is_some());
        assert_eq!(
            kioubit.setting(SettingKey::Port).unwrap().value_str(),
            Some("1179")
        );

        let upstream = &body.peers[1];
        assert_eq!(upstream.name, "upstream");
        assert!(upstream.setting(SettingKey::Passive).is_some());
        assert!(upstream.setting(SettingKey::RrClient).is_some());
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
    match my-prefixes -> accept
    default -> reject
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
        assert_eq!(body.announces.len(), 2);
        assert_eq!(body.announces[0].prefix, "172.23.211.0/27");
        assert_eq!(body.announces[1].prefix, "fd0d:fbde:bca5::/48");
    }

    #[test]
    fn test_parse_unknown_service_errors() {
        let err = parse("service ospf { router-id 1.1.1.1 }").unwrap_err();
        assert!(err.message.contains("unknown service 'ospf'"));
    }

    #[test]
    fn test_parse_comments() {
        let input = "\
# Top-level comment
service bgp {
  asn 65001  # inline comment
  # full line comment
  router-id 1.1.1.1
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert_eq!(
            body.setting(SettingKey::Asn).unwrap().value_str(),
            Some("65001")
        );
        assert_eq!(
            body.setting(SettingKey::RouterId).unwrap().value_str(),
            Some("1.1.1.1")
        );
    }

    #[test]
    fn test_parse_inline_block() {
        let input = "service bgp { asn 65001\nrouter-id 1.1.1.1 }";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert_eq!(
            body.setting(SettingKey::Asn).unwrap().value_str(),
            Some("65001")
        );
    }

    #[test]
    fn test_parse_errors() {
        let cases = vec![
            ("service bgp {", "unexpected end of input"),
            ("}", "unexpected '}'"),
            ("{", "unexpected '{'"),
            ("service {", "service requires a name"),
            ("hostname router01", "unexpected statement"),
        ];

        for (input, expected_msg) in cases {
            let err = parse(input).unwrap_err();
            assert!(
                err.message.contains(expected_msg),
                "for {:?}: expected {:?} in {:?}",
                input,
                expected_msg,
                err.message
            );
        }
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
    next-hop-self
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
    match my-prefixes -> accept
    default -> reject
  }

  prefix-list my-prefixes {
    172.23.211.0/27
    fd0d:fbde:bca5::/48
  }
}";
        let root = parse(input).unwrap();
        assert_eq!(root.services.len(), 1);

        let Service::Bgp(body) = &root.services[0];

        assert_eq!(
            body.setting(SettingKey::Asn).unwrap().value_str(),
            Some("4242423930")
        );
        assert_eq!(body.peers.len(), 1);
        assert_eq!(body.announces.len(), 2);
        assert_eq!(body.policies.len(), 1);
        assert_eq!(body.prefix_lists.len(), 1);
        assert!(body.peers[0].setting(SettingKey::NextHopSelf).is_some());
    }
}
