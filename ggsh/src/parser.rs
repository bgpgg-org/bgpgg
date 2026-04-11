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

use crate::commands::Command;

type CommandFn = fn(&[&str]) -> Result<Command, String>;

/// A node in the command tree. Each node has a keyword, optional children,
/// and an optional terminal command that the node resolves to.
pub struct CommandNode {
    pub keyword: &'static str,
    pub help: &'static str,
    pub children: Vec<CommandNode>,
    /// If set, this node is a valid terminal that produces this command.
    pub command: Option<CommandFn>,
    /// If true, this node accepts a freeform argument (e.g. peer address, prefix).
    pub accepts_arg: bool,
}

impl CommandNode {
    fn keyword(keyword: &'static str, help: &'static str) -> Self {
        CommandNode {
            keyword,
            help,
            children: vec![],
            command: None,
            accepts_arg: false,
        }
    }

    fn with_children(mut self, children: Vec<CommandNode>) -> Self {
        self.children = children;
        self
    }

    fn terminal(mut self, command: CommandFn) -> Self {
        self.command = Some(command);
        self
    }

    fn arg(mut self) -> Self {
        self.accepts_arg = true;
        self
    }
}

/// Build the full command tree for ggsh.
pub fn build_command_tree() -> Vec<CommandNode> {
    vec![
        CommandNode::keyword("show", "Show operational information").with_children(vec![
            CommandNode::keyword("bgp", "BGP information").with_children(vec![
                CommandNode::keyword("summary", "Peer table overview")
                    .terminal(|_| Ok(Command::ShowBgpSummary)),
                CommandNode::keyword("info", "Server information")
                    .terminal(|_| Ok(Command::ShowBgpInfo)),
                CommandNode::keyword("peers", "Peer information")
                    .terminal(|_| Ok(Command::ShowBgpPeers))
                    .with_children(vec![
                        // "show bgp peers <address>" -> then optionally "in" or "out"
                        CommandNode::keyword("<address>", "Peer address")
                            .arg()
                            .terminal(|args| {
                                let address = args
                                    .first()
                                    .ok_or_else(|| "missing peer address".to_string())?;
                                Ok(Command::ShowBgpPeer {
                                    address: address.to_string(),
                                })
                            })
                            .with_children(vec![
                                CommandNode::keyword("in", "Adj-RIB-In")
                                    .terminal(|args| {
                                        let address = args
                                            .first()
                                            .ok_or_else(|| "missing peer address".to_string())?;
                                        Ok(Command::ShowBgpPeerIn {
                                            address: address.to_string(),
                                            afi: None,
                                            safi: None,
                                        })
                                    })
                                    .with_children(vec![CommandNode::keyword(
                                        "<afi>",
                                        "Address family (ipv4, ipv6, ls)",
                                    )
                                    .arg()
                                    .terminal(|args| parse_peer_rib_with_afi(args, "in"))
                                    .with_children(vec![CommandNode::keyword(
                                        "<safi>",
                                        "Sub-address family (unicast, multicast)",
                                    )
                                    .arg()
                                    .terminal(|args| parse_peer_rib_with_safi(args, "in"))])]),
                                CommandNode::keyword("out", "Adj-RIB-Out")
                                    .terminal(|args| {
                                        let address = args
                                            .first()
                                            .ok_or_else(|| "missing peer address".to_string())?;
                                        Ok(Command::ShowBgpPeerOut {
                                            address: address.to_string(),
                                            afi: None,
                                            safi: None,
                                        })
                                    })
                                    .with_children(vec![CommandNode::keyword(
                                        "<afi>",
                                        "Address family (ipv4, ipv6, ls)",
                                    )
                                    .arg()
                                    .terminal(|args| parse_peer_rib_with_afi(args, "out"))
                                    .with_children(vec![CommandNode::keyword(
                                        "<safi>",
                                        "Sub-address family (unicast, multicast)",
                                    )
                                    .arg()
                                    .terminal(|args| parse_peer_rib_with_safi(args, "out"))])]),
                            ]),
                    ]),
                CommandNode::keyword("routes", "Routing table")
                    .terminal(|_| Ok(Command::ShowBgpRoute { prefix: None }))
                    .with_children(vec![
                        // Could be a prefix (contains '/') or an AFI keyword
                        CommandNode::keyword("<prefix|afi>", "Prefix (CIDR) or address family")
                            .arg()
                            .terminal(|args| {
                                let arg = args
                                    .first()
                                    .ok_or_else(|| "missing prefix or afi".to_string())?;
                                if arg.contains('/') {
                                    Ok(Command::ShowBgpRoute {
                                        prefix: Some(arg.to_string()),
                                    })
                                } else {
                                    let afi = parse_afi(arg)?;
                                    Ok(Command::ShowBgpRouteFiltered { afi, safi: None })
                                }
                            })
                            .with_children(vec![CommandNode::keyword(
                                "<safi>",
                                "Sub-address family (unicast, multicast)",
                            )
                            .arg()
                            .terminal(|args| {
                                let afi_str =
                                    args.first().ok_or_else(|| "missing afi".to_string())?;
                                let safi_str =
                                    args.get(1).ok_or_else(|| "missing safi".to_string())?;
                                let afi = parse_afi(afi_str)?;
                                let safi = parse_safi(safi_str)?;
                                Ok(Command::ShowBgpRouteFiltered {
                                    afi,
                                    safi: Some(safi),
                                })
                            })]),
                    ]),
            ]),
            CommandNode::keyword("rpki", "RPKI information").with_children(vec![
                CommandNode::keyword("caches", "RPKI cache status")
                    .terminal(|_| Ok(Command::ShowRpkiCaches)),
                CommandNode::keyword("roa", "ROA table").terminal(|_| Ok(Command::ShowRpkiRoa)),
                CommandNode::keyword("validate", "Validate a prefix").with_children(vec![
                    CommandNode::keyword("<prefix>", "Prefix in CIDR format")
                        .arg()
                        .with_children(vec![CommandNode::keyword("origin", "Origin AS keyword")
                            .with_children(vec![CommandNode::keyword("<asn>", "AS number")
                                .arg()
                                .terminal(|args| {
                                    let prefix =
                                        args.first().ok_or_else(|| "missing prefix".to_string())?;
                                    let asn_str =
                                        args.get(1).ok_or_else(|| "missing ASN".to_string())?;
                                    let origin_as: u32 = asn_str
                                        .parse()
                                        .map_err(|_| format!("invalid ASN: {}", asn_str))?;
                                    Ok(Command::ShowRpkiValidate {
                                        prefix: prefix.to_string(),
                                        origin_as,
                                    })
                                })])]),
                ]),
            ]),
            CommandNode::keyword("config", "Current configuration")
                .terminal(|_| Ok(Command::ShowConfig)),
            CommandNode::keyword("version", "Version information")
                .terminal(|_| Ok(Command::ShowVersion)),
        ]),
        CommandNode::keyword("exit", "Exit ggsh").terminal(|_| Ok(Command::Exit)),
        CommandNode::keyword("quit", "Exit ggsh").terminal(|_| Ok(Command::Exit)),
    ]
}

/// Parse a command line into a Command.
pub fn parse(input: &str, tree: &[CommandNode]) -> Result<Command, String> {
    let tokens: Vec<&str> = input.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(String::new());
    }

    // "?", "help", or "--help" at end of line -> help
    let last = tokens.last().copied().unwrap_or("");
    if last == "?" || last == "help" || last == "--help" {
        return Ok(Command::Help);
    }

    parse_tokens(&tokens, tree, &mut vec![])
}

fn parse_tokens(
    tokens: &[&str],
    nodes: &[CommandNode],
    collected_args: &mut Vec<String>,
) -> Result<Command, String> {
    if tokens.is_empty() {
        let items: Vec<(String, String)> = nodes
            .iter()
            .map(|n| (n.keyword.to_string(), n.help.to_string()))
            .collect();
        return Ok(Command::HelpAt { items });
    }

    let token = tokens[0];
    let rest = &tokens[1..];

    for node in nodes {
        let matches = if node.accepts_arg {
            // Arg nodes match anything that isn't a sibling keyword
            let is_keyword = nodes.iter().any(|n| !n.accepts_arg && n.keyword == token);
            !is_keyword
        } else {
            node.keyword == token
        };

        if matches {
            if node.accepts_arg {
                collected_args.push(token.to_string());
            }

            if rest.is_empty() {
                // End of input: this node must be terminal
                if let Some(cmd_fn) = &node.command {
                    let args_refs: Vec<&str> = collected_args.iter().map(|s| s.as_str()).collect();
                    return cmd_fn(&args_refs);
                }
                // Not terminal, show available subcommands
                let items: Vec<(String, String)> = node
                    .children
                    .iter()
                    .map(|c| (c.keyword.to_string(), c.help.to_string()))
                    .collect();
                return Ok(Command::HelpAt { items });
            }

            // More tokens to consume
            if !node.children.is_empty() {
                return parse_tokens(rest, &node.children, collected_args);
            }

            // No children but more tokens -- too many arguments
            if let Some(cmd_fn) = &node.command {
                let args_refs: Vec<&str> = collected_args.iter().map(|s| s.as_str()).collect();
                return cmd_fn(&args_refs);
            }

            return Err(format!("unexpected token: {}", rest[0]));
        }
    }

    // No node matched
    let valid: Vec<&str> = nodes.iter().map(|n| n.keyword).collect();
    Err(format!(
        "unknown command '{}', expected: {}",
        token,
        valid.join(", ")
    ))
}

/// Get completions for a partial input line.
pub fn completions(input: &str, tree: &[CommandNode]) -> Vec<String> {
    let tokens: Vec<&str> = input.split_whitespace().collect();
    let trailing_space = input.ends_with(' ');

    if tokens.is_empty() || (tokens.len() == 1 && !trailing_space) {
        // Completing the first token
        let prefix = tokens.first().copied().unwrap_or("");
        return tree
            .iter()
            .filter(|n| !n.accepts_arg && n.keyword.starts_with(prefix))
            .map(|n| n.keyword.to_string())
            .collect();
    }

    complete_tokens(&tokens, trailing_space, tree)
}

fn complete_tokens(tokens: &[&str], trailing_space: bool, nodes: &[CommandNode]) -> Vec<String> {
    if tokens.is_empty() {
        return nodes
            .iter()
            .filter(|n| !n.accepts_arg)
            .map(|n| n.keyword.to_string())
            .collect();
    }

    let token = tokens[0];
    let rest = &tokens[1..];

    for node in nodes {
        let matches = if node.accepts_arg {
            let is_keyword = nodes.iter().any(|n| !n.accepts_arg && n.keyword == token);
            !is_keyword
        } else {
            node.keyword == token
        };

        if matches {
            if rest.is_empty() && trailing_space {
                // Token fully matched, complete children
                return node
                    .children
                    .iter()
                    .filter(|n| !n.accepts_arg)
                    .map(|n| n.keyword.to_string())
                    .collect();
            }
            if rest.is_empty() && !trailing_space {
                // Partial match of this token level -- but it already fully matches
                // Return this keyword as the sole completion
                if !node.accepts_arg {
                    return vec![node.keyword.to_string()];
                }
                return vec![];
            }
            // Recurse into children
            if !node.children.is_empty() {
                return complete_tokens(rest, trailing_space, &node.children);
            }
            return vec![];
        }
    }

    // No exact match -- partial completion at this level
    if !trailing_space {
        return nodes
            .iter()
            .filter(|n| !n.accepts_arg && n.keyword.starts_with(token))
            .map(|n| n.keyword.to_string())
            .collect();
    }

    vec![]
}

/// Get help text for the current position in the command.
pub fn help_at<'a>(input: &str, tree: &'a [CommandNode]) -> Vec<(&'a str, &'a str)> {
    let tokens: Vec<&str> = input.split_whitespace().collect();
    let tokens: Vec<&str> = tokens
        .iter()
        .filter(|t| !matches!(**t, "?" | "help" | "--help"))
        .copied()
        .collect();
    let stripped = input
        .trim_end_matches('?')
        .trim_end_matches("--help")
        .trim_end_matches("help");
    let trailing_space = stripped.ends_with(' ') || stripped.is_empty();

    help_tokens(&tokens, trailing_space, tree)
}

fn help_tokens<'a>(
    tokens: &[&str],
    trailing_space: bool,
    nodes: &'a [CommandNode],
) -> Vec<(&'a str, &'a str)> {
    if tokens.is_empty() {
        return nodes.iter().map(|n| (n.keyword, n.help)).collect();
    }

    let token = tokens[0];
    let rest = &tokens[1..];

    for node in nodes {
        let matches = if node.accepts_arg {
            let is_keyword = nodes.iter().any(|n| !n.accepts_arg && n.keyword == token);
            !is_keyword
        } else {
            node.keyword == token
        };

        if matches {
            if rest.is_empty() && trailing_space {
                return node.children.iter().map(|n| (n.keyword, n.help)).collect();
            }
            if rest.is_empty() && !trailing_space {
                if !node.accepts_arg {
                    return vec![(node.keyword, node.help)];
                }
                return vec![];
            }
            if !node.children.is_empty() {
                return help_tokens(rest, trailing_space, &node.children);
            }
            return vec![];
        }
    }

    // Partial match
    if !trailing_space {
        return nodes
            .iter()
            .filter(|n| !n.accepts_arg && n.keyword.starts_with(token))
            .map(|n| (n.keyword, n.help))
            .collect();
    }

    vec![]
}

fn parse_afi(afi: &str) -> Result<u32, String> {
    match afi.to_lowercase().as_str() {
        "ipv4" => Ok(1),
        "ipv6" => Ok(2),
        "ls" => Ok(16388),
        _ => Err(format!("unknown AFI '{}', expected: ipv4, ipv6, ls", afi)),
    }
}

fn parse_safi(safi: &str) -> Result<u32, String> {
    match safi.to_lowercase().as_str() {
        "unicast" => Ok(1),
        "multicast" => Ok(2),
        _ => Err(format!(
            "unknown SAFI '{}', expected: unicast, multicast",
            safi
        )),
    }
}

fn parse_peer_rib(args: &[&str], direction: &str, with_safi: bool) -> Result<Command, String> {
    let address = args
        .first()
        .ok_or_else(|| "missing peer address".to_string())?
        .to_string();
    let afi_str = args.get(1).ok_or_else(|| "missing AFI".to_string())?;
    let afi = Some(parse_afi(afi_str)?);
    let safi = if with_safi {
        let safi_str = args.get(2).ok_or_else(|| "missing SAFI".to_string())?;
        Some(parse_safi(safi_str)?)
    } else {
        None
    };
    if direction == "in" {
        Ok(Command::ShowBgpPeerIn { address, afi, safi })
    } else {
        Ok(Command::ShowBgpPeerOut { address, afi, safi })
    }
}

fn parse_peer_rib_with_afi(args: &[&str], direction: &str) -> Result<Command, String> {
    parse_peer_rib(args, direction, false)
}

fn parse_peer_rib_with_safi(args: &[&str], direction: &str) -> Result<Command, String> {
    parse_peer_rib(args, direction, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_commands() {
        let tree = build_command_tree();

        let cases = vec![
            ("show bgp summary", Command::ShowBgpSummary),
            ("show bgp info", Command::ShowBgpInfo),
            ("show bgp peers", Command::ShowBgpPeers),
            (
                "show bgp peers 10.0.0.1",
                Command::ShowBgpPeer {
                    address: "10.0.0.1".to_string(),
                },
            ),
            (
                "show bgp peers 10.0.0.1 in",
                Command::ShowBgpPeerIn {
                    address: "10.0.0.1".to_string(),
                    afi: None,
                    safi: None,
                },
            ),
            (
                "show bgp peers 10.0.0.1 out ipv4",
                Command::ShowBgpPeerOut {
                    address: "10.0.0.1".to_string(),
                    afi: Some(1),
                    safi: None,
                },
            ),
            (
                "show bgp peers 10.0.0.1 in ipv6 unicast",
                Command::ShowBgpPeerIn {
                    address: "10.0.0.1".to_string(),
                    afi: Some(2),
                    safi: Some(1),
                },
            ),
            ("show bgp routes", Command::ShowBgpRoute { prefix: None }),
            (
                "show bgp routes 10.0.0.0/24",
                Command::ShowBgpRoute {
                    prefix: Some("10.0.0.0/24".to_string()),
                },
            ),
            (
                "show bgp routes ipv4",
                Command::ShowBgpRouteFiltered { afi: 1, safi: None },
            ),
            (
                "show bgp routes ipv6 unicast",
                Command::ShowBgpRouteFiltered {
                    afi: 2,
                    safi: Some(1),
                },
            ),
            ("show rpki caches", Command::ShowRpkiCaches),
            ("show rpki roa", Command::ShowRpkiRoa),
            (
                "show rpki validate 10.0.0.0/24 origin 65001",
                Command::ShowRpkiValidate {
                    prefix: "10.0.0.0/24".to_string(),
                    origin_as: 65001,
                },
            ),
            ("show config", Command::ShowConfig),
            ("show version", Command::ShowVersion),
            ("exit", Command::Exit),
            ("quit", Command::Exit),
        ];

        for (input, expected) in cases {
            let result = parse(input, &tree);
            assert_eq!(result.unwrap(), expected, "failed for input: {}", input);
        }
    }

    #[test]
    fn test_parse_errors() {
        let tree = build_command_tree();

        assert!(parse("", &tree).is_err());
        assert!(parse("invalid", &tree).is_err());
        // Non-terminal commands return HelpAt with available subcommands
        let non_terminals = vec!["show", "show bgp", "show rpki validate"];
        for input in non_terminals {
            assert!(
                matches!(parse(input, &tree), Ok(Command::HelpAt { .. })),
                "expected HelpAt for input: {}",
                input
            );
        }
    }

    #[test]
    fn test_completions() {
        let tree = build_command_tree();

        let cases = vec![
            ("", vec!["show", "exit", "quit"]),
            ("sh", vec!["show"]),
            ("show ", vec!["bgp", "rpki", "config", "version"]),
            ("show bgp ", vec!["summary", "info", "peers", "routes"]),
            ("show bgp s", vec!["summary"]),
            ("show rpki ", vec!["caches", "roa", "validate"]),
        ];

        for (input, expected) in cases {
            let mut result = completions(input, &tree);
            let mut expected: Vec<String> = expected.into_iter().map(String::from).collect();
            result.sort();
            expected.sort();
            assert_eq!(
                result, expected,
                "completions failed for input: {:?}",
                input
            );
        }
    }

    #[test]
    fn test_help_at() {
        let tree = build_command_tree();

        let help = help_at("show ?", &tree);
        let keywords: Vec<&str> = help.iter().map(|(k, _)| *k).collect();
        assert!(keywords.contains(&"bgp"));
        assert!(keywords.contains(&"rpki"));
        assert!(keywords.contains(&"config"));
        assert!(keywords.contains(&"version"));

        let help = help_at("show bgp ?", &tree);
        let keywords: Vec<&str> = help.iter().map(|(k, _)| *k).collect();
        assert!(keywords.contains(&"summary"));
        assert!(keywords.contains(&"info"));
        assert!(keywords.contains(&"peers"));
        assert!(keywords.contains(&"routes"));
    }

    #[test]
    fn test_parse_afi_safi() {
        assert_eq!(parse_afi("ipv4").unwrap(), 1);
        assert_eq!(parse_afi("ipv6").unwrap(), 2);
        assert_eq!(parse_afi("ls").unwrap(), 16388);
        assert!(parse_afi("bad").is_err());

        assert_eq!(parse_safi("unicast").unwrap(), 1);
        assert_eq!(parse_safi("multicast").unwrap(), 2);
        assert!(parse_safi("bad").is_err());
    }

    #[test]
    fn test_help_triggers() {
        let tree = build_command_tree();

        for keyword in &["?", "help", "--help"] {
            assert_eq!(parse(keyword, &tree).unwrap(), Command::Help);
            assert_eq!(
                parse(&format!("show {}", keyword), &tree).unwrap(),
                Command::Help
            );
            assert_eq!(
                parse(&format!("show bgp {}", keyword), &tree).unwrap(),
                Command::Help
            );
            assert_eq!(
                parse(&format!("show bgp peers {}", keyword), &tree).unwrap(),
                Command::Help
            );
        }
    }
}
