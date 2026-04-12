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

use std::collections::HashMap;

use bgpgg::grpc::BgpClient;
use rustyline::completion::Completer;
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Editor, Helper};

use crate::cmd::{Client, Command, Service};
use crate::grammar;
use crate::grammar::Node;

const HISTORY_FILE: &str = ".ggsh_history";

pub struct HelpEntry {
    pub keyword: String,
    pub description: String,
}

pub enum ParseResult {
    Execution { cmd: Command, args: Vec<String> },
    Help { entries: Vec<HelpEntry> },
    Error(String),
}

struct TabCompleter {
    tree: Vec<Node>,
}

impl Completer for TabCompleter {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<String>)> {
        let input = &line[..pos];
        let candidates = completions(&self.tree, input);

        let start = input.rfind(' ').map(|i| i + 1).unwrap_or(0);
        Ok((start, candidates))
    }
}

impl Hinter for TabCompleter {
    type Hint = String;
}

impl Highlighter for TabCompleter {}
impl Validator for TabCompleter {}
impl Helper for TabCompleter {}

pub struct Shell {
    grpc_addrs: HashMap<Service, String>,
    command: Option<Vec<String>>,
    tree: Vec<Node>,
    clients: HashMap<Service, Client>,
}

impl Shell {
    pub fn new(grpc_addrs: HashMap<Service, String>, command: Option<Vec<String>>) -> Self {
        Shell {
            grpc_addrs,
            command,
            tree: grammar::tree(),
            clients: HashMap::new(),
        }
    }

    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(command) = self.command.take() {
            let tokens: Vec<&str> = command.iter().map(|s| s.as_str()).collect();
            return self.run_single(&tokens).await;
        }

        self.run_interactive().await
    }

    async fn connect(&mut self, service: Service) -> Result<(), String> {
        if self.clients.contains_key(&service) {
            return Ok(());
        }
        let addr = self
            .grpc_addrs
            .get(&service)
            .ok_or_else(|| format!("no gRPC address configured for {:?}", service))?;
        let connected = match service {
            Service::Bgpgg => BgpClient::connect(addr).await.map(Client::Bgpgg),
        };
        match connected {
            Ok(client) => {
                self.clients.insert(service, client);
            }
            Err(err) => {
                return Err(format!(
                    "Failed to connect to {:?} at {}: {}",
                    service, addr, err
                ));
            }
        }
        Ok(())
    }

    async fn execute(&mut self, cmd: Command, args: &[String]) -> Result<(), String> {
        if let Some(service) = cmd.service() {
            self.connect(service).await?;
        }
        cmd.execute(args, &self.clients)
            .await
            .map_err(|err| err.to_string())
    }

    async fn run_interactive(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut editor = Editor::new()?;
        editor.set_helper(Some(TabCompleter {
            tree: grammar::tree(),
        }));

        if let Some(path) = history_path() {
            let _ = editor.load_history(&path);
        }

        println!("ggshell {}\n", env!("CARGO_PKG_VERSION"));

        loop {
            match editor.readline("ggsh> ") {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    let _ = editor.add_history_entry(trimmed);

                    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                    let result = parse(&self.tree, &tokens);
                    if self.handle_result(result).await == Some(0) {
                        break;
                    }
                }
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
                Err(err) => {
                    eprintln!("Error: {}", err);
                    break;
                }
            }
        }

        if let Some(path) = history_path() {
            let _ = editor.save_history(&path);
        }

        Ok(())
    }

    async fn run_single(&mut self, tokens: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let result = parse(&self.tree, tokens);
        if let Some(code) = self.handle_result(result).await {
            if code != 0 {
                std::process::exit(code);
            }
        }
        Ok(())
    }

    /// Handle a parse result. Returns Some(exit_code) to stop, None to continue.
    async fn handle_result(&mut self, result: ParseResult) -> Option<i32> {
        match result {
            ParseResult::Execution {
                cmd: Command::Exit, ..
            } => Some(0),
            ParseResult::Help { ref entries } => {
                if entries.is_empty() {
                    println!("  No further completions");
                } else {
                    for entry in entries {
                        println!("  {:<20} {}", entry.keyword, entry.description);
                    }
                }
                None
            }
            ParseResult::Execution { cmd, ref args } => {
                if let Err(err) = self.execute(cmd, args).await {
                    eprintln!("Error: {}", err);
                    return Some(1);
                }
                println!();
                None
            }
            ParseResult::Error(ref msg) => {
                if !msg.is_empty() {
                    eprintln!("% {}", msg);
                }
                Some(1)
            }
        }
    }
}

fn parse(tree: &[Node], tokens: &[&str]) -> ParseResult {
    if tokens.is_empty() {
        return ParseResult::Error("no command entered".to_string());
    }

    let last = tokens[tokens.len() - 1];
    if matches!(last, "?" | "help" | "--help") {
        // Walk preceding tokens to find position, then return children as help
        let preceding = &tokens[..tokens.len() - 1];
        let mut nodes = tree;
        for &token in preceding {
            match find_match(token, nodes) {
                Some(node) => nodes = &node.children,
                None => break,
            }
        }
        let items = nodes
            .iter()
            .map(|n| HelpEntry {
                keyword: n.name.to_string(),
                description: n.help.to_string(),
            })
            .collect();
        return ParseResult::Help { entries: items };
    }

    let mut nodes = tree;
    let mut args = Vec::new();
    let mut last_node: Option<&Node> = None;

    for (idx, &token) in tokens.iter().enumerate() {
        match find_match(token, nodes) {
            Some(node) => {
                if node.is_arg() {
                    args.push(token.to_string());
                }
                last_node = Some(node);
                if idx < tokens.len() - 1 {
                    if node.children.is_empty() {
                        if let Some(cmd) = node.command {
                            return ParseResult::Execution { cmd, args };
                        }
                        return ParseResult::Error(format!(
                            "unexpected token: {}",
                            tokens[idx + 1]
                        ));
                    }
                    nodes = &node.children;
                }
            }
            None => {
                let valid: Vec<&str> = nodes.iter().map(|n| n.name).collect();
                return ParseResult::Error(format!(
                    "unknown command '{}', expected: {}",
                    token,
                    valid.join(", ")
                ));
            }
        }
    }

    match last_node.and_then(|node| node.command) {
        Some(cmd) => ParseResult::Execution { cmd, args },
        _ => {
            // Show children of the last matched node.
            let help_nodes = last_node
                .filter(|n| !n.children.is_empty())
                .map(|n| n.children.as_slice())
                .unwrap_or(nodes);
            let items = help_nodes
                .iter()
                .map(|n| HelpEntry {
                    keyword: n.name.to_string(),
                    description: n.help.to_string(),
                })
                .collect();
            ParseResult::Help { entries: items }
        }
    }
}

fn completions(tree: &[Node], input: &str) -> Vec<String> {
    let tokens: Vec<&str> = input.split_whitespace().collect();
    let completing_next = input.ends_with(' ');
    let mut nodes = tree;

    let walk_count = if completing_next {
        tokens.len()
    } else {
        tokens.len().saturating_sub(1)
    };
    for &token in &tokens[..walk_count] {
        match find_match(token, nodes) {
            Some(node) => nodes = &node.children,
            None => return vec![],
        }
    }

    let prefix = if completing_next {
        ""
    } else {
        tokens.last().copied().unwrap_or("")
    };

    nodes
        .iter()
        .filter(|n| !n.is_arg() && n.name.starts_with(prefix))
        .map(|n| n.name.to_string())
        .collect()
}

fn find_match<'a>(token: &str, nodes: &'a [Node]) -> Option<&'a Node> {
    if let Some(node) = nodes.iter().find(|n| !n.is_arg() && n.name == token) {
        return Some(node);
    }
    nodes.iter().find(|n| n.is_arg())
}

fn history_path() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(HISTORY_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_cmd(input: &str) -> (Command, Vec<String>) {
        let root = grammar::tree();
        let tokens: Vec<&str> = input.split_whitespace().collect();
        match parse(&root, &tokens) {
            ParseResult::Execution { cmd, args } => (cmd, args),
            _ => panic!("expected Command for '{}'", input),
        }
    }

    #[test]
    fn test_parse_commands() {
        let cases = vec![
            ("show bgp summary", Command::ShowBgpSummary, vec![]),
            ("show bgp info", Command::ShowBgpInfo, vec![]),
            ("show bgp peers", Command::ShowBgpPeers, vec![]),
            (
                "show bgp peers 10.0.0.1",
                Command::ShowBgpPeer,
                vec!["10.0.0.1"],
            ),
            (
                "show bgp peers 10.0.0.1 in",
                Command::ShowBgpPeerIn,
                vec!["10.0.0.1"],
            ),
            (
                "show bgp peers 10.0.0.1 out ipv4",
                Command::ShowBgpPeerOut,
                vec!["10.0.0.1", "ipv4"],
            ),
            (
                "show bgp peers 10.0.0.1 in ipv6 unicast",
                Command::ShowBgpPeerIn,
                vec!["10.0.0.1", "ipv6", "unicast"],
            ),
            ("show bgp routes", Command::ShowBgpRoute, vec![]),
            (
                "show bgp routes 10.0.0.0/24",
                Command::ShowBgpRoute,
                vec!["10.0.0.0/24"],
            ),
            ("show bgp routes ipv4", Command::ShowBgpRoute, vec!["ipv4"]),
            (
                "show bgp routes ipv6 unicast",
                Command::ShowBgpRoute,
                vec!["ipv6", "unicast"],
            ),
            ("show rpki caches", Command::ShowRpkiCaches, vec![]),
            ("show rpki roa", Command::ShowRpkiRoa, vec![]),
            (
                "show rpki validate 10.0.0.0/24 origin 65001",
                Command::ShowRpkiValidate,
                vec!["10.0.0.0/24", "65001"],
            ),
            ("show version", Command::ShowVersion, vec![]),
            ("exit", Command::Exit, vec![]),
            ("quit", Command::Exit, vec![]),
        ];

        for (input, expected_cmd, expected_args) in cases {
            let (cmd, args) = parse_cmd(input);
            assert_eq!(cmd, expected_cmd, "wrong command for: {}", input);
            let expected_args: Vec<String> = expected_args.iter().map(|s| s.to_string()).collect();
            assert_eq!(args, expected_args, "wrong args for: {}", input);
        }
    }

    #[test]
    fn test_parse_errors() {
        let root = grammar::tree();

        for input in &["", "invalid"] {
            let tokens: Vec<&str> = input.split_whitespace().collect();
            assert!(
                matches!(parse(&root, &tokens), ParseResult::Error(_)),
                "expected Error for: {}",
                input
            );
        }

        for input in &["show", "show bgp", "show rpki validate"] {
            let tokens: Vec<&str> = input.split_whitespace().collect();
            assert!(
                matches!(parse(&root, &tokens), ParseResult::Help { .. }),
                "expected Help for: {}",
                input
            );
        }

        // "show bgp" should show bgp's children, not show's children
        match parse(&root, &["show", "bgp"]) {
            ParseResult::Help { entries } => {
                let keywords: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
                assert!(
                    keywords.contains(&"summary"),
                    "expected summary in: {:?}",
                    keywords
                );
                assert!(
                    keywords.contains(&"peers"),
                    "expected peers in: {:?}",
                    keywords
                );
                assert!(
                    !keywords.contains(&"rpki"),
                    "should not contain rpki: {:?}",
                    keywords
                );
            }
            other => panic!(
                "expected Help for 'show bgp', got: {:?}",
                matches!(other, ParseResult::Error(_))
            ),
        }

        // "show" should show show's children
        match parse(&root, &["show"]) {
            ParseResult::Help { entries } => {
                let keywords: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
                assert!(keywords.contains(&"bgp"), "expected bgp in: {:?}", keywords);
                assert!(
                    keywords.contains(&"rpki"),
                    "expected rpki in: {:?}",
                    keywords
                );
                assert!(
                    keywords.contains(&"version"),
                    "expected version in: {:?}",
                    keywords
                );
            }
            other => panic!(
                "expected Help for 'show', got: {:?}",
                matches!(other, ParseResult::Error(_))
            ),
        }
    }

    #[test]
    fn test_completions() {
        let root = grammar::tree();

        let cases = vec![
            ("", vec!["show", "exit", "quit"]),
            ("sh", vec!["show"]),
            ("show ", vec!["bgp", "rpki", "version"]),
            ("show bgp ", vec!["summary", "info", "peers", "routes"]),
            ("show bgp s", vec!["summary"]),
            ("show rpki ", vec!["caches", "roa", "validate"]),
        ];

        for (input, expected) in cases {
            let mut result = completions(&root, input);
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
    fn test_help() {
        let root = grammar::tree();

        // "show ?" returns show's children
        match parse(&root, &["show", "?"]) {
            ParseResult::Help { entries } => {
                let keywords: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
                assert!(keywords.contains(&"bgp"));
                assert!(keywords.contains(&"rpki"));
                assert!(keywords.contains(&"version"));
            }
            _ => panic!("expected HelpAt"),
        }

        // "show bgp ?" returns bgp's children
        match parse(&root, &["show", "bgp", "?"]) {
            ParseResult::Help { entries } => {
                let keywords: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
                assert!(keywords.contains(&"summary"));
                assert!(keywords.contains(&"info"));
                assert!(keywords.contains(&"peers"));
                assert!(keywords.contains(&"routes"));
            }
            _ => panic!("expected HelpAt"),
        }

        // bare "?" returns top-level help
        match parse(&root, &["?"]) {
            ParseResult::Help { entries } => {
                let keywords: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
                assert!(keywords.contains(&"show"));
                assert!(keywords.contains(&"exit"));
            }
            _ => panic!("expected HelpAt"),
        }
    }
}
