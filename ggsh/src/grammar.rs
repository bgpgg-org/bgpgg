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

use crate::cmd::Command;

pub(crate) struct Node {
    pub(crate) name: &'static str,
    pub(crate) help: &'static str,
    pub(crate) children: Vec<Node>,
    pub(crate) command: Option<Command>,
    /// When set, the node accepts freetext input validated by this function.
    /// The matched token is captured into the args list.
    pub(crate) validate: Option<fn(&str) -> bool>,
}

impl Node {
    pub(crate) fn keyword(name: &'static str, help: &'static str) -> Self {
        Node {
            name,
            help,
            children: vec![],
            command: None,
            validate: None,
        }
    }

    pub(crate) fn arg(name: &'static str, help: &'static str, validate: fn(&str) -> bool) -> Self {
        Node {
            name,
            help,
            children: vec![],
            command: None,
            validate: Some(validate),
        }
    }

    pub(crate) fn children(mut self, children: Vec<Node>) -> Self {
        self.children = children;
        self
    }

    pub(crate) fn cmd(mut self, command: Command) -> Self {
        self.command = Some(command);
        self
    }

    pub(crate) fn is_arg(&self) -> bool {
        self.validate.is_some()
    }
}

fn is_prefix(token: &str) -> bool {
    token.contains('/')
}

fn is_ip_addr(token: &str) -> bool {
    token.parse::<std::net::IpAddr>().is_ok()
}

fn is_asn(token: &str) -> bool {
    token.parse::<u32>().is_ok()
}

fn is_afi(token: &str) -> bool {
    matches!(token, "ipv4" | "ipv6" | "ls")
}

fn is_safi(token: &str) -> bool {
    matches!(token, "unicast" | "multicast")
}

pub fn tree() -> Vec<Node> {
    vec![
        Node::keyword("show", "Show operational information").children(vec![
            Node::keyword("bgp", "BGP information").children(tree_show_bgp()),
            Node::keyword("rpki", "RPKI information").children(tree_show_rpki()),
            Node::keyword("config", "Config information").children(tree_show_config()),
            Node::keyword("version", "Version information").cmd(Command::ShowVersion),
        ]),
        Node::keyword("exit", "Exit ggsh").cmd(Command::Exit),
        Node::keyword("quit", "Exit ggsh").cmd(Command::Exit),
    ]
}

/// AFI/SAFI arg nodes. AFI accepts ipv4/ipv6/ls, SAFI accepts unicast/multicast.
fn afi_safi_nodes(cmd: Command) -> Vec<Node> {
    vec![
        Node::arg("<afi>", "Address family (ipv4, ipv6, ls)", is_afi)
            .cmd(cmd)
            .children(vec![Node::arg(
                "<safi>",
                "Sub-address family (unicast, multicast)",
                is_safi,
            )
            .cmd(cmd)]),
    ]
}

fn tree_show_bgp() -> Vec<Node> {
    vec![
        Node::keyword("summary", "Peer table overview").cmd(Command::ShowBgpSummary),
        Node::keyword("info", "Server information").cmd(Command::ShowBgpInfo),
        Node::keyword("peers", "Peer information")
            .cmd(Command::ShowBgpPeers)
            .children(vec![Node::arg("<address>", "Peer address", is_ip_addr)
                .cmd(Command::ShowBgpPeer)
                .children(vec![
                    Node::keyword("in", "Adj-RIB-In")
                        .cmd(Command::ShowBgpPeerIn)
                        .children(afi_safi_nodes(Command::ShowBgpPeerIn)),
                    Node::keyword("out", "Adj-RIB-Out")
                        .cmd(Command::ShowBgpPeerOut)
                        .children(afi_safi_nodes(Command::ShowBgpPeerOut)),
                ])]),
        Node::keyword("routes", "Routing table")
            .cmd(Command::ShowBgpRoute)
            .children({
                let mut nodes = afi_safi_nodes(Command::ShowBgpRoute);
                nodes.push(
                    Node::arg("<prefix>", "Prefix in CIDR format", is_prefix)
                        .cmd(Command::ShowBgpRoute),
                );
                nodes
            }),
    ]
}

fn tree_show_config() -> Vec<Node> {
    vec![Node::keyword("history", "Stored config snapshots").cmd(Command::ShowConfigHistory)]
}

fn tree_show_rpki() -> Vec<Node> {
    vec![
        Node::keyword("caches", "RPKI cache status").cmd(Command::ShowRpkiCaches),
        Node::keyword("roa", "ROA table").cmd(Command::ShowRpkiRoa),
        Node::keyword("validate", "Validate a prefix").children(vec![Node::arg(
            "<prefix>",
            "Prefix in CIDR format",
            is_prefix,
        )
        .children(vec![Node::keyword("origin", "Origin AS keyword").children(
            vec![Node::arg("<asn>", "AS number", is_asn).cmd(Command::ShowRpkiValidate)],
        )])]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_structure() {
        let root = tree();
        let top: Vec<&str> = root.iter().map(|n| n.name).collect();
        assert_eq!(top, vec!["show", "exit", "quit"]);
    }
}
