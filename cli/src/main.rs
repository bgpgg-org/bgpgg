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

use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "bgpgg")]
#[command(about = "BGP control CLI", version)]
struct Cli {
    /// gRPC server address
    #[arg(long, default_value = "http://[::1]:50051")]
    addr: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Peer management commands
    #[command(subcommand)]
    Peer(PeerCommands),

    /// Global RIB commands
    #[command(subcommand)]
    Global(GlobalCommands),
}

#[derive(Subcommand, Debug)]
pub enum PeerCommands {
    /// Add a BGP peer
    Add {
        /// Peer address (IP:PORT)
        address: String,
        /// Remote AS number
        remote_as: u32,
        /// Maximum number of prefixes to accept
        #[arg(long)]
        max_prefix_limit: Option<u32>,
        /// Action when limit reached: terminate (default) or discard
        #[arg(long, default_value = "terminate")]
        max_prefix_action: String,
    },

    /// Remove a BGP peer
    Del {
        /// Peer address (IP:PORT)
        address: String,
    },

    /// Show specific peer details
    Show {
        /// Peer address (IP:PORT)
        address: String,
    },

    /// List all peers
    List,
}

#[derive(Subcommand, Debug)]
pub enum GlobalCommands {
    /// Global RIB operations
    #[command(subcommand)]
    Rib(RibCommands),

    /// Show server information (AS, router-id, uptime)
    Info,

    /// Show quick statistics overview
    Summary,
}

#[derive(Subcommand, Debug)]
pub enum RibCommands {
    /// Show global RIB (Routing Information Base)
    Show,

    /// Add a route to the global RIB
    Add {
        /// Prefix in CIDR format (e.g., 10.0.0.0/24)
        prefix: String,
        /// Next hop IPv4 address
        #[arg(long)]
        nexthop: String,
        /// Origin type (igp, egp, incomplete)
        #[arg(long, default_value = "igp")]
        origin: String,
        /// AS path segments (e.g., "100 200 300")
        #[arg(long)]
        as_path: Option<String>,
        /// Local preference
        #[arg(long)]
        local_pref: Option<u32>,
        /// Multi-exit discriminator (MED)
        #[arg(long)]
        med: Option<u32>,
        /// Atomic aggregate flag
        #[arg(long)]
        atomic_aggregate: bool,
        /// BGP community (can be specified multiple times, e.g., --community 65001:100 --community NO_EXPORT)
        #[arg(long)]
        community: Vec<String>,
    },

    /// Delete a route from the global RIB
    Del {
        /// Prefix in CIDR format (e.g., 10.0.0.0/24)
        prefix: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Dispatch to command handlers
    match cli.command {
        Commands::Peer(peer_cmd) => {
            commands::peer::handle(cli.addr, peer_cmd)
                .await
                .map_err(|e| format!("Failed to execute command: {}", e))?;
        }
        Commands::Global(global_cmd) => {
            commands::global::handle(cli.addr, global_cmd)
                .await
                .map_err(|e| format!("Failed to execute command: {}", e))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_verify() {
        // Verify the CLI structure is valid
        Cli::command().debug_assert();
    }

    #[test]
    fn test_peer_add_command() {
        let args = vec!["bgpgg", "peer", "add", "192.168.1.1:179", "65001"];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Peer(PeerCommands::Add {
                address, remote_as, ..
            }) => {
                assert_eq!(address, "192.168.1.1:179");
                assert_eq!(remote_as, 65001);
            }
            _ => panic!("Expected Peer Add command"),
        }
    }

    #[test]
    fn test_peer_add_with_max_prefix() {
        let args = vec![
            "bgpgg",
            "peer",
            "add",
            "10.0.0.1:179",
            "65002",
            "--max-prefix-limit",
            "100",
            "--max-prefix-action",
            "discard",
        ];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Peer(PeerCommands::Add {
                address,
                remote_as,
                max_prefix_limit,
                max_prefix_action,
            }) => {
                assert_eq!(address, "10.0.0.1:179");
                assert_eq!(remote_as, 65002);
                assert_eq!(max_prefix_limit, Some(100));
                assert_eq!(max_prefix_action, "discard");
            }
            _ => panic!("Expected Peer Add command"),
        }
    }

    #[test]
    fn test_peer_del_command() {
        let args = vec!["bgpgg", "peer", "del", "10.0.0.1:179"];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Peer(PeerCommands::Del { address }) => {
                assert_eq!(address, "10.0.0.1:179");
            }
            _ => panic!("Expected Peer Del command"),
        }
    }

    #[test]
    fn test_peer_show_command() {
        let args = vec!["bgpgg", "peer", "show", "10.0.0.1:179"];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Peer(PeerCommands::Show { address }) => {
                assert_eq!(address, "10.0.0.1:179");
            }
            _ => panic!("Expected Peer Show command"),
        }
    }

    #[test]
    fn test_peer_list_command() {
        let args = vec!["bgpgg", "peer", "list"];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Peer(PeerCommands::List) => {
                // Success
            }
            _ => panic!("Expected Peer List command"),
        }
    }

    #[test]
    fn test_custom_grpc_address() {
        let args = vec!["bgpgg", "--addr", "http://127.0.0.1:9999", "peer", "list"];
        let cli = Cli::parse_from(args);

        assert_eq!(cli.addr, "http://127.0.0.1:9999");
    }

    #[test]
    fn test_default_grpc_address() {
        let args = vec!["bgpgg", "peer", "list"];
        let cli = Cli::parse_from(args);

        assert_eq!(cli.addr, "http://[::1]:50051");
    }

    #[test]
    fn test_missing_arguments_for_add() {
        // Should fail because address and remote_as are required
        let args = vec!["bgpgg", "peer", "add"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err());

        // Should fail because remote_as is missing
        let args = vec!["bgpgg", "peer", "add", "10.0.0.1:179"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_command() {
        // Should fail because command is required (peer or global)
        let args = vec!["bgpgg"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_global_rib_show_command() {
        let args = vec!["bgpgg", "global", "rib", "show"];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Global(GlobalCommands::Rib(RibCommands::Show)) => {
                // Success
            }
            _ => panic!("Expected Global Rib Show command"),
        }
    }

    #[test]
    fn test_global_rib_add_command() {
        let args = vec![
            "bgpgg",
            "global",
            "rib",
            "add",
            "10.0.0.0/24",
            "--nexthop",
            "192.168.1.1",
        ];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Global(GlobalCommands::Rib(RibCommands::Add {
                prefix,
                nexthop,
                origin,
                ..
            })) => {
                assert_eq!(prefix, "10.0.0.0/24");
                assert_eq!(nexthop, "192.168.1.1");
                assert_eq!(origin, "igp");
            }
            _ => panic!("Expected Global Rib Add command"),
        }
    }

    #[test]
    fn test_global_rib_add_with_attributes() {
        let args = vec![
            "bgpgg",
            "global",
            "rib",
            "add",
            "10.0.0.0/24",
            "--nexthop",
            "192.168.1.1",
            "--origin",
            "incomplete",
            "--as-path",
            "100 200 300",
            "--local-pref",
            "150",
            "--med",
            "50",
            "--atomic-aggregate",
            "--community",
            "65001:100",
            "--community",
            "NO_EXPORT",
        ];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Global(GlobalCommands::Rib(RibCommands::Add {
                prefix,
                nexthop,
                origin,
                as_path,
                local_pref,
                med,
                atomic_aggregate,
                community,
            })) => {
                assert_eq!(prefix, "10.0.0.0/24");
                assert_eq!(nexthop, "192.168.1.1");
                assert_eq!(origin, "incomplete");
                assert_eq!(as_path, Some("100 200 300".to_string()));
                assert_eq!(local_pref, Some(150));
                assert_eq!(med, Some(50));
                assert!(atomic_aggregate);
                assert_eq!(
                    community,
                    vec!["65001:100".to_string(), "NO_EXPORT".to_string()]
                );
            }
            _ => panic!("Expected Global Rib Add command"),
        }
    }

    #[test]
    fn test_global_rib_del_command() {
        let args = vec!["bgpgg", "global", "rib", "del", "10.0.0.0/24"];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Global(GlobalCommands::Rib(RibCommands::Del { prefix })) => {
                assert_eq!(prefix, "10.0.0.0/24");
            }
            _ => panic!("Expected Global Rib Del command"),
        }
    }

    #[test]
    fn test_global_info_command() {
        let args = vec!["bgpgg", "global", "info"];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Global(GlobalCommands::Info) => {
                // Success
            }
            _ => panic!("Expected Global Info command"),
        }
    }

    #[test]
    fn test_global_summary_command() {
        let args = vec!["bgpgg", "global", "summary"];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Global(GlobalCommands::Summary) => {
                // Success
            }
            _ => panic!("Expected Global Summary command"),
        }
    }
}
