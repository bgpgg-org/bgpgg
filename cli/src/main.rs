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
use tonic::transport::Channel;

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
}

#[derive(Subcommand, Debug, PartialEq)]
pub enum PeerCommands {
    /// Add a BGP peer
    Add {
        /// Peer address (IP:PORT)
        address: String,
    },

    /// Remove a BGP peer
    Remove {
        /// Peer address (IP:PORT)
        address: String,
    },

    /// List all peers
    List,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Connect to gRPC server
    let channel = Channel::from_shared(cli.addr.clone())?
        .connect()
        .await
        .map_err(|e| format!("Failed to connect to BGP daemon at {}: {}", cli.addr, e))?;

    // Dispatch to command handlers
    match cli.command {
        Commands::Peer(peer_cmd) => {
            commands::peer::handle(channel, peer_cmd).await?;
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
        let args = vec!["bgpgg", "peer", "add", "192.168.1.1:179"];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Peer(PeerCommands::Add { address }) => {
                assert_eq!(address, "192.168.1.1:179");
            }
            _ => panic!("Expected Peer Add command"),
        }
    }

    #[test]
    fn test_peer_remove_command() {
        let args = vec!["bgpgg", "peer", "remove", "10.0.0.1:179"];
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Peer(PeerCommands::Remove { address }) => {
                assert_eq!(address, "10.0.0.1:179");
            }
            _ => panic!("Expected Peer Remove command"),
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
    fn test_missing_address_for_add() {
        // Should fail because address is required
        let args = vec!["bgpgg", "peer", "add"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_subcommand() {
        // Should fail because subcommand is required
        let args = vec!["bgpgg"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err());
    }
}
