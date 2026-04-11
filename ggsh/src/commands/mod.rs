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

pub mod bgp;
pub mod rpki;
pub mod show;

use bgpgg::grpc::BgpClient;

/// Parsed command ready for execution.
#[derive(Debug, PartialEq)]
pub enum Command {
    // show bgp
    ShowBgpSummary,
    ShowBgpInfo,
    ShowBgpPeers,
    ShowBgpPeer {
        address: String,
    },
    ShowBgpPeerIn {
        address: String,
        afi: Option<u32>,
        safi: Option<u32>,
    },
    ShowBgpPeerOut {
        address: String,
        afi: Option<u32>,
        safi: Option<u32>,
    },
    ShowBgpRoute {
        prefix: Option<String>,
    },
    ShowBgpRouteFiltered {
        afi: u32,
        safi: Option<u32>,
    },

    // show rpki
    ShowRpkiCaches,
    ShowRpkiRoa,
    ShowRpkiValidate {
        prefix: String,
        origin_as: u32,
    },

    // show config / version
    ShowConfig,
    ShowVersion,

    // shell
    Exit,
    Help,
    HelpAt {
        items: Vec<(String, String)>,
    },
}

/// Returns true if the command needs a daemon connection.
pub fn needs_client(cmd: &Command) -> bool {
    !matches!(
        cmd,
        Command::ShowVersion | Command::Exit | Command::Help | Command::HelpAt { .. }
    )
}

/// Execute a parsed command against the BGP daemon.
pub async fn execute(
    cmd: &Command,
    client: Option<&BgpClient>,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        Command::ShowVersion => return show::show_version().await,
        Command::Exit | Command::Help => return Ok(()),
        _ => {}
    }

    let client = client.ok_or("not connected to BGP daemon")?;

    match cmd {
        Command::ShowBgpSummary => bgp::show_summary(client).await,
        Command::ShowBgpInfo => bgp::show_info(client).await,
        Command::ShowBgpPeers => bgp::show_peers(client).await,
        Command::ShowBgpPeer { address } => bgp::show_peer(client, address).await,
        Command::ShowBgpPeerIn { address, afi, safi } => {
            bgp::show_peer_rib(client, address, "in", *afi, *safi).await
        }
        Command::ShowBgpPeerOut { address, afi, safi } => {
            bgp::show_peer_rib(client, address, "out", *afi, *safi).await
        }
        Command::ShowBgpRoute { prefix } => bgp::show_route(client, prefix.as_deref()).await,
        Command::ShowBgpRouteFiltered { afi, safi } => {
            bgp::show_route_filtered(client, *afi, *safi).await
        }

        Command::ShowRpkiCaches => rpki::show_caches(client).await,
        Command::ShowRpkiRoa => rpki::show_roa(client).await,
        Command::ShowRpkiValidate { prefix, origin_as } => {
            rpki::show_validate(client, prefix, *origin_as).await
        }

        Command::ShowConfig => show::show_config(client).await,
        Command::ShowVersion | Command::Exit | Command::Help | Command::HelpAt { .. } => Ok(()),
    }
}
