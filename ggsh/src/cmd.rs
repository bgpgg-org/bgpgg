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

use crate::cmd_bgp;
use crate::cmd_rpki;
use crate::cmd_show;
use crate::util::{parse_afi, parse_safi};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Service {
    Bgpgg,
}

pub enum Client {
    Bgpgg(BgpClient),
}

fn get_bgpgg(clients: &HashMap<Service, Client>) -> Result<&BgpClient, &'static str> {
    match clients.get(&Service::Bgpgg) {
        Some(Client::Bgpgg(client)) => Ok(client),
        _ => Err("not connected to BGP daemon"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    ShowBgpSummary,
    ShowBgpInfo,
    ShowBgpPeers,
    ShowBgpPeer,
    ShowBgpPeerIn,
    ShowBgpPeerOut,
    ShowBgpRoute,
    ShowRpkiCaches,
    ShowRpkiRoa,
    ShowRpkiValidate,
    ShowVersion,
    Exit,
}

impl Command {
    pub fn service(&self) -> Option<Service> {
        match self {
            Command::ShowVersion | Command::Exit => None,
            _ => Some(Service::Bgpgg),
        }
    }

    pub async fn execute(
        &self,
        args: &[String],
        clients: &HashMap<Service, Client>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.service() {
            None => match self {
                Command::ShowVersion => cmd_show::show_version().await,
                Command::Exit => Ok(()),
                _ => Ok(()),
            },
            Some(Service::Bgpgg) => execute_bgpgg(self, args, get_bgpgg(clients)?).await,
        }
    }
}

async fn execute_bgpgg(
    cmd: &Command,
    args: &[String],
    client: &BgpClient,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        Command::ShowBgpSummary => cmd_bgp::show_summary(client).await,
        Command::ShowBgpInfo => cmd_bgp::show_info(client).await,
        Command::ShowBgpPeers => cmd_bgp::show_peers(client).await,
        Command::ShowBgpPeer => cmd_bgp::show_peer(client, &args[0]).await,
        Command::ShowBgpPeerIn => {
            cmd_bgp::show_peer_rib(
                client,
                &args[0],
                "in",
                parse_afi(args.get(1)),
                parse_safi(args.get(2)),
            )
            .await
        }
        Command::ShowBgpPeerOut => {
            cmd_bgp::show_peer_rib(
                client,
                &args[0],
                "out",
                parse_afi(args.get(1)),
                parse_safi(args.get(2)),
            )
            .await
        }
        Command::ShowBgpRoute => cmd_bgp::show_bgp_route(client, args).await,
        Command::ShowRpkiCaches => cmd_rpki::show_caches(client).await,
        Command::ShowRpkiRoa => cmd_rpki::show_roa(client).await,
        Command::ShowRpkiValidate => {
            let prefix = args.first().ok_or("missing prefix")?;
            let origin_as: u32 = args
                .get(1)
                .ok_or("missing ASN")?
                .parse()
                .map_err(|_| "invalid ASN")?;
            cmd_rpki::show_validate(client, prefix, origin_as).await
        }
        Command::ShowVersion | Command::Exit => Ok(()),
    }
}
