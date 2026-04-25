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

use bgpgg::grpc::proto::bgp_service_server::BgpServiceServer;
use bgpgg::grpc::BgpGrpcService;
use bgpgg::server::BgpServer;
use clap::Parser;
use std::path::PathBuf;
use std::process;
use tracing::info;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Parser)]
#[command(name = "bgpggd")]
#[command(about = "BGP daemon server", version)]
struct Args {
    /// Path to rogg.conf. Defaults to `$XDG_CONFIG_HOME/rogg/rogg.conf`
    /// (i.e. `~/.config/rogg/rogg.conf`).
    #[arg(short, long, default_value_os_t = conf::fs::default_config_path())]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let server = BgpServer::new(args.config.clone()).unwrap_or_else(|err| {
        eprintln!(
            "Error: failed to start BGP server from {}: {}",
            args.config.display(),
            err
        );
        process::exit(1);
    });

    for peer_config in &server.config.peers {
        if let Err(err) = peer_config.validate() {
            eprintln!(
                "Error: invalid peer configuration ({}): {}",
                peer_config.address, err
            );
            process::exit(1);
        }
    }

    let level = match server.config.log_level.to_lowercase().as_str() {
        "error" => LevelFilter::ERROR,
        "warn" => LevelFilter::WARN,
        "info" => LevelFilter::INFO,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        _ => LevelFilter::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .json()
        .with_current_span(false)
        .with_span_events(FmtSpan::NONE)
        .init();

    let grpc_addr = server.config.grpc_listen_addr.parse()?;

    info!(
        bgp_addr = %server.config.listen_addr,
        grpc_addr = %server.config.grpc_listen_addr,
        asn = server.config.asn,
        router_id = %server.config.router_id,
        "starting BGP daemon"
    );

    let grpc_service = BgpGrpcService::new(server.mgmt_tx.clone());

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "BGP server error");
            }
        },

        result = tonic::transport::Server::builder()
            .add_service(BgpServiceServer::new(grpc_service))
            .serve(grpc_addr) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "gRPC server error");
            }
        },
    }

    Ok(())
}
