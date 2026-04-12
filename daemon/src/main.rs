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
use conf::bgp::BgpConfig;
use tracing::info;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Parser)]
#[command(name = "bgpggd")]
#[command(about = "BGP daemon server", version)]
struct Args {
    /// Path to rogg.conf configuration file
    #[arg(short, long)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let config = BgpConfig::from_conf_file(&args.config).unwrap_or_else(|err| {
        eprintln!("Error: failed to load config from {}: {}", args.config, err);
        std::process::exit(1);
    });

    // Validate peer configurations
    for peer_config in &config.peers {
        if let Err(err) = peer_config.validate() {
            eprintln!(
                "Error: invalid peer configuration ({}): {}",
                peer_config.address, err
            );
            std::process::exit(1);
        }
    }

    // Initialize tracing subscriber with configured log level
    let level = match config.log_level.to_lowercase().as_str() {
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

    let grpc_addr = config.grpc_listen_addr.parse()?;

    info!(
        bgp_addr = %config.listen_addr,
        grpc_addr = %config.grpc_listen_addr,
        asn = config.asn,
        router_id = %config.router_id,
        "starting BGP daemon"
    );

    // Create BGP server
    let server = BgpServer::new(config)?;

    // Create gRPC service with cloned components
    let grpc_service = BgpGrpcService::new(server.mgmt_tx.clone());

    // Run both servers concurrently
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
