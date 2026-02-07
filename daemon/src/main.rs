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

use bgpgg::config::Config;
use bgpgg::grpc::proto::bgp_service_server::BgpServiceServer;
use bgpgg::grpc::BgpGrpcService;
use bgpgg::server::BgpServer;
use clap::Parser;
use std::env;
use std::path::Path;
use tracing::info;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Parser)]
#[command(name = "bgpggd")]
#[command(about = "BGP daemon server", version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<String>,

    /// Autonomous System Number
    #[arg(long)]
    asn: Option<u32>,

    /// Router ID (IPv4 address)
    #[arg(long)]
    router_id: Option<String>,

    /// BGP listen address
    #[arg(long)]
    listen_addr: Option<String>,

    /// gRPC listen address
    #[arg(long)]
    grpc_listen_addr: Option<String>,
}

fn get_env_or<T: std::str::FromStr>(name: &str) -> Option<T> {
    env::var(name).ok()?.parse().ok()
}

fn apply_overrides(config: &mut Config, args: &Args) {
    // CLI args override config, env vars override everything
    if let Some(asn) = args.asn.or_else(|| get_env_or("BGPGG_ASN")) {
        config.asn = asn;
    }

    if let Some(ref router_id) = args.router_id {
        config.router_id = router_id.parse().expect("invalid router-id");
    } else if let Some(router_id) = get_env_or("BGPGG_ROUTER_ID") {
        config.router_id = router_id;
    }

    if let Some(ref addr) = args.listen_addr {
        config.listen_addr = addr.clone();
    } else if let Ok(addr) = env::var("BGPGG_LISTEN_ADDR") {
        config.listen_addr = addr;
    }

    if let Some(ref addr) = args.grpc_listen_addr {
        config.grpc_listen_addr = addr.clone();
    } else if let Ok(addr) = env::var("BGPGG_GRPC_LISTEN_ADDR") {
        config.grpc_listen_addr = addr;
    }

    if let Ok(val) = env::var("BGPGG_LOG_LEVEL") {
        config.log_level = val;
    }

    if let Some(secs) = get_env_or("BGPGG_HOLD_TIME_SECS") {
        config.hold_time_secs = secs;
    }

    if let Some(secs) = get_env_or("BGPGG_CONNECT_RETRY_SECS") {
        config.connect_retry_secs = secs;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Determine config file path: --config flag > BGPGG_CONFIG_PATH env > /etc/bgpgg/config.yaml
    let config_path = args.config.clone().or_else(|| {
        env::var("BGPGG_CONFIG_PATH").ok().or_else(|| {
            let default_path = "/etc/bgpgg/config.yaml";
            if Path::new(default_path).exists() {
                Some(default_path.to_string())
            } else {
                None
            }
        })
    });

    // Load configuration from file or use default
    let mut config = if let Some(path) = config_path {
        Config::from_file(&path).unwrap_or_else(|e| {
            eprintln!("Error: failed to load config from {}: {}", path, e);
            eprintln!("Info: using default configuration");
            Config::default()
        })
    } else {
        Config::default()
    };

    apply_overrides(&mut config, &args);

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
