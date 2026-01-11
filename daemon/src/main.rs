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
use bgpgg::log;
use bgpgg::server::BgpServer;
use clap::Parser;
use serde_json::json;

#[derive(Parser)]
#[command(name = "bgpggd")]
#[command(about = "BGP daemon server", version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Load configuration
    let config = Config::from_file(&args.config).unwrap_or_else(|e| {
        eprintln!("Error: failed to load config from {}: {}", &args.config, e);
        eprintln!("Info: using default configuration");
        Config::default()
    });

    let grpc_addr = config.grpc_listen_addr.parse()?;

    println!(
        "{}",
        json!({
            "timestamp": log::get_timestamp(),
            "level": "INFO",
            "message": "starting BGP daemon",
            "bgp_addr": &config.listen_addr,
            "grpc_addr": &config.grpc_listen_addr,
            "asn": config.asn,
            "router_id": config.router_id.to_string()
        })
    );

    // Create BGP server
    let server = BgpServer::new(config)?;

    // Create gRPC service with cloned components
    let grpc_service = BgpGrpcService::new(server.mgmt_tx.clone());

    // Run both servers concurrently
    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                eprintln!("{}", json!({
                    "timestamp": log::get_timestamp(),
                    "level": "ERROR",
                    "message": "BGP server error",
                    "error": e.to_string()
                }));
            }
        },

        result = tonic::transport::Server::builder()
            .add_service(BgpServiceServer::new(grpc_service))
            .serve(grpc_addr) => {
            if let Err(e) = result {
                eprintln!("{}", json!({
                    "timestamp": log::get_timestamp(),
                    "level": "ERROR",
                    "message": "gRPC server error",
                    "error": e.to_string()
                }));
            }
        },
    }

    Ok(())
}
