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
use bgpgg::server::BgpServer;
use bgpgg::{error, info};
use std::env;

fn parse_args() -> Option<String> {
    for arg in env::args() {
        if let Some(path) = arg.strip_prefix("--config-file=") {
            return Some(path.to_string());
        }
    }
    None
}

fn load_config(config_path: Option<String>) -> Config {
    match config_path {
        Some(path) => match Config::from_file(&path) {
            Ok(cfg) => {
                info!("loaded configuration from file", "config_file" => path);
                cfg
            }
            Err(e) => {
                error!("failed to load config file", "config_file" => path, "error" => e.to_string());
                info!("using default configuration");
                Config::default()
            }
        },
        None => {
            info!("no config file specified, using defaults");
            Config::default()
        }
    }
}

#[tokio::main]
async fn main() {
    let config = load_config(parse_args());
    info!("starting BGP server", "asn" => config.asn, "listen_addr" => config.listen_addr.to_string(), "router_id" => config.router_id.to_string());

    BgpServer::new(config).run().await;
}
