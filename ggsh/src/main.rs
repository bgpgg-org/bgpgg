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

mod cmd;
mod cmd_bgp;
mod cmd_config;
mod cmd_rpki;
mod cmd_show;
mod grammar;
mod shell;
mod util;

use std::collections::HashMap;

use cmd::Service;
use shell::Shell;

const DEFAULT_BGPGG_ADDR: &str = "http://127.0.0.1:50051";

#[tokio::main]
async fn main() {
    let (grpc_addrs, command) = parse_args();
    let shell = Shell::new(grpc_addrs, command);

    if let Err(err) = shell.run().await {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

fn parse_args() -> (HashMap<Service, String>, Option<Vec<String>>) {
    let mut args = std::env::args().skip(1);
    let mut bgpgg_addr = DEFAULT_BGPGG_ADDR.to_string();
    let mut command = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bgpgg-addr" => {
                bgpgg_addr = args.next().unwrap_or_else(|| {
                    eprintln!("--bgpgg-addr requires a value");
                    std::process::exit(1);
                });
            }
            _ => {
                command.push(arg);
                command.extend(args);
                break;
            }
        }
    }

    let mut grpc_addrs = HashMap::new();
    grpc_addrs.insert(Service::Bgpgg, bgpgg_addr);

    let command = if command.is_empty() {
        None
    } else {
        Some(command)
    };

    (grpc_addrs, command)
}
