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

mod commands;
mod parser;
mod shell;

use bgpgg::grpc::BgpClient;

const DEFAULT_ADDR: &str = "http://127.0.0.1:50051";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Extract --addr if present, otherwise default
    let (addr, command_args) = extract_addr(&args[1..]);

    if command_args.is_empty() {
        // Interactive mode
        if let Err(err) = shell::run(&addr).await {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    } else {
        // One-shot mode: join remaining args as a command line
        let input = command_args.join(" ");
        let tree = parser::build_command_tree();

        match parser::parse(&input, &tree) {
            Ok(commands::Command::Exit) => {}
            Ok(commands::Command::Help) => {
                let help_items = parser::help_at(&format!("{} ?", input), &tree);
                for (keyword, help) in &help_items {
                    println!("  {:<20} {}", keyword, help);
                }
            }
            Ok(commands::Command::HelpAt { ref items }) => {
                for (keyword, help) in items {
                    println!("  {:<20} {}", keyword, help);
                }
            }
            Ok(cmd) => {
                let client = if commands::needs_client(&cmd) {
                    match BgpClient::connect(&addr).await {
                        Ok(client) => Some(client),
                        Err(err) => {
                            eprintln!("Failed to connect to BGP daemon at {}: {}", addr, err);
                            std::process::exit(1);
                        }
                    }
                } else {
                    None
                };

                if let Err(err) = commands::execute(&cmd, client.as_ref()).await {
                    eprintln!("Error: {}", err);
                    std::process::exit(1);
                }
            }
            Err(msg) => {
                if !msg.is_empty() {
                    eprintln!("% {}", msg);
                }
                std::process::exit(1);
            }
        }
    }
}

/// Extract --addr <value> from arguments, returning (addr, remaining_args).
fn extract_addr(args: &[String]) -> (String, Vec<String>) {
    let mut addr = DEFAULT_ADDR.to_string();
    let mut remaining = Vec::new();
    let mut skip_next = false;

    for (idx, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--addr" {
            if let Some(next) = args.get(idx + 1) {
                addr = next.clone();
                skip_next = true;
            }
        } else {
            remaining.push(arg.clone());
        }
    }

    (addr, remaining)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_addr_default() {
        let args: Vec<String> = vec!["show".into(), "bgp".into(), "summary".into()];
        let (addr, remaining) = extract_addr(&args);
        assert_eq!(addr, DEFAULT_ADDR);
        assert_eq!(remaining, vec!["show", "bgp", "summary"]);
    }

    #[test]
    fn test_extract_addr_custom() {
        let args: Vec<String> = vec![
            "--addr".into(),
            "http://10.0.0.1:50051".into(),
            "show".into(),
            "bgp".into(),
            "summary".into(),
        ];
        let (addr, remaining) = extract_addr(&args);
        assert_eq!(addr, "http://10.0.0.1:50051");
        assert_eq!(remaining, vec!["show", "bgp", "summary"]);
    }

    #[test]
    fn test_extract_addr_no_args() {
        let args: Vec<String> = vec![];
        let (addr, remaining) = extract_addr(&args);
        assert_eq!(addr, DEFAULT_ADDR);
        assert!(remaining.is_empty());
    }
}
