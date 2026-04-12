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

struct Args {
    addr: String,
    command: Vec<String>,
}

impl Args {
    fn parse() -> Self {
        let mut args = std::env::args().skip(1);
        let mut addr = DEFAULT_ADDR.to_string();
        let mut command = Vec::new();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--addr" => {
                    addr = args.next().unwrap_or_else(|| {
                        eprintln!("--addr requires a value");
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

        Args { addr, command }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.command.is_empty() {
        if let Err(err) = shell::run(&args.addr).await {
            eprintln!("{}", err);
            std::process::exit(1);
        }
        return;
    }

    // One-shot mode
    let tree = parser::build_command_tree();
    let tokens: Vec<&str> = args.command.iter().map(|s| s.as_str()).collect();

    match parser::parse(&tokens, &tree) {
        Ok(commands::Command::Exit) => {}
        Ok(commands::Command::Help) => {
            let input = args.command.join(" ");
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
                match BgpClient::connect(&args.addr).await {
                    Ok(client) => Some(client),
                    Err(err) => {
                        eprintln!("Failed to connect to BGP daemon at {}: {}", args.addr, err);
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

#[cfg(test)]
mod tests {
    use super::*;

    impl Args {
        fn from(raw: &[&str]) -> Self {
            let iter = raw.iter().map(|s| s.to_string());
            let mut addr = DEFAULT_ADDR.to_string();
            let mut command = Vec::new();
            let mut iter = iter.peekable();

            while let Some(arg) = iter.next() {
                match arg.as_str() {
                    "--addr" => {
                        if let Some(next) = iter.next() {
                            addr = next;
                        }
                    }
                    _ => {
                        command.push(arg);
                        command.extend(iter);
                        break;
                    }
                }
            }

            Args { addr, command }
        }
    }

    #[test]
    fn test_args_default() {
        let args = Args::from(&["show", "bgp", "summary"]);
        assert_eq!(args.addr, DEFAULT_ADDR);
        assert_eq!(args.command, vec!["show", "bgp", "summary"]);
    }

    #[test]
    fn test_args_custom_addr() {
        let args = Args::from(&["--addr", "http://10.0.0.1:50051", "show", "bgp", "summary"]);
        assert_eq!(args.addr, "http://10.0.0.1:50051");
        assert_eq!(args.command, vec!["show", "bgp", "summary"]);
    }

    #[test]
    fn test_args_no_args() {
        let args = Args::from(&[]);
        assert_eq!(args.addr, DEFAULT_ADDR);
        assert!(args.command.is_empty());
    }
}
