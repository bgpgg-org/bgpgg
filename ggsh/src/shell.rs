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
use std::path::PathBuf;

use bgpgg::grpc::BgpClient;
use rustyline::error::ReadlineError;
use rustyline::Editor;

use crate::cmd_bgp;
use crate::cmd_config;
use crate::cmd_configure;
use crate::cmd_rpki;
use crate::cmd_show;
use crate::grammar;
use crate::parser::{self, BgpggCommand, Command, ParseResult, TabCompleter};
use crate::util::{parse_afi, parse_safi};

const HISTORY_FILENAME: &str = "ggsh_history";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellMode {
    Operational,
    Configure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Service {
    Bgpgg,
}

pub enum Client {
    Bgpgg(BgpClient),
}

pub struct Shell {
    grpc_addrs: HashMap<Service, String>,
    command: Option<Vec<String>>,
    tree_op: Vec<crate::grammar::Node>,
    tree_cfg: Vec<crate::grammar::Node>,
    clients: HashMap<Service, Client>,
    pub mode: ShellMode,
    pub candidate: Option<conf::language::Root>,
    pub session_uuid: uuid::Uuid,
    /// EX flock on `<config>.lock` held for the configure session.
    pub session_lock: Option<std::fs::File>,
    pub config_path: PathBuf,
}

impl Shell {
    pub fn new(
        grpc_addrs: HashMap<Service, String>,
        command: Option<Vec<String>>,
        config_path: PathBuf,
    ) -> Self {
        Shell {
            grpc_addrs,
            command,
            tree_op: grammar::tree(),
            tree_cfg: grammar::tree_config(),
            clients: HashMap::new(),
            mode: ShellMode::Operational,
            candidate: None,
            session_uuid: conf::fs::make_session_uuid(),
            session_lock: None,
            config_path,
        }
    }

    fn current_tree(&self) -> &[crate::grammar::Node] {
        match self.mode {
            ShellMode::Operational => &self.tree_op,
            ShellMode::Configure => &self.tree_cfg,
        }
    }

    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(command) = self.command.take() {
            let tokens: Vec<&str> = command.iter().map(|s| s.as_str()).collect();
            return self.run_single(&tokens).await;
        }
        self.run_interactive().await
    }

    async fn connect(&mut self, service: Service) -> Result<(), String> {
        if self.clients.contains_key(&service) {
            return Ok(());
        }
        let addr = self
            .grpc_addrs
            .get(&service)
            .ok_or_else(|| format!("no gRPC address configured for {:?}", service))?;
        let connected = match service {
            Service::Bgpgg => BgpClient::connect(addr).await.map(Client::Bgpgg),
        };
        match connected {
            Ok(client) => {
                self.clients.insert(service, client);
                Ok(())
            }
            Err(err) => Err(format!(
                "Failed to connect to {:?} at {}: {}",
                service, addr, err
            )),
        }
    }

    async fn bgp(&mut self) -> Result<&BgpClient, String> {
        self.connect(Service::Bgpgg).await?;
        match self.clients.get(&Service::Bgpgg) {
            Some(Client::Bgpgg(c)) => Ok(c),
            _ => Err("not connected to BGP daemon".into()),
        }
    }

    /// Dispatch a parsed command. Returns `Ok(None)` to continue,
    /// `Ok(Some(code))` to exit with the given code, `Err` on failure.
    async fn execute(&mut self, cmd: Command, args: &[String]) -> Result<Option<i32>, String> {
        match cmd {
            Command::Exit => return Ok(Some(0)),
            Command::Configure => cmd_configure::enter_configure(self)?,
            Command::Abort => cmd_configure::abort_configure(self)?,
            Command::Version => cmd_show::show_version().await.map_err(|e| e.to_string())?,
            Command::Bgpgg(c) => self.execute_bgpgg(c, args).await?,
        }
        Ok(None)
    }

    async fn execute_bgpgg(&mut self, cmd: BgpggCommand, args: &[String]) -> Result<(), String> {
        let stringify = |e: Box<dyn std::error::Error>| e.to_string();
        let client = self.bgp().await?;
        match cmd {
            BgpggCommand::BgpSummary => cmd_bgp::show_summary(client).await.map_err(stringify),
            BgpggCommand::BgpInfo => cmd_bgp::show_info(client).await.map_err(stringify),
            BgpggCommand::BgpPeers => cmd_bgp::show_peers(client).await.map_err(stringify),
            BgpggCommand::BgpPeer => cmd_bgp::show_peer(client, &args[0])
                .await
                .map_err(stringify),
            BgpggCommand::BgpPeerIn => cmd_bgp::show_peer_rib(
                client,
                &args[0],
                "in",
                parse_afi(args.get(1)),
                parse_safi(args.get(2)),
            )
            .await
            .map_err(stringify),
            BgpggCommand::BgpPeerOut => cmd_bgp::show_peer_rib(
                client,
                &args[0],
                "out",
                parse_afi(args.get(1)),
                parse_safi(args.get(2)),
            )
            .await
            .map_err(stringify),
            BgpggCommand::BgpRoute => cmd_bgp::show_bgp_route(client, args)
                .await
                .map_err(stringify),
            BgpggCommand::RpkiCaches => cmd_rpki::show_caches(client).await.map_err(stringify),
            BgpggCommand::RpkiRoa => cmd_rpki::show_roa(client).await.map_err(stringify),
            BgpggCommand::RpkiValidate => {
                let prefix = args.first().ok_or("missing prefix")?;
                let origin_as: u32 = args
                    .get(1)
                    .ok_or("missing ASN")?
                    .parse()
                    .map_err(|_| "invalid ASN".to_string())?;
                cmd_rpki::show_validate(client, prefix, origin_as)
                    .await
                    .map_err(stringify)
            }
            BgpggCommand::ConfigHistory => {
                cmd_config::show_history(client).await.map_err(stringify)
            }
        }
    }

    async fn run_interactive(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut editor = Editor::new()?;
        editor.set_helper(Some(TabCompleter {
            tree: grammar::tree(),
        }));

        if let Some(path) = history_path() {
            let _ = editor.load_history(&path);
        }

        println!("ggshell {}\n", env!("CARGO_PKG_VERSION"));

        loop {
            let prompt = match self.mode {
                ShellMode::Operational => "ggsh> ",
                ShellMode::Configure => "ggsh(config)> ",
            };
            match editor.readline(prompt) {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let _ = editor.add_history_entry(trimmed);
                    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                    let result = parser::parse(self.current_tree(),&tokens);
                    if self.handle_result(result).await == Some(0) {
                        break;
                    }
                }
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
                Err(err) => {
                    eprintln!("Error: {}", err);
                    break;
                }
            }
        }

        if let Some(path) = history_path() {
            let _ = editor.save_history(&path);
        }
        Ok(())
    }

    async fn run_single(&mut self, tokens: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let result = parser::parse(self.current_tree(),tokens);
        if let Some(code) = self.handle_result(result).await {
            if code != 0 {
                std::process::exit(code);
            }
        }
        Ok(())
    }

    /// Handle a parse result. Returns Some(exit_code) to stop, None to continue.
    async fn handle_result(&mut self, result: ParseResult) -> Option<i32> {
        match result {
            ParseResult::Execution { cmd, args } => match self.execute(cmd, &args).await {
                Ok(Some(code)) => Some(code),
                Ok(None) => {
                    println!();
                    None
                }
                Err(err) => {
                    eprintln!("Error: {}", err);
                    Some(1)
                }
            },
            ParseResult::Help { ref entries } => {
                if entries.is_empty() {
                    println!("  No further completions");
                } else {
                    for entry in entries {
                        println!("  {:<20} {}", entry.keyword, entry.description);
                    }
                }
                None
            }
            ParseResult::Error(ref msg) => {
                if !msg.is_empty() {
                    eprintln!("% {}", msg);
                }
                Some(1)
            }
        }
    }
}

fn history_path() -> Option<PathBuf> {
    let dir = conf::fs::user_state_dir();
    let _ = std::fs::create_dir_all(&dir);
    Some(dir.join(HISTORY_FILENAME))
}
