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

use rustyline::completion::Completer;
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Editor, Helper};

use bgpgg::grpc::BgpClient;

use crate::commands::{self, Command};
use crate::parser::{self, CommandNode};

const HISTORY_FILE: &str = ".ggsh_history";

/// rustyline helper that provides tab completion and ? help.
struct GgshHelper {
    tree: Vec<CommandNode>,
}

impl GgshHelper {
    fn new(tree: Vec<CommandNode>) -> Self {
        GgshHelper { tree }
    }
}

impl Completer for GgshHelper {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<String>)> {
        let input = &line[..pos];
        let candidates = parser::completions(input, &self.tree);

        // Find the start of the current word being completed
        let start = input.rfind(' ').map(|i| i + 1).unwrap_or(0);
        Ok((start, candidates))
    }
}

impl Hinter for GgshHelper {
    type Hint = String;
}

impl Highlighter for GgshHelper {}
impl Validator for GgshHelper {}
impl Helper for GgshHelper {}

fn history_path() -> Option<std::path::PathBuf> {
    dirs_next().map(|home| home.join(HISTORY_FILE))
}

fn dirs_next() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

/// Run the interactive REPL.
pub async fn run(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Two trees: one owned by the rustyline helper (tab completion),
    // one for parsing and ? help in the REPL loop.
    let completion_tree = parser::build_command_tree();
    let parse_tree = parser::build_command_tree();

    let mut editor = Editor::new()?;
    editor.set_helper(Some(GgshHelper::new(completion_tree)));

    if let Some(path) = history_path() {
        let _ = editor.load_history(&path);
    }

    println!("ggshell {}\n", env!("CARGO_PKG_VERSION"));

    // Lazy connection: connect on first command that needs the daemon.
    let mut client: Option<BgpClient> = None;

    loop {
        match editor.readline("ggsh> ") {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let _ = editor.add_history_entry(trimmed);

                match parser::parse(trimmed, &parse_tree) {
                    Ok(Command::Exit) => break,
                    Ok(Command::Help) => {
                        let help_items = parser::help_at(trimmed, &parse_tree);
                        if help_items.is_empty() {
                            println!("  No further completions");
                        } else {
                            for (keyword, help) in &help_items {
                                println!("  {:<20} {}", keyword, help);
                            }
                        }
                    }
                    Ok(Command::HelpAt { ref items }) => {
                        for (keyword, help) in items {
                            println!("  {:<20} {}", keyword, help);
                        }
                    }
                    Ok(cmd) => {
                        if commands::needs_client(&cmd) && client.is_none() {
                            match BgpClient::connect(addr).await {
                                Ok(connected) => client = Some(connected),
                                Err(err) => {
                                    eprintln!(
                                        "Failed to connect to BGP daemon at {}: {}",
                                        addr, err
                                    );
                                    continue;
                                }
                            }
                        }
                        if let Err(err) = commands::execute(&cmd, client.as_ref()).await {
                            eprintln!("Error: {}", err);
                        }
                        println!();
                    }
                    Err(msg) => {
                        if !msg.is_empty() {
                            eprintln!("% {}", msg);
                        }
                    }
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
