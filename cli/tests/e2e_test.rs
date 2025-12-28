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

//! End-to-end tests that execute the compiled CLI binary

use std::process::Command;

fn run_cli(args: &[&str]) -> std::process::Output {
    // Build and run the binary
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "--bin", "bgpgg", "--"]);
    cmd.args(args);
    cmd.output().expect("Failed to execute command")
}

#[test]
fn test_cli_help() {
    let output = run_cli(&["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BGP control CLI"));
    assert!(stdout.contains("peer"));
}

#[test]
fn test_cli_version() {
    let output = run_cli(&["--version"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bgpgg"));
}

#[test]
fn test_peer_help() {
    let output = run_cli(&["peer", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Peer management commands"));
    assert!(stdout.contains("add"));
    assert!(stdout.contains("del"));
    assert!(stdout.contains("show"));
    assert!(stdout.contains("list"));
}

#[test]
fn test_peer_add_help() {
    let output = run_cli(&["peer", "add", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Add a BGP peer"));
}

#[test]
fn test_missing_subcommand() {
    let output = run_cli(&[]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage:"));
}

#[test]
fn test_peer_add_missing_address() {
    let output = run_cli(&["peer", "add"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required arguments"));
}

#[test]
fn test_peer_del_missing_address() {
    let output = run_cli(&["peer", "del"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required arguments"));
}

#[test]
fn test_custom_grpc_address_flag() {
    let output = run_cli(&["--addr", "http://127.0.0.1:9999", "peer", "list"]);

    // This will fail to connect, but we're testing that the flag is accepted
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to connect"));
}

#[test]
fn test_connection_error_message() {
    let output = run_cli(&["--addr", "http://127.0.0.1:19999", "peer", "list"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to connect to BGP daemon"));
}

#[test]
fn test_invalid_grpc_url() {
    let output = run_cli(&["--addr", "not-a-valid-url", "peer", "list"]);

    assert!(!output.status.success());
}
