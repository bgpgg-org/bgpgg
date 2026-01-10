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

use bgpgg::grpc::proto::BgpState;
use clap::Parser;
use std::fs;
use std::path::Path;
use std::time::Instant;

mod server;
mod utils;

use server::ServerConfig;
use utils::{generate_routes_for_sender, get_process_memory, setup_topology, TestServer};

#[derive(Parser)]
#[command(name = "load_test")]
#[command(about = "BGP load testing tool")]
struct Args {
    /// BGP implementation to test (config file name without .yaml)
    #[arg(default_value = "bgpgg")]
    implementation: String,

    /// Number of sender peers
    #[arg(long, default_value = "10")]
    senders: usize,

    /// Number of receiver peers
    #[arg(long, default_value = "10")]
    receivers: usize,

    /// Routes per sender
    #[arg(long, default_value = "1000")]
    routes: usize,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let config_path = format!("core/loadtests/{}.yaml", args.implementation);
    if !Path::new(&config_path).exists() {
        eprintln!("Config not found: {}", config_path);
        eprintln!(
            "Create core/loadtests/{}.yaml to test this implementation",
            args.implementation
        );
        std::process::exit(1);
    }

    let config_content = fs::read_to_string(&config_path).expect("Failed to read config");
    let server_config: ServerConfig =
        serde_yaml::from_str(&config_content).expect("Failed to parse config");

    println!("=== BGP Load Test ({}) ===", args.implementation);
    println!(
        "Config: {} senders, {} receivers, {} routes/sender\n",
        args.senders, args.receivers, args.routes
    );
    run_test(server_config, args.senders, args.receivers, args.routes)
        .await
        .expect("Test failed");
}

async fn run_test(
    server_config: ServerConfig,
    num_senders: usize,
    num_receivers: usize,
    routes_per_sender: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    test_route_ingestion(server_config.clone(), num_senders, routes_per_sender).await?;
    test_route_propagation(server_config, num_senders, num_receivers, routes_per_sender).await?;

    println!("=== Load Test Complete ===");

    Ok(())
}

async fn test_route_ingestion(
    server_config: ServerConfig,
    num_senders: usize,
    routes_per_sender: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Test: Route ingestion ({} senders × {} routes -> server)",
        num_senders, routes_per_sender
    );

    let (server, mut senders, _receivers) = setup_topology(num_senders, 0, server_config).await?;

    let expected_total = num_senders * routes_per_sender;

    // Connect peers first
    println!("  Connecting peers...");
    let server_bgp_addr = "127.0.1.1:17900";
    for sender in &mut senders {
        sender
            .client
            .add_peer(server_bgp_addr.to_string(), None)
            .await?;
    }

    // Wait for sessions to establish
    println!("  Waiting for BGP sessions to establish...");
    for _ in 0..30 {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let mut all_established = true;
        for sender in &senders {
            let peers = sender.client.get_peers().await.unwrap_or_default();
            if !peers
                .iter()
                .any(|p| p.state == BgpState::Established as i32)
            {
                all_established = false;
                break;
            }
        }

        if all_established {
            println!("  All sessions established!");
            break;
        }
    }

    // Now load routes and measure ingestion
    println!("  Loading routes into senders...");
    let mem_before = get_process_memory();
    let start = Instant::now();

    load_routes_parallel(&mut senders, routes_per_sender).await?;
    poll_server_routes(&server, expected_total).await;

    let elapsed = start.elapsed();
    let mem_after = get_process_memory();

    println!("  Time: {:.2}s", elapsed.as_secs_f64());
    println!(
        "  Throughput: {:.0} routes/sec",
        expected_total as f64 / elapsed.as_secs_f64()
    );
    println!(
        "  Memory: {} KB -> {} KB (delta: {} KB)\n",
        mem_before.rss_kb,
        mem_after.rss_kb,
        mem_after.rss_kb.saturating_sub(mem_before.rss_kb)
    );

    drop(senders);
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    server.shutdown();

    Ok(())
}

async fn test_route_propagation(
    server_config: ServerConfig,
    num_senders: usize,
    num_receivers: usize,
    routes_per_sender: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Test: Route propagation (server -> {} receivers)",
        num_receivers
    );

    let (server, mut senders, mut receivers) =
        setup_topology(num_senders, num_receivers, server_config).await?;

    let expected_total = num_senders * routes_per_sender;

    // Connect senders to server
    println!("  Connecting senders...");
    let server_bgp_addr = "127.0.1.1:17900";
    for sender in &mut senders {
        sender
            .client
            .add_peer(server_bgp_addr.to_string(), None)
            .await?;
    }

    // Wait for sessions to establish
    println!("  Waiting for BGP sessions to establish...");
    for _ in 0..30 {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let mut all_established = true;
        for sender in &senders {
            let peers = sender.client.get_peers().await.unwrap_or_default();
            if !peers
                .iter()
                .any(|p| p.state == BgpState::Established as i32)
            {
                all_established = false;
                break;
            }
        }

        if all_established {
            println!("  All sessions established!");
            break;
        }
    }

    // Load routes into senders
    println!("  Loading routes into senders...");
    load_routes_parallel(&mut senders, routes_per_sender).await?;

    // Wait for server to receive routes
    poll_server_routes(&server, expected_total).await;

    // Connect receivers and measure propagation
    println!("  Connecting receivers...");
    let start = Instant::now();

    for receiver in &mut receivers {
        receiver
            .client
            .add_peer(server_bgp_addr.to_string(), None)
            .await?;
    }

    poll_all_receivers_routes(&receivers, expected_total).await;
    let elapsed = start.elapsed();

    println!("  Time: {:.2}s", elapsed.as_secs_f64());
    println!(
        "  Per-receiver avg: {:.2}s\n",
        elapsed.as_secs_f64() / num_receivers as f64
    );

    drop(senders);
    drop(receivers);
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    server.shutdown();

    Ok(())
}

async fn load_routes_parallel(
    senders: &mut Vec<TestServer>,
    routes_per_sender: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "  Loading routes into {} senders in parallel...",
        senders.len()
    );

    let mut handles = vec![];

    for (idx, sender) in senders.iter_mut().enumerate() {
        let sender_id = (idx + 1) as u32;
        let routes = generate_routes_for_sender(sender_id, routes_per_sender);

        // Spawn parallel task for each sender
        let mut client = sender.client.clone();
        let handle = tokio::spawn(async move { client.add_route_stream(routes).await });

        handles.push(handle);
    }

    // Wait for all to complete
    let mut total = 0;
    for (idx, handle) in handles.into_iter().enumerate() {
        let count = handle.await??;
        total += count;

        if (idx + 1) % 10 == 0 {
            println!("    {} senders completed", idx + 1);
        }
    }

    println!("  All routes loaded into senders ({} total)", total);

    // Verify the expected total was loaded
    if total as usize != senders.len() * routes_per_sender {
        return Err(format!(
            "Loaded {} routes but expected {}",
            total,
            senders.len() * routes_per_sender
        )
        .into());
    }

    Ok(())
}

async fn poll_server_routes(server: &server::Server, expected: usize) {
    println!("  Waiting for server to receive {} routes...", expected);
    let mut last_count = 0;
    let mut iterations = 0;

    // Poll for up to 120 seconds
    for _ in 0..1200 {
        let count = server.get_route_count().await.unwrap_or(0);

        // Print progress every 5 seconds or when count changes significantly
        iterations += 1;
        if iterations % 50 == 0 || (count > 0 && count != last_count && count % 50_000 == 0) {
            println!(
                "    Server has {} / {} routes ({:.1}%)",
                count,
                expected,
                (count as f64 / expected as f64) * 100.0
            );
            last_count = count;
        }

        if count >= expected {
            println!("    Server received all {} routes!", count);
            return;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    panic!("Timeout waiting for server routes");
}

async fn poll_receiver_routes(receiver: &TestServer, expected: usize) {
    let mut iterations = 0;

    // Poll for up to 120 seconds
    for _ in 0..1200 {
        let routes = receiver.client.get_routes().await.unwrap_or_default();
        let count = routes.len();

        // Print progress every 5 seconds
        iterations += 1;
        if iterations % 50 == 0 {
            println!(
                "    Receiver has {} / {} routes ({:.1}%)",
                count,
                expected,
                (count as f64 / expected as f64) * 100.0
            );
        }

        if count >= expected {
            return;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    panic!("Timeout waiting for receiver routes");
}

async fn poll_all_receivers_routes(receivers: &Vec<TestServer>, expected: usize) {
    for (idx, receiver) in receivers.iter().enumerate() {
        println!("    Waiting for receiver {}...", idx + 1);
        poll_receiver_routes(receiver, expected).await;
    }
}
