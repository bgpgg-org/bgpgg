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

use std::fs;
use std::path::Path;
use std::time::Instant;

mod server;
mod utils;

use server::ServerConfig;
use utils::{generate_routes_for_spoke, get_process_memory, setup_topology, TestServer};

#[tokio::main]
async fn main() {
    let impl_name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "bgpgg".to_string());

    // Load config for server under test
    let config_path = format!("core/bench/{}.yaml", impl_name);
    if !Path::new(&config_path).exists() {
        eprintln!("Config not found: {}", config_path);
        eprintln!(
            "Create core/bench/{}.yaml to test this implementation",
            impl_name
        );
        std::process::exit(1);
    }

    let config_content = fs::read_to_string(&config_path).expect("Failed to read config");
    let server_config: ServerConfig =
        serde_yaml::from_str(&config_content).expect("Failed to parse config");

    println!("=== BGP Load Test ({}) ===\n", impl_name);
    run_test(server_config).await.expect("Test failed");
}

async fn run_test(server_config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup topology
    let num_senders = 10;
    let num_receivers = 2;
    let routes_per_sender = 100;
    let expected_total = num_senders * routes_per_sender;

    println!(
        "Setting up topology ({} senders + 1 server + {} receivers)...",
        num_senders, num_receivers
    );
    let setup_start = Instant::now();
    let (server, mut senders, receivers) =
        setup_topology(num_senders, num_receivers, server_config).await?;
    println!("Setup: {:?}\n", setup_start.elapsed());

    // 2. Test ingestion
    println!(
        "Test 1: Route ingestion ({} senders × {} routes -> server)",
        num_senders, routes_per_sender
    );
    let mem_before = get_process_memory();
    let start = Instant::now();
    load_routes_parallel(&mut senders, routes_per_sender).await?;
    poll_server_routes(&server, expected_total).await;
    let elapsed = start.elapsed();
    let mem_after = get_process_memory();

    let routes_per_sec = expected_total as f64 / elapsed.as_secs_f64();
    println!("  Time: {:.2}s", elapsed.as_secs_f64());
    println!("  Throughput: {:.0} routes/sec", routes_per_sec);
    println!(
        "  Memory: {} KB -> {} KB (delta: {} KB)\n",
        mem_before.rss_kb,
        mem_after.rss_kb,
        mem_after.rss_kb.saturating_sub(mem_before.rss_kb)
    );

    // 3. Test propagation to 1 receiver
    println!("Test 2: Route propagation (server -> 1 receiver)");
    let start = Instant::now();
    poll_receiver_routes(&receivers[0], expected_total).await;
    let elapsed = start.elapsed();
    println!("  Time: {:.2}s", elapsed.as_secs_f64());
    println!(
        "  Throughput: {:.0} routes/sec\n",
        expected_total as f64 / elapsed.as_secs_f64()
    );

    // 4. Test propagation to all receivers
    println!(
        "Test 3: Route propagation (server -> {} receivers)",
        num_receivers
    );
    let start = Instant::now();
    poll_all_receivers_routes(&receivers, expected_total).await;
    let elapsed = start.elapsed();
    println!("  Time: {:.2}s", elapsed.as_secs_f64());
    println!(
        "  Per-receiver avg: {:.2}s\n",
        elapsed.as_secs_f64() / num_receivers as f64
    );

    // 5. Test stats collection
    println!("Test 4: Statistics collection");
    let start = Instant::now();
    let peer_count = server.get_peer_count().await?;
    let elapsed = start.elapsed();
    println!("  Time: {:?} for {} peers\n", elapsed, peer_count);

    println!("=== Load Test Complete ===");

    // Drop senders and receivers first so they disconnect cleanly
    drop(senders);
    drop(receivers);

    // Give them a moment to close connections
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Then shutdown the hub
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
        let routes = generate_routes_for_spoke(sender_id, routes_per_sender);

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
