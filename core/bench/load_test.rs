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
use utils::{generate_routes_for_spoke, get_process_memory, poll_until, setup_topology, TestServer};

#[tokio::main]
async fn main() {
    let impl_name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "bgpgg".to_string());

    // Load config for server under test
    let config_path = format!("core/bench/{}.yaml", impl_name);
    if !Path::new(&config_path).exists() {
        eprintln!("Config not found: {}", config_path);
        eprintln!("Create core/bench/{}.yaml to test this implementation", impl_name);
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
    println!("Setting up topology (1000 senders + 1 server + 10 receivers)...");
    let setup_start = Instant::now();
    let (server, mut senders, receivers) =
        setup_topology(1000, 10, server_config).await?;
    println!("Setup: {:?}\n", setup_start.elapsed());

    // 2. Test ingestion
    println!("Test 1: Route ingestion (1000 senders -> server)");
    let mem_before = get_process_memory();
    let start = Instant::now();
    announce_routes_parallel(&mut senders).await?;
    poll_server_routes(&server, 1_000_000).await;
    let elapsed = start.elapsed();
    let mem_after = get_process_memory();

    let routes_per_sec = 1_000_000.0 / elapsed.as_secs_f64();
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
    poll_receiver_routes(&receivers[0], 1_000_000).await;
    let elapsed = start.elapsed();
    println!("  Time: {:.2}s", elapsed.as_secs_f64());
    println!(
        "  Throughput: {:.0} routes/sec\n",
        1_000_000.0 / elapsed.as_secs_f64()
    );

    // 4. Test propagation to all 10 receivers
    println!("Test 3: Route propagation (server -> 10 receivers)");
    let start = Instant::now();
    poll_all_receivers_routes(&receivers, 1_000_000).await;
    let elapsed = start.elapsed();
    println!("  Time: {:.2}s", elapsed.as_secs_f64());
    println!("  Per-receiver avg: {:.2}s\n", elapsed.as_secs_f64() / 10.0);

    // 5. Test stats collection
    println!("Test 4: Statistics collection");
    let start = Instant::now();
    let peer_count = server.get_peer_count().await?;
    let elapsed = start.elapsed();
    println!("  Time: {:?} for {} peers\n", elapsed, peer_count);

    println!("=== Load Test Complete ===");
    Ok(())
}

async fn announce_routes_parallel(
    senders: &mut Vec<TestServer>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Announce routes from all senders (sequentially for simplicity)
    // Could be parallelized but would need to clone BgpClient or refactor
    for (idx, sender) in senders.iter_mut().enumerate() {
        let sender_id = (idx + 1) as u32;
        let routes = generate_routes_for_spoke(sender_id, 1000);

        for (prefix, next_hop, origin) in routes {
            sender
                .client
                .add_route(prefix, next_hop, origin, vec![], None, None, false, vec![])
                .await?;
        }

        if (idx + 1) % 100 == 0 {
            println!("  Announced routes from {} senders", idx + 1);
        }
    }

    Ok(())
}

async fn poll_server_routes(server: &server::Server, expected: usize) {
    poll_until(
        || async {
            let count = server.get_route_count().await.unwrap_or(0);
            if count > 0 && count % 100_000 == 0 {
                println!("    Server has {} routes...", count);
            }
            count >= expected
        },
        "server routes",
    )
    .await;
}

async fn poll_receiver_routes(receiver: &TestServer, expected: usize) {
    poll_until(
        || async {
            let routes = receiver.client.get_routes().await.unwrap_or_default();
            let count = routes.len();
            if count > 0 && count % 100_000 == 0 {
                println!("    Receiver has {} routes...", count);
            }
            count >= expected
        },
        "receiver routes",
    )
    .await;
}

async fn poll_all_receivers_routes(receivers: &Vec<TestServer>, expected: usize) {
    for (idx, receiver) in receivers.iter().enumerate() {
        println!("    Waiting for receiver {}...", idx + 1);
        poll_receiver_routes(receiver, expected).await;
    }
}
