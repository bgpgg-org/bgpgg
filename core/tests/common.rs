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

//! Common test utilities for BGP server testing

use bgpgg::config::Config;
use bgpgg::grpc::proto::bgp_service_server::BgpServiceServer;
use bgpgg::grpc::proto::{BgpState, Peer, Route};
use bgpgg::grpc::{BgpClient, BgpGrpcService};
use bgpgg::server::BgpServer;
use std::net::Ipv4Addr;
use tokio::time::{sleep, Duration};

/// Test server handle that includes runtime for killing the server
pub struct TestServer {
    pub client: BgpClient,
    pub bgp_port: u16,
    pub asn: u16,
    pub address: String,  // IP address the server is bound to (no port)
    runtime: Option<tokio::runtime::Runtime>,
}

impl TestServer {
    /// Kill the BGP server by shutting down its runtime (simulates process death)
    pub fn kill(&mut self) {
        // Shutdown the runtime - this kills ALL tasks in it (simulates process death)
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Shutdown runtime in background when TestServer is dropped
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Helper to check if peer is in a specific BGP state
pub fn peer_in_state(peer: &Peer, state: BgpState) -> bool {
    peer.state == state as i32
}

/// Starts a single BGP server with gRPC interface for testing
///
/// # Arguments
/// * `asn` - Autonomous System Number
/// * `router_id` - Router ID (IPv4 address)
/// * `hold_timer_secs` - BGP hold timer in seconds (defaults to 3 seconds if None)
///
/// Returns a TestServer struct containing the client, port, and abort handles
pub async fn start_test_server(
    asn: u16,
    router_id: Ipv4Addr,
    hold_timer_secs: Option<u16>,
    bind_ip: &str,
) -> TestServer {
    use tokio::net::TcpListener;

    // Bind to port 0 to let OS allocate a free BGP port
    let bgp_listener = TcpListener::bind(format!("{}:0", bind_ip)).await.unwrap();
    let bgp_port = bgp_listener.local_addr().unwrap().port();
    drop(bgp_listener);

    // Bind to port 0 to let OS allocate a free gRPC port
    let grpc_listener = TcpListener::bind("[::1]:0").await.unwrap();
    let grpc_port = grpc_listener.local_addr().unwrap().port();
    drop(grpc_listener);

    // Use the provided hold timer, or default to 3 seconds for testing (short time so peers detect disconnections quickly)
    let hold_timer_secs = hold_timer_secs.unwrap_or(3);
    let config = Config::new(
        asn,
        &format!("{}:{}", bind_ip, bgp_port),
        router_id,
        hold_timer_secs as u64,
    );

    let server = BgpServer::new(config);

    // Create gRPC service
    let grpc_service = BgpGrpcService::new(server.request_tx.clone());

    // Create a separate runtime for this server (simulates separate process)
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Spawn BGP server in its own runtime
    runtime.spawn(async move { server.run().await });

    // Spawn gRPC server in the same runtime
    let grpc_addr = format!("[::1]:{}", grpc_port).parse().unwrap();
    runtime.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(BgpServiceServer::new(grpc_service))
            .serve(grpc_addr)
            .await
            .unwrap();
    });

    // Retry connecting to gRPC server until it's ready
    let mut client = None;
    for _ in 0..50 {
        match BgpClient::connect_with_router_id(format!("http://[::1]:{}", grpc_port), router_id)
            .await
        {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => {
                sleep(Duration::from_millis(100)).await;
            }
        }
    }

    let client = client.expect("Failed to connect to gRPC server after retries");

    TestServer {
        client,
        bgp_port,
        asn,
        address: bind_ip.to_string(),
        runtime: Some(runtime),
    }
}

/// Sets up two BGP servers with peering established
///
/// Server1 (AS65001) <-----> Server2 (AS65002)
///
/// # Arguments
/// * `hold_timer_secs` - BGP hold timer in seconds (defaults to 3 seconds if None)
///
/// Returns (server1, server2) TestServer instances for each server.
/// Both servers will be in Established state when this function returns.
pub async fn setup_two_peered_servers(hold_timer_secs: Option<u16>) -> (TestServer, TestServer) {
    // Start both servers on different loopback IPs - OS allocates ports automatically
    let server1 = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), hold_timer_secs, "127.0.0.1").await;
    let mut server2 = start_test_server(65002, Ipv4Addr::new(2, 2, 2, 2), hold_timer_secs, "127.0.0.2").await;

    // Server2 connects to Server1 via gRPC
    server2
        .client
        .add_peer(format!("127.0.0.1:{}", server1.bgp_port))
        .await
        .expect("Failed to add peer");

    // Wait for peering to establish by polling via gRPC
    for _ in 0..100 {
        let peers1 = server1.client.get_peers().await.unwrap();
        let peers2 = server2.client.get_peers().await.unwrap();

        let both_established = peers1.len() == 1
            && peers2.len() == 1
            && peer_in_state(&peers1[0], BgpState::Established)
            && peer_in_state(&peers2[0], BgpState::Established);

        if both_established {
            return (server1, server2);
        }
        sleep(Duration::from_millis(100)).await;
    }

    panic!("Timeout waiting for peers to establish");
}

/// Sets up three BGP servers in a full mesh topology
///
///     Server1 (AS65001)
///       /  \
///      /    \
/// Server2 -- Server3
/// (AS65002)  (AS65003)
///
/// # Arguments
/// * `hold_timer_secs` - BGP hold timer in seconds (defaults to 3 seconds if None)
///
/// Returns (server1, server2, server3) TestServer instances for each server.
/// All servers will have 2 peers each in Established state when this function returns.
pub async fn setup_three_meshed_servers(
    hold_timer_secs: Option<u16>,
) -> (TestServer, TestServer, TestServer) {
    // Start all three servers on different loopback IPs - OS allocates ports automatically
    let mut server1 = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), hold_timer_secs, "127.0.0.1").await;
    let mut server2 = start_test_server(65002, Ipv4Addr::new(2, 2, 2, 2), hold_timer_secs, "127.0.0.2").await;
    let server3 = start_test_server(65003, Ipv4Addr::new(3, 3, 3, 3), hold_timer_secs, "127.0.0.3").await;

    // Create full mesh: each server peers with the other two
    // Server1 connects to Server2 and Server3
    server1
        .client
        .add_peer(format!("127.0.0.2:{}", server2.bgp_port))
        .await
        .expect("Failed to add peer 2 to server 1");
    server1
        .client
        .add_peer(format!("127.0.0.3:{}", server3.bgp_port))
        .await
        .expect("Failed to add peer 3 to server 1");

    // Server2 connects to Server3 (already connected to Server1)
    server2
        .client
        .add_peer(format!("127.0.0.3:{}", server3.bgp_port))
        .await
        .expect("Failed to add peer 3 to server 2");

    // Wait for all peerings to establish
    for _ in 0..100 {
        let peers1 = server1.client.get_peers().await.unwrap();
        let peers2 = server2.client.get_peers().await.unwrap();
        let peers3 = server3.client.get_peers().await.unwrap();

        let all_established = peers1.len() == 2
            && peers2.len() == 2
            && peers3.len() == 2
            && peers1
                .iter()
                .all(|p| peer_in_state(p, BgpState::Established))
            && peers2
                .iter()
                .all(|p| peer_in_state(p, BgpState::Established))
            && peers3
                .iter()
                .all(|p| peer_in_state(p, BgpState::Established));

        if all_established {
            return (server1, server2, server3);
        }
        sleep(Duration::from_millis(100)).await;
    }

    panic!("Timeout waiting for mesh peers to establish");
}

/// Sets up four BGP servers in a full mesh topology
///
/// (AS65001) (AS65002)
///     S1----S2
///      |\   /|
///      | \ / |
///      | / \ |
///      |/   \|
///     S3----S4
/// (AS65003) (AS65004)
///
/// # Arguments
/// * `hold_timer_secs` - BGP hold timer in seconds (defaults to 3 seconds if None)
///
/// Returns (server1, server2, server3, server4) TestServer instances for each server.
/// All servers will have 3 peers each in Established state when this function returns.
pub async fn setup_four_meshed_servers(
    hold_timer_secs: Option<u16>,
) -> (TestServer, TestServer, TestServer, TestServer) {
    // Start all four servers on different loopback IPs - OS allocates ports automatically
    let mut server1 = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), hold_timer_secs, "127.0.0.1").await;
    let mut server2 = start_test_server(65002, Ipv4Addr::new(2, 2, 2, 2), hold_timer_secs, "127.0.0.2").await;
    let mut server3 = start_test_server(65003, Ipv4Addr::new(3, 3, 3, 3), hold_timer_secs, "127.0.0.3").await;
    let server4 = start_test_server(65004, Ipv4Addr::new(4, 4, 4, 4), hold_timer_secs, "127.0.0.4").await;

    // Create full mesh: each server peers with the other three
    // Server1 connects to Server2, Server3, and Server4
    server1
        .client
        .add_peer(format!("127.0.0.2:{}", server2.bgp_port))
        .await
        .expect("Failed to add peer 2 to server 1");
    server1
        .client
        .add_peer(format!("127.0.0.3:{}", server3.bgp_port))
        .await
        .expect("Failed to add peer 3 to server 1");
    server1
        .client
        .add_peer(format!("127.0.0.4:{}", server4.bgp_port))
        .await
        .expect("Failed to add peer 4 to server 1");

    // Server2 connects to Server3 and Server4 (already connected to Server1)
    server2
        .client
        .add_peer(format!("127.0.0.3:{}", server3.bgp_port))
        .await
        .expect("Failed to add peer 3 to server 2");
    server2
        .client
        .add_peer(format!("127.0.0.4:{}", server4.bgp_port))
        .await
        .expect("Failed to add peer 4 to server 2");

    // Server3 connects to Server4 (already connected to Server1 and Server2)
    server3
        .client
        .add_peer(format!("127.0.0.4:{}", server4.bgp_port))
        .await
        .expect("Failed to add peer 4 to server 3");

    // Wait for all peerings to establish
    for _ in 0..100 {
        let peers1 = server1.client.get_peers().await.unwrap();
        let peers2 = server2.client.get_peers().await.unwrap();
        let peers3 = server3.client.get_peers().await.unwrap();
        let peers4 = server4.client.get_peers().await.unwrap();

        let all_established = peers1.len() == 3
            && peers2.len() == 3
            && peers3.len() == 3
            && peers4.len() == 3
            && peers1
                .iter()
                .all(|p| peer_in_state(p, BgpState::Established))
            && peers2
                .iter()
                .all(|p| peer_in_state(p, BgpState::Established))
            && peers3
                .iter()
                .all(|p| peer_in_state(p, BgpState::Established))
            && peers4
                .iter()
                .all(|p| peer_in_state(p, BgpState::Established));

        if all_established {
            return (server1, server2, server3, server4);
        }
        sleep(Duration::from_millis(100)).await;
    }

    panic!("Timeout waiting for mesh peers to establish");
}

/// Polls for route propagation to multiple servers with expected routes
///
/// # Arguments
/// * `expectations` - Slice of tuples containing (TestServer, expected routes)
pub async fn poll_route_propagation(expectations: &[(&TestServer, Vec<Route>)]) {
    'retry: for _ in 0..100 {
        for (server, expected_routes) in expectations {
            let routes = server.client.get_routes().await.unwrap();

            if routes != *expected_routes {
                sleep(Duration::from_millis(100)).await;
                continue 'retry;
            }
        }
        // All expectations matched
        return;
    }

    panic!("Timeout waiting for routes to propagate");
}

/// Polls for route withdrawal from multiple servers
///
/// # Arguments
/// * `servers` - Slice of TestServer instances to check
pub async fn poll_route_withdrawal(servers: &[&TestServer]) {
    for _ in 0..100 {
        let mut all_withdrawn = true;

        for server in servers.iter() {
            let routes = server.client.get_routes().await.unwrap();
            if !routes.is_empty() {
                all_withdrawn = false;
                break;
            }
        }

        if all_withdrawn {
            return;
        }

        sleep(Duration::from_millis(100)).await;
    }

    panic!("Timeout waiting for route withdrawal");
}

/// Verifies all servers have expected peer count in Established state
///
/// # Arguments
/// * `servers` - Slice of TestServer instances to verify
/// * `expected_peer_count` - Expected number of peers per server
pub async fn verify_peers_established(servers: &[&TestServer], expected_peer_count: usize) {
    for server in servers.iter() {
        let routes = server.client.get_routes().await.unwrap();
        assert!(
            routes.is_empty(),
            "Route not withdrawn from server {}",
            server.client.router_id
        );

        let peers = server.client.get_peers().await.unwrap();
        assert_eq!(
            peers.len(),
            expected_peer_count,
            "Server {} should have {} peers",
            server.client.router_id,
            expected_peer_count
        );
        assert!(
            peers
                .iter()
                .all(|p| peer_in_state(p, BgpState::Established)),
            "Server {} peers should be established",
            server.client.router_id
        );
    }
}
