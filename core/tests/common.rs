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

use bgpgg::bgp::msg::{read_bgp_message, BgpMessage, Message};
use bgpgg::bgp::msg_keepalive::KeepAliveMessage;
use bgpgg::bgp::msg_notification::NotifcationMessage;
use bgpgg::bgp::msg_open::OpenMessage;
use bgpgg::config::Config;
use bgpgg::grpc::proto::bgp_service_server::BgpServiceServer;
use bgpgg::grpc::proto::{AsPathSegment, AsPathSegmentType, BgpState, Origin, Path, Peer, Route};
use bgpgg::grpc::{BgpClient, BgpGrpcService};
use bgpgg::server::BgpServer;
use std::net::Ipv4Addr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

/// Test server handle that includes runtime for killing the server
pub struct TestServer {
    pub client: BgpClient,
    pub bgp_port: u16,
    pub asn: u16,
    pub address: String, // IP address the server is bound to (no port)
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

impl TestServer {
    /// Converts a TestServer to a Peer struct for use in test assertions
    pub fn to_peer(&self, state: BgpState) -> Peer {
        Peer {
            address: self.address.clone(),
            asn: self.asn as u32,
            state: state.into(),
        }
    }
}

/// Helper to check if peer is in a specific BGP state
pub fn peer_in_state(peer: &Peer, state: BgpState) -> bool {
    peer.state == state as i32
}

/// Helper to convert a flat AS list to AS_SEQUENCE segment
pub fn as_sequence(asns: Vec<u32>) -> AsPathSegment {
    AsPathSegment {
        segment_type: AsPathSegmentType::AsSequence.into(),
        asns,
    }
}

/// Helper to create an AS_SET segment
pub fn as_set(asns: Vec<u32>) -> AsPathSegment {
    AsPathSegment {
        segment_type: AsPathSegmentType::AsSet.into(),
        asns,
    }
}

/// Helper to build a Path with AS_PATH segments
pub fn build_path(
    as_path: Vec<AsPathSegment>,
    next_hop: &str,
    peer_address: String,
    origin: Origin,
    local_pref: Option<u32>,
    med: Option<u32>,
    atomic_aggregate: bool,
) -> Path {
    Path {
        origin: origin.into(),
        as_path,
        next_hop: next_hop.to_string(),
        peer_address,
        local_pref,
        med,
        atomic_aggregate,
    }
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
    let grpc_service = BgpGrpcService::new(server.mgmt_tx.clone());

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
/// Server1 (AS65001) <-----> Server2 (AS65001)
///
/// # Arguments
/// * `hold_timer_secs` - BGP hold timer in seconds (defaults to 3 seconds if None)
///
/// Returns (server1, server2) TestServer instances for each server.
/// Both servers will be in Established state when this function returns.
pub async fn setup_two_peered_servers(hold_timer_secs: Option<u16>) -> (TestServer, TestServer) {
    let [server1, server2] = chain_servers([
        start_test_server(
            65001,
            Ipv4Addr::new(1, 1, 1, 1),
            hold_timer_secs,
            "127.0.0.1",
        )
        .await,
        start_test_server(
            65002,
            Ipv4Addr::new(2, 2, 2, 2),
            hold_timer_secs,
            "127.0.0.2",
        )
        .await,
    ])
    .await;

    (server1, server2)
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
    let [server1, server2, server3] = mesh_servers([
        start_test_server(
            65001,
            Ipv4Addr::new(1, 1, 1, 1),
            hold_timer_secs,
            "127.0.0.1",
        )
        .await,
        start_test_server(
            65002,
            Ipv4Addr::new(2, 2, 2, 2),
            hold_timer_secs,
            "127.0.0.2",
        )
        .await,
        start_test_server(
            65003,
            Ipv4Addr::new(3, 3, 3, 3),
            hold_timer_secs,
            "127.0.0.3",
        )
        .await,
    ])
    .await;

    (server1, server2, server3)
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
    let [server1, server2, server3, server4] = mesh_servers([
        start_test_server(
            65001,
            Ipv4Addr::new(1, 1, 1, 1),
            hold_timer_secs,
            "127.0.0.1",
        )
        .await,
        start_test_server(
            65002,
            Ipv4Addr::new(2, 2, 2, 2),
            hold_timer_secs,
            "127.0.0.2",
        )
        .await,
        start_test_server(
            65003,
            Ipv4Addr::new(3, 3, 3, 3),
            hold_timer_secs,
            "127.0.0.3",
        )
        .await,
        start_test_server(
            65004,
            Ipv4Addr::new(4, 4, 4, 4),
            hold_timer_secs,
            "127.0.0.4",
        )
        .await,
    ])
    .await;

    (server1, server2, server3, server4)
}

/// Sets up two ASes connected by one eBGP session
///
/// (AS65001)                    (AS65002)
///     S1----S2                     S7
///      |\   /|                    /  \
///      | \ / |                   /    \
///      | / \ |                  /      \
///      |/   \|                 /        \
///     S3----S4--------eBGP----S5--------S6
///
/// # Arguments
/// * `hold_timer_secs` - BGP hold timer in seconds (defaults to 3 seconds if None)
///
/// Returns (server1, server2, server3, server4, server5, server6, server7) TestServer instances.
/// AS65001 (S1, S2, S3, S4) - fully meshed iBGP (each has 3 peers within AS).
/// AS65002 (S5, S6, S7) - triangle iBGP topology (S5-S6, S5-S7, S6-S7).
/// S4 (AS65001) and S5 (AS65002) connected via eBGP.
/// All connections will be in Established state when this function returns.
pub async fn setup_two_ases_with_ebgp(
    hold_timer_secs: Option<u16>,
) -> (
    TestServer,
    TestServer,
    TestServer,
    TestServer,
    TestServer,
    TestServer,
    TestServer,
) {
    // Start all seven servers on different loopback IPs
    // Island 1: All servers use AS65001 (iBGP mesh)
    let mut server1 = start_test_server(
        65001,
        Ipv4Addr::new(1, 1, 1, 1),
        hold_timer_secs,
        "127.0.0.1",
    )
    .await;
    let mut server2 = start_test_server(
        65001,
        Ipv4Addr::new(2, 2, 2, 2),
        hold_timer_secs,
        "127.0.0.2",
    )
    .await;
    let mut server3 = start_test_server(
        65001,
        Ipv4Addr::new(3, 3, 3, 3),
        hold_timer_secs,
        "127.0.0.3",
    )
    .await;
    let mut server4 = start_test_server(
        65001,
        Ipv4Addr::new(4, 4, 4, 4),
        hold_timer_secs,
        "127.0.0.4",
    )
    .await;
    // Island 2: All servers use AS65002 (iBGP triangle)
    let mut server5 = start_test_server(
        65002,
        Ipv4Addr::new(5, 5, 5, 5),
        hold_timer_secs,
        "127.0.0.5",
    )
    .await;
    let mut server6 = start_test_server(
        65002,
        Ipv4Addr::new(6, 6, 6, 6),
        hold_timer_secs,
        "127.0.0.6",
    )
    .await;
    let server7 = start_test_server(
        65002,
        Ipv4Addr::new(7, 7, 7, 7),
        hold_timer_secs,
        "127.0.0.7",
    )
    .await;

    // Island 1 mesh: S1, S2, S3, S4
    // S1 connects to S2, S3, and S4
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

    // S2 connects to S3 and S4 (already connected to S1)
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

    // S3 connects to S4 (already connected to S1 and S2)
    server3
        .client
        .add_peer(format!("127.0.0.4:{}", server4.bgp_port))
        .await
        .expect("Failed to add peer 4 to server 3");

    // Island 2 triangle: S5, S6, S7
    // S5 connects to S6 and S7
    server5
        .client
        .add_peer(format!("127.0.0.6:{}", server6.bgp_port))
        .await
        .expect("Failed to add peer 6 to server 5");
    server5
        .client
        .add_peer(format!("127.0.0.7:{}", server7.bgp_port))
        .await
        .expect("Failed to add peer 7 to server 5");

    // S6 connects to S7 (already connected to S5)
    server6
        .client
        .add_peer(format!("127.0.0.7:{}", server7.bgp_port))
        .await
        .expect("Failed to add peer 7 to server 6");

    // Bridge connection: S4 (AS65001) to S5 (AS65002) - eBGP
    server4
        .client
        .add_peer(format!("127.0.0.5:{}", server5.bgp_port))
        .await
        .expect("Failed to add eBGP bridge peer 5 to server 4");

    // Wait for all peerings to establish
    poll_until(
        || async {
            // Island 1 full mesh (4 servers)
            verify_peers(
                &server1,
                vec![
                    server2.to_peer(BgpState::Established),
                    server3.to_peer(BgpState::Established),
                    server4.to_peer(BgpState::Established),
                ],
            )
            .await
                && verify_peers(
                    &server2,
                    vec![
                        server1.to_peer(BgpState::Established),
                        server3.to_peer(BgpState::Established),
                        server4.to_peer(BgpState::Established),
                    ],
                )
                .await
                && verify_peers(
                    &server3,
                    vec![
                        server1.to_peer(BgpState::Established),
                        server2.to_peer(BgpState::Established),
                        server4.to_peer(BgpState::Established),
                    ],
                )
                .await
                // S4 has island peers + eBGP bridge to S5
                && verify_peers(
                    &server4,
                    vec![
                        server1.to_peer(BgpState::Established),
                        server2.to_peer(BgpState::Established),
                        server3.to_peer(BgpState::Established),
                        server5.to_peer(BgpState::Established),
                    ],
                )
                .await
                // Island 2 triangle (S5, S6, S7)
                // S5 connects to S6, S7, and eBGP bridge to S4
                && verify_peers(
                    &server5,
                    vec![
                        server4.to_peer(BgpState::Established),
                        server6.to_peer(BgpState::Established),
                        server7.to_peer(BgpState::Established),
                    ],
                )
                .await
                // S6 connects to S5 and S7
                && verify_peers(
                    &server6,
                    vec![
                        server5.to_peer(BgpState::Established),
                        server7.to_peer(BgpState::Established),
                    ],
                )
                .await
                // S7 connects to S5 and S6
                && verify_peers(
                    &server7,
                    vec![
                        server5.to_peer(BgpState::Established),
                        server6.to_peer(BgpState::Established),
                    ],
                )
                .await
        },
        "Timeout waiting for two-island bridge topology to establish",
    )
    .await;

    (
        server1, server2, server3, server4, server5, server6, server7,
    )
}

/// Polls for route propagation to multiple servers with expected routes
///
/// # Arguments
/// * `expectations` - Slice of tuples containing (TestServer, expected routes)
pub async fn poll_route_propagation(expectations: &[(&TestServer, Vec<Route>)]) {
    use std::collections::HashMap;

    poll_until(
        || async {
            for (server, expected_routes) in expectations {
                let Ok(routes) = server.client.get_routes().await else {
                    return false;
                };

                // Convert to HashMaps keyed by prefix for order-independent comparison
                // (routes come from HashMap in RIB, so order is not guaranteed)
                let routes_map: HashMap<_, _> =
                    routes.into_iter().map(|r| (r.prefix.clone(), r)).collect();
                let expected_map: HashMap<_, _> = expected_routes
                    .iter()
                    .map(|r| (r.prefix.clone(), r.clone()))
                    .collect();

                if routes_map != expected_map {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for routes to propagate",
    )
    .await;
}

/// Polls for route withdrawal from multiple servers
///
/// # Arguments
/// * `servers` - Slice of TestServer instances to check
pub async fn poll_route_withdrawal(servers: &[&TestServer]) {
    poll_until(
        || async {
            for server in servers.iter() {
                let Ok(routes) = server.client.get_routes().await else {
                    return false;
                };
                if !routes.is_empty() {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for route withdrawal",
    )
    .await;
}

/// Generic polling helper that retries until a condition is met
///
/// # Arguments
/// * `check` - Async function that returns true when condition is met
/// * `timeout_message` - Message to display if timeout occurs
/// * `max_iterations` - Maximum number of polling attempts (default: 100)
pub async fn poll_until_with_timeout<F, Fut>(check: F, timeout_message: &str, max_iterations: usize)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..max_iterations {
        if check().await {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }

    panic!("{}", timeout_message);
}

/// Generic polling helper that retries until a condition is met (default 10s timeout)
pub async fn poll_until<F, Fut>(check: F, timeout_message: &str)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    poll_until_with_timeout(check, timeout_message, 100).await;
}

/// Verify peer statistics
///
/// # Arguments
/// * `server` - Server to query for peer statistics
/// * `peer_addr` - Address of the peer to check
/// * `expected_open_sent` - Expected number of OPEN messages sent
/// * `expected_open_received` - Expected number of OPEN messages received
/// * `expected_update_sent` - Expected number of UPDATE messages sent
pub async fn verify_peer_statistics(
    server: &TestServer,
    peer_addr: String,
    expected_open_sent: u64,
    expected_open_received: u64,
    expected_update_sent: u64,
) {
    let (peer, stats) = server
        .client
        .get_peer(peer_addr.clone())
        .await
        .expect("Failed to get peer");

    assert!(peer.is_some(), "Peer {} should exist", peer_addr);
    let stats = stats.expect("Statistics should be present");

    assert_eq!(
        stats.open_sent, expected_open_sent,
        "Peer {} should send OPEN {} time(s), got {}",
        peer_addr, expected_open_sent, stats.open_sent
    );
    assert_eq!(
        stats.open_received, expected_open_received,
        "Peer {} should receive OPEN {} time(s), got {}",
        peer_addr, expected_open_received, stats.open_received
    );
    assert_eq!(
        stats.update_sent, expected_update_sent,
        "Peer {} should send UPDATE {} time(s), got {}",
        peer_addr, expected_update_sent, stats.update_sent
    );
}

/// Chains BGP servers together in a linear topology
///
/// Connects each server to the previous one in the chain (server[i] connects to server[i-1]).
/// Waits for all peerings to establish before returning.
///
/// # Arguments
/// * `servers` - Array of servers to chain together
///
/// # Returns
/// The same array of servers after chaining is complete
///
/// # Example
/// ```
/// let [s1, s2, s3] = chain_servers([
///     start_test_server(65001, ...).await,
///     start_test_server(65002, ...).await,
///     start_test_server(65002, ...).await,
/// ]).await;
/// ```
pub async fn chain_servers<const N: usize>(mut servers: [TestServer; N]) -> [TestServer; N] {
    // Connect each server to the previous one
    for i in 1..servers.len() {
        let prev_port = servers[i - 1].bgp_port;
        let prev_address = servers[i - 1].address.clone();

        servers[i]
            .client
            .add_peer(format!("{}:{}", prev_address, prev_port))
            .await
            .expect(&format!("Failed to add peer {} to server {}", i - 1, i));
    }

    // Build expected peer states for verification
    // For each server, determine which peers it should have
    poll_until(
        || async {
            for (i, server) in servers.iter().enumerate() {
                let mut expected_peers = Vec::new();

                // Previous server (if exists)
                if i > 0 {
                    expected_peers.push(servers[i - 1].to_peer(BgpState::Established));
                }

                // Next server (if exists)
                if i < servers.len() - 1 {
                    expected_peers.push(servers[i + 1].to_peer(BgpState::Established));
                }

                if !verify_peers(server, expected_peers).await {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for chain topology to establish",
    )
    .await;

    servers
}

/// Meshes BGP servers together in a full mesh topology
///
/// Connects each server to all other servers in the mesh.
/// Waits for all peerings to establish before returning.
///
/// # Arguments
/// * `servers` - Array of servers to mesh together
///
/// # Returns
/// The same array of servers after meshing is complete
///
/// # Example
/// ```
/// let [s1, s2, s3] = mesh_servers([
///     start_test_server(65001, ...).await,
///     start_test_server(65002, ...).await,
///     start_test_server(65003, ...).await,
/// ]).await;
/// // All three servers are now connected to each other
/// ```
pub async fn mesh_servers<const N: usize>(mut servers: [TestServer; N]) -> [TestServer; N] {
    // Create full mesh: each server connects to all others with higher index
    // This avoids duplicate connections while creating a full mesh
    for i in 0..servers.len() {
        for j in (i + 1)..servers.len() {
            let peer_port = servers[j].bgp_port;
            let peer_address = servers[j].address.clone();

            servers[i]
                .client
                .add_peer(format!("{}:{}", peer_address, peer_port))
                .await
                .expect(&format!("Failed to add peer {} to server {}", j, i));
        }
    }

    // Build expected peer states for verification
    // Each server should have N-1 peers (all other servers)
    poll_until(
        || async {
            for (i, server) in servers.iter().enumerate() {
                let mut expected_peers = Vec::new();

                // Add all other servers as expected peers
                for (j, other_server) in servers.iter().enumerate() {
                    if i != j {
                        expected_peers.push(other_server.to_peer(BgpState::Established));
                    }
                }

                if !verify_peers(server, expected_peers).await {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for mesh topology to establish",
    )
    .await;

    servers
}

/// Helper to check if server has expected peers (returns bool, suitable for poll_until)
pub async fn verify_peers(server: &TestServer, mut expected_peers: Vec<Peer>) -> bool {
    let Ok(mut peers) = server.client.get_peers().await else {
        return false;
    };

    // Sort both by address for consistent comparison
    peers.sort_by(|a, b| a.address.cmp(&b.address));
    expected_peers.sort_by(|a, b| a.address.cmp(&b.address));

    peers == expected_peers
}

/// Fake BGP peer for testing error handling
///
/// This allows sending raw/malformed BGP messages to test error handling.
/// Use a long hold timer (e.g., 300s) to avoid needing KEEPALIVE management.
pub struct FakePeer {
    stream: TcpStream,
}

impl FakePeer {
    /// Create a new FakePeer, connect to the given peer via TCP, and complete BGP handshake
    pub async fn new(
        local_asn: u16,
        local_router_id: Ipv4Addr,
        hold_time: u16,
        peer: &TestServer,
    ) -> Self {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", peer.bgp_port))
            .await
            .expect("Failed to connect to BGP peer");

        // 1. Send our OPEN
        let open = OpenMessage::new(local_asn, hold_time, u32::from(local_router_id));
        let open_bytes = open.serialize();
        stream
            .write_all(&open_bytes)
            .await
            .expect("Failed to send OPEN");

        // 2. Read their OPEN
        let msg = read_bgp_message(&mut stream)
            .await
            .expect("Failed to read OPEN");
        match msg {
            BgpMessage::Open(_) => {}
            _ => panic!("Expected OPEN message during handshake"),
        }

        // 3. Send KEEPALIVE
        let keepalive = KeepAliveMessage {};
        let keepalive_bytes = keepalive.serialize();
        stream
            .write_all(&keepalive_bytes)
            .await
            .expect("Failed to send KEEPALIVE");

        // 4. Read their KEEPALIVE
        let msg = read_bgp_message(&mut stream)
            .await
            .expect("Failed to read KEEPALIVE");
        match msg {
            BgpMessage::KeepAlive(_) => {}
            _ => panic!("Expected KEEPALIVE message during handshake"),
        }

        // Now in Established state (no background KEEPALIVEs needed with long hold_time)
        FakePeer { stream }
    }

    /// Send raw bytes to the peer
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.stream
            .write_all(bytes)
            .await
            .expect("Failed to send raw bytes");
    }

    /// Read a NOTIFICATION message (skips any KEEPALIVEs)
    pub async fn read_notification(&mut self) -> NotifcationMessage {
        loop {
            let msg = read_bgp_message(&mut self.stream)
                .await
                .expect("Failed to read message");

            match msg {
                BgpMessage::Notification(notif) => return notif,
                BgpMessage::KeepAlive(_) => continue, // Skip KEEPALIVEs sent by peer
                _ => panic!("Expected NOTIFICATION, got unexpected message type"),
            }
        }
    }
}
