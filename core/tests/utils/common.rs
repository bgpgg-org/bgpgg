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

use bgpgg::bgp::msg::{read_bgp_message, BgpMessage, Message, MessageType, BGP_MARKER};
use bgpgg::bgp::msg_keepalive::KeepAliveMessage;
use bgpgg::bgp::msg_notification::NotificationMessage;
use bgpgg::bgp::msg_open::OpenMessage;
use bgpgg::config::Config;
use bgpgg::grpc::proto::bgp_service_server::BgpServiceServer;
use bgpgg::grpc::proto::{
    AdminState, AsPathSegment, AsPathSegmentType, BgpState, Origin, Path, Peer, Route,
};
use bgpgg::grpc::{BgpClient, BgpGrpcService};
use bgpgg::server::BgpServer;
use std::net::Ipv4Addr;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, Duration};

/// Test server handle that includes runtime for killing the server
pub struct TestServer {
    pub client: BgpClient,
    pub bgp_port: u16,
    pub asn: u16,
    pub address: std::net::IpAddr, // IP address the server is bound to (no port)
    pub config: Config,
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
    pub fn to_peer(&self, state: BgpState, configured: bool) -> Peer {
        Peer {
            address: self.address.to_string(),
            asn: self.asn as u32,
            state: state.into(),
            admin_state: AdminState::Up.into(),
            configured,
            import_policies: vec![],
            export_policies: vec![],
        }
    }

    /// Add a peer to this server
    pub async fn add_peer(&mut self, peer: &TestServer) {
        self.client
            .add_peer(format!("{}:{}", peer.address, peer.bgp_port), None)
            .await
            .unwrap();
    }

    /// Remove a peer from this server
    pub async fn remove_peer(&mut self, peer: &TestServer) {
        self.client
            .remove_peer(peer.address.to_string())
            .await
            .unwrap();
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
#[allow(clippy::too_many_arguments)]
pub fn build_path(
    as_path: Vec<AsPathSegment>,
    next_hop: &str,
    peer_address: String,
    origin: Origin,
    local_pref: Option<u32>,
    med: Option<u32>,
    atomic_aggregate: bool,
    unknown_attributes: Vec<bgpgg::grpc::proto::UnknownAttribute>,
    communities: Vec<u32>,
) -> Path {
    Path {
        origin: origin.into(),
        as_path,
        next_hop: next_hop.to_string(),
        peer_address,
        local_pref,
        med,
        atomic_aggregate,
        unknown_attributes,
        communities,
    }
}

pub fn routes_match(actual: &[Route], expected: &[Route]) -> bool {
    use std::collections::HashMap;

    let routes_map: HashMap<_, _> = actual
        .iter()
        .map(|r| (r.prefix.clone(), r.paths.first().cloned()))
        .collect();
    let expected_map: HashMap<_, _> = expected
        .iter()
        .map(|r| (r.prefix.clone(), r.paths.first().cloned()))
        .collect();

    routes_map == expected_map
}

/// Helper to create a standard test config with sane defaults
pub fn test_config(asn: u16, ip_last_octet: u8) -> Config {
    let ip = format!("127.0.0.{}", ip_last_octet);
    let mut config = Config::new(
        asn,
        &format!("{}:0", ip),
        Ipv4Addr::new(ip_last_octet, ip_last_octet, ip_last_octet, ip_last_octet),
        90,
        true,
    );
    config.sys_name = Some(format!("test-bgpgg-{}", ip));
    config.sys_descr = Some("test bgpgg router".to_string());
    config
}

/// Starts a single BGP server with gRPC interface for testing
pub async fn start_test_server(config: Config) -> TestServer {
    use tokio::net::TcpListener;

    let router_id = config.router_id;
    let asn = config.asn;
    let bind_ip: std::net::IpAddr = config
        .listen_addr
        .split(':')
        .next()
        .unwrap_or("127.0.0.1")
        .parse()
        .expect("valid IP address");

    // Bind gRPC listener to get port (no race - we keep the listener)
    let grpc_listener = TcpListener::bind("[::1]:0").await.unwrap();
    let grpc_port = grpc_listener.local_addr().unwrap().port();
    let grpc_listener = grpc_listener.into_std().unwrap();

    let config_clone = config.clone();
    let server = BgpServer::new(config).expect("valid server config");
    let grpc_service = BgpGrpcService::new(server.mgmt_tx.clone());

    // Create a separate runtime for this server (simulates separate process)
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Spawn BGP server
    runtime.spawn(async move { server.run().await });

    // Spawn gRPC server
    runtime.spawn(async move {
        let grpc_listener = tokio::net::TcpListener::from_std(grpc_listener).unwrap();
        tonic::transport::Server::builder()
            .add_service(BgpServiceServer::new(grpc_service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(
                grpc_listener,
            ))
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

    // Query actual BGP port from server
    let mut bgp_port = 0;
    for _ in 0..50 {
        match client.get_server_info().await {
            Ok((_, port, _)) if port > 0 => {
                bgp_port = port;
                break;
            }
            _ => {
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
    assert!(bgp_port > 0, "Failed to get BGP port from server");

    TestServer {
        client,
        bgp_port,
        asn,
        address: bind_ip,
        config: config_clone,
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
    let hold = hold_timer_secs.unwrap_or(90) as u64;
    let [server1, server2] = chain_servers([
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            hold,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            hold,
            true,
        ))
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
    let hold = hold_timer_secs.unwrap_or(90) as u64;
    let [server1, server2, server3] = mesh_servers([
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            hold,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            hold,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65003,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            hold,
            true,
        ))
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
    let hold = hold_timer_secs.unwrap_or(90) as u64;
    let [server1, server2, server3, server4] = mesh_servers([
        start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            hold,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            hold,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65003,
            "127.0.0.3:0",
            Ipv4Addr::new(3, 3, 3, 3),
            hold,
            true,
        ))
        .await,
        start_test_server(Config::new(
            65004,
            "127.0.0.4:0",
            Ipv4Addr::new(4, 4, 4, 4),
            hold,
            true,
        ))
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
    let hold = hold_timer_secs.unwrap_or(90) as u64;

    // Island 1: AS65001 (iBGP mesh)
    let mut server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        hold,
        true,
    ))
    .await;
    let mut server2 = start_test_server(Config::new(
        65001,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        hold,
        true,
    ))
    .await;
    let mut server3 = start_test_server(Config::new(
        65001,
        "127.0.0.3:0",
        Ipv4Addr::new(3, 3, 3, 3),
        hold,
        true,
    ))
    .await;
    let mut server4 = start_test_server(Config::new(
        65001,
        "127.0.0.4:0",
        Ipv4Addr::new(4, 4, 4, 4),
        hold,
        true,
    ))
    .await;

    // Island 2: AS65002 (iBGP triangle)
    let mut server5 = start_test_server(Config::new(
        65002,
        "127.0.0.5:0",
        Ipv4Addr::new(5, 5, 5, 5),
        hold,
        true,
    ))
    .await;
    let mut server6 = start_test_server(Config::new(
        65002,
        "127.0.0.6:0",
        Ipv4Addr::new(6, 6, 6, 6),
        hold,
        true,
    ))
    .await;
    let server7 = start_test_server(Config::new(
        65002,
        "127.0.0.7:0",
        Ipv4Addr::new(7, 7, 7, 7),
        hold,
        true,
    ))
    .await;

    // Island 1 mesh: S1, S2, S3, S4
    // S1 connects to S2, S3, and S4
    server1
        .client
        .add_peer(format!("127.0.0.2:{}", server2.bgp_port), None)
        .await
        .expect("Failed to add peer 2 to server 1");
    server1
        .client
        .add_peer(format!("127.0.0.3:{}", server3.bgp_port), None)
        .await
        .expect("Failed to add peer 3 to server 1");
    server1
        .client
        .add_peer(format!("127.0.0.4:{}", server4.bgp_port), None)
        .await
        .expect("Failed to add peer 4 to server 1");

    // S2 connects to S3 and S4 (already connected to S1)
    server2
        .client
        .add_peer(format!("127.0.0.3:{}", server3.bgp_port), None)
        .await
        .expect("Failed to add peer 3 to server 2");
    server2
        .client
        .add_peer(format!("127.0.0.4:{}", server4.bgp_port), None)
        .await
        .expect("Failed to add peer 4 to server 2");

    // S3 connects to S4 (already connected to S1 and S2)
    server3
        .client
        .add_peer(format!("127.0.0.4:{}", server4.bgp_port), None)
        .await
        .expect("Failed to add peer 4 to server 3");

    // Island 2 triangle: S5, S6, S7
    // S5 connects to S6 and S7
    server5
        .client
        .add_peer(format!("127.0.0.6:{}", server6.bgp_port), None)
        .await
        .expect("Failed to add peer 6 to server 5");
    server5
        .client
        .add_peer(format!("127.0.0.7:{}", server7.bgp_port), None)
        .await
        .expect("Failed to add peer 7 to server 5");

    // S6 connects to S7 (already connected to S5)
    server6
        .client
        .add_peer(format!("127.0.0.7:{}", server7.bgp_port), None)
        .await
        .expect("Failed to add peer 7 to server 6");

    // Bridge connection: S4 (AS65001) to S5 (AS65002) - eBGP
    server4
        .client
        .add_peer(format!("127.0.0.5:{}", server5.bgp_port), None)
        .await
        .expect("Failed to add eBGP bridge peer 5 to server 4");

    // Wait for all peerings to establish
    // Connection pattern: lower-indexed server connects to higher-indexed server
    // From connector's view: configured=true; from acceptor's view: configured=false
    poll_until(
        || async {
            // Island 1 full mesh (4 servers)
            // S1 connected to S2, S3, S4 (all configured)
            verify_peers(
                &server1,
                vec![
                    server2.to_peer(BgpState::Established, true),
                    server3.to_peer(BgpState::Established, true),
                    server4.to_peer(BgpState::Established, true),
                ],
            )
            .await
                // S2: S1 connected to us (unconfigured), we connected to S3, S4 (configured)
                && verify_peers(
                    &server2,
                    vec![
                        server1.to_peer(BgpState::Established, false),
                        server3.to_peer(BgpState::Established, true),
                        server4.to_peer(BgpState::Established, true),
                    ],
                )
                .await
                // S3: S1, S2 connected to us (unconfigured), we connected to S4 (configured)
                && verify_peers(
                    &server3,
                    vec![
                        server1.to_peer(BgpState::Established, false),
                        server2.to_peer(BgpState::Established, false),
                        server4.to_peer(BgpState::Established, true),
                    ],
                )
                .await
                // S4: S1, S2, S3 connected to us (unconfigured), we connected to S5 (configured)
                && verify_peers(
                    &server4,
                    vec![
                        server1.to_peer(BgpState::Established, false),
                        server2.to_peer(BgpState::Established, false),
                        server3.to_peer(BgpState::Established, false),
                        server5.to_peer(BgpState::Established, true),
                    ],
                )
                .await
                // Island 2 triangle (S5, S6, S7)
                // S5: S4 connected to us (unconfigured), we connected to S6, S7 (configured)
                && verify_peers(
                    &server5,
                    vec![
                        server4.to_peer(BgpState::Established, false),
                        server6.to_peer(BgpState::Established, true),
                        server7.to_peer(BgpState::Established, true),
                    ],
                )
                .await
                // S6: S5 connected to us (unconfigured), we connected to S7 (configured)
                && verify_peers(
                    &server6,
                    vec![
                        server5.to_peer(BgpState::Established, false),
                        server7.to_peer(BgpState::Established, true),
                    ],
                )
                .await
                // S7: S5, S6 connected to us (all unconfigured)
                && verify_peers(
                    &server7,
                    vec![
                        server5.to_peer(BgpState::Established, false),
                        server6.to_peer(BgpState::Established, false),
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
pub async fn poll_route_propagation(expectations: &[(&TestServer, Vec<Route>)]) {
    poll_route_propagation_with_timeout(expectations, 100).await;
}

/// Polls for route propagation with custom timeout (iterations × 100ms)
pub async fn poll_route_propagation_with_timeout(
    expectations: &[(&TestServer, Vec<Route>)],
    max_iterations: usize,
) {
    poll_until_with_timeout(
        || async {
            for (server, expected_routes) in expectations {
                let Ok(routes) = server.client.get_routes().await else {
                    return false;
                };

                if !routes_match(&routes, expected_routes) {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for routes to propagate",
        max_iterations,
    )
    .await;
}

/// Expected peer statistics for polling. None means don't check that field.
/// Uses `==` for exact match, `>=` for `min_*` fields.
#[derive(Default, Clone, Copy)]
pub struct ExpectedStats {
    pub open_sent: Option<u64>,
    pub open_received: Option<u64>,
    pub update_sent: Option<u64>,
    pub update_received: Option<u64>,
    pub notification_sent: Option<u64>,
    pub notification_received: Option<u64>,
    pub min_update_sent: Option<u64>,
    pub min_update_received: Option<u64>,
    pub min_keepalive_sent: Option<u64>,
    pub min_keepalive_received: Option<u64>,
}

impl ExpectedStats {
    pub fn is_met_by(&self, s: &bgpgg::grpc::proto::PeerStatistics) -> bool {
        self.open_sent.is_none_or(|e| s.open_sent == e)
            && self.open_received.is_none_or(|e| s.open_received == e)
            && self.update_sent.is_none_or(|e| s.update_sent == e)
            && self.update_received.is_none_or(|e| s.update_received == e)
            && self
                .notification_sent
                .is_none_or(|e| s.notification_sent == e)
            && self
                .notification_received
                .is_none_or(|e| s.notification_received == e)
            && self.min_update_sent.is_none_or(|e| s.update_sent >= e)
            && self
                .min_update_received
                .is_none_or(|e| s.update_received >= e)
            && self
                .min_keepalive_sent
                .is_none_or(|e| s.keepalive_sent >= e)
            && self
                .min_keepalive_received
                .is_none_or(|e| s.keepalive_received >= e)
    }
}

/// Poll until peer statistics meet expected thresholds.
pub async fn poll_peer_stats(server: &TestServer, peer_addr: &str, expected: ExpectedStats) {
    poll_until(
        || async {
            let Ok((_, stats)) = server.client.get_peer(peer_addr.to_string()).await else {
                return false;
            };
            let Some(s) = stats else {
                return false;
            };
            expected.is_met_by(&s)
        },
        "Timeout waiting for peer statistics",
    )
    .await;
}

/// Wait for routes and peer stats to converge.
pub async fn wait_convergence(
    route_expectations: &[(&TestServer, Vec<Route>)],
    stats_expectations: &[(&TestServer, &TestServer, ExpectedStats)],
) {
    use std::collections::HashMap;

    poll_until(
        || async {
            for (server, expected_routes) in route_expectations {
                let Ok(routes) = server.client.get_routes().await else {
                    return false;
                };
                // Compare only best paths (first path in each route)
                let routes_map: HashMap<_, _> = routes
                    .into_iter()
                    .map(|r| (r.prefix.clone(), r.paths.into_iter().next()))
                    .collect();
                let expected_map: HashMap<_, _> = expected_routes
                    .iter()
                    .map(|r| (r.prefix.clone(), r.paths.first().cloned()))
                    .collect();
                if routes_map != expected_map {
                    return false;
                }
            }
            for (server, peer, expected) in stats_expectations {
                let Ok((_, stats)) = server.client.get_peer(peer.address.to_string()).await else {
                    return false;
                };
                let Some(s) = stats else {
                    return false;
                };
                if !expected.is_met_by(&s) {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for route convergence",
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

/// Poll to verify a condition stays true for a duration.
/// Panics immediately if condition becomes false.
pub async fn poll_while<F, Fut>(check: F, duration: Duration, fail_message: &str)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < duration {
        assert!(check().await, "{}", fail_message);
        sleep(Duration::from_millis(100)).await;
    }
}

/// Wait until condition becomes true, then verify it stays stable for a duration.
/// Combines poll_until + poll_while to prevent race conditions.
pub async fn poll_until_stable<F, Fut>(check: F, stable_duration: Duration, fail_message: &str)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    poll_until(&check, fail_message).await;
    poll_while(check, stable_duration, fail_message).await;
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
    // Connect each server to the next one: s0 -> s1 -> s2 -> ...
    for i in 0..servers.len() - 1 {
        let next_port = servers[i + 1].bgp_port;
        let next_address = servers[i + 1].address;

        servers[i]
            .client
            .add_peer(format!("{}:{}", next_address, next_port), None)
            .await
            .unwrap_or_else(|_| panic!("Failed to add peer {} to server {}", i + 1, i));
    }

    // Build expected peer states for verification
    // Connection pattern: server i connects to server i+1
    // From i's view: i+1 is configured (we called AddPeer)
    // From i+1's view: i is unconfigured (they didn't call AddPeer)
    poll_until(
        || async {
            for (i, server) in servers.iter().enumerate() {
                let mut expected_peers = Vec::new();

                // Previous server (if exists) - they connected to us (unconfigured)
                if i > 0 {
                    expected_peers.push(servers[i - 1].to_peer(BgpState::Established, false));
                }

                // Next server (if exists) - we connected to it (configured)
                if i < servers.len() - 1 {
                    expected_peers.push(servers[i + 1].to_peer(BgpState::Established, true));
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
            let peer_address = servers[j].address;

            servers[i]
                .client
                .add_peer(format!("{}:{}", peer_address, peer_port), None)
                .await
                .unwrap_or_else(|_| panic!("Failed to add peer {} to server {}", j, i));
        }
    }

    // Build expected peer states for verification
    // Connection pattern: server i connects to server j where i < j
    // From i's view: j is configured (we called AddPeer)
    // From j's view: i is unconfigured (they didn't call AddPeer)
    poll_until(
        || async {
            for (i, server) in servers.iter().enumerate() {
                let mut expected_peers = Vec::new();

                for (j, other_server) in servers.iter().enumerate() {
                    if i != j {
                        // If j < i, then j connected to us (unconfigured)
                        // If j > i, then we connected to j (configured)
                        let configured = j > i;
                        expected_peers
                            .push(other_server.to_peer(BgpState::Established, configured));
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

/// Poll until server has expected peers
pub async fn poll_peers(server: &TestServer, expected_peers: Vec<Peer>) {
    poll_until(
        || async { verify_peers(server, expected_peers.clone()).await },
        "Timeout waiting for peers to match expected state",
    )
    .await;
}

/// Verify server info matches expected values
pub async fn verify_server_info(
    server: &TestServer,
    expected_addr: Ipv4Addr,
    expected_port: u16,
    expected_num_routes: u64,
) {
    let (listen_addr, listen_port, num_routes) = server
        .client
        .get_server_info()
        .await
        .expect("Failed to get server info");

    assert_eq!(listen_addr, expected_addr, "listen_addr mismatch");
    assert_eq!(listen_port, expected_port, "listen_port mismatch");
    assert_eq!(num_routes, expected_num_routes, "num_routes mismatch");
}

/// Fake BGP peer for testing error handling
///
/// This allows sending raw/malformed BGP messages to test error handling.
/// Use a long hold timer (e.g., 300s) to avoid needing KEEPALIVE management.
pub struct FakePeer {
    pub stream: Option<TcpStream>,
    pub address: String,
    pub asn: u16,
    pub listener: Option<TcpListener>,
}

impl FakePeer {
    /// Connect TCP only. Use local_ip to bind to specific address.
    pub async fn connect(local_ip: Option<&str>, peer: &TestServer) -> Self {
        use std::net::SocketAddr;
        use tokio::net::TcpSocket;

        let local_ip = local_ip.unwrap_or("0.0.0.0");
        let local_addr: SocketAddr = format!("{}:0", local_ip).parse().unwrap();
        let peer_addr: SocketAddr = format!("{}:{}", peer.address, peer.bgp_port)
            .parse()
            .unwrap();

        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.bind(local_addr).unwrap();
        let stream = socket.connect(peer_addr).await.unwrap();

        let address = stream.local_addr().unwrap().ip().to_string();
        FakePeer {
            stream: Some(stream),
            address,
            asn: 0,
            listener: None,
        }
    }

    /// Create a FakePeer. Call accept() to accept the connection.
    pub async fn new(bind_addr: &str, local_asn: u16) -> Self {
        let listener = TcpListener::bind(bind_addr).await.unwrap();
        let address = listener.local_addr().unwrap().ip().to_string();
        FakePeer {
            stream: None,
            address,
            asn: local_asn,
            listener: Some(listener),
        }
    }

    /// Get the port this FakePeer is listening on.
    pub fn port(&self) -> u16 {
        self.listener.as_ref().unwrap().local_addr().unwrap().port()
    }

    /// Accept a TCP connection on the listener (no BGP handshake).
    pub async fn accept(&mut self) {
        let listener = self.listener.as_ref().unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        self.stream = Some(stream);
    }

    /// Exchange OPEN messages with peer (ends up in OpenConfirm state).
    /// For outgoing connections: sends OPEN then reads OPEN.
    pub async fn handshake_open(&mut self, asn: u16, router_id: Ipv4Addr, hold_time: u16) {
        self.asn = asn;

        // Send our OPEN
        let open = OpenMessage::new(asn, hold_time, u32::from(router_id));
        self.stream
            .as_mut()
            .unwrap()
            .write_all(&open.serialize())
            .await
            .expect("Failed to send OPEN");

        // Read their OPEN
        let msg = read_bgp_message(self.stream.as_mut().unwrap())
            .await
            .expect("Failed to read OPEN");
        match msg {
            BgpMessage::Open(_) => {}
            _ => panic!("Expected OPEN message"),
        }
    }

    /// Exchange OPEN messages for accepted connections (ends up in OpenConfirm state).
    /// For incoming connections: reads OPEN then sends OPEN.
    pub async fn accept_handshake_open(&mut self, asn: u16, router_id: Ipv4Addr, hold_time: u16) {
        self.asn = asn;

        // Read their OPEN (they connected, they send first)
        let msg = read_bgp_message(self.stream.as_mut().unwrap())
            .await
            .expect("Failed to read OPEN");
        match msg {
            BgpMessage::Open(_) => {}
            _ => panic!("Expected OPEN message"),
        }

        // Send our OPEN
        let open = OpenMessage::new(asn, hold_time, u32::from(router_id));
        self.stream
            .as_mut()
            .unwrap()
            .write_all(&open.serialize())
            .await
            .expect("Failed to send OPEN");
    }

    /// Exchange KEEPALIVE messages to complete handshake (reaches Established state).
    pub async fn handshake_keepalive(&mut self) {
        let keepalive = KeepAliveMessage {};
        self.stream
            .as_mut()
            .unwrap()
            .write_all(&keepalive.serialize())
            .await
            .expect("Failed to send KEEPALIVE");

        let msg = read_bgp_message(self.stream.as_mut().unwrap())
            .await
            .expect("Failed to read KEEPALIVE");
        match msg {
            BgpMessage::KeepAlive(_) => {}
            _ => panic!("Expected KEEPALIVE message during handshake"),
        }
    }

    pub fn to_peer(&self, state: BgpState, configured: bool) -> Peer {
        Peer {
            address: self.address.clone(),
            asn: self.asn as u32,
            state: state.into(),
            admin_state: AdminState::Up.into(),
            configured,
            import_policies: vec![],
            export_policies: vec![],
        }
    }

    /// Send raw bytes to the peer
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.stream
            .as_mut()
            .unwrap()
            .write_all(bytes)
            .await
            .expect("Failed to send raw bytes");
    }

    /// Send a KEEPALIVE message
    pub async fn send_keepalive(&mut self) {
        let keepalive = KeepAliveMessage {};
        self.stream
            .as_mut()
            .unwrap()
            .write_all(&keepalive.serialize())
            .await
            .expect("Failed to send KEEPALIVE");
    }

    /// Send an OPEN message
    pub async fn send_open(&mut self, asn: u16, router_id: Ipv4Addr, hold_time: u16) {
        let open = OpenMessage::new(asn, hold_time, u32::from(router_id));
        self.stream
            .as_mut()
            .unwrap()
            .write_all(&open.serialize())
            .await
            .unwrap();
    }

    /// Read and discard an OPEN message
    pub async fn read_open(&mut self) {
        let msg = read_bgp_message(self.stream.as_mut().unwrap())
            .await
            .unwrap();
        assert!(matches!(msg, BgpMessage::Open(_)));
    }

    /// Read and discard a KEEPALIVE message
    pub async fn read_keepalive(&mut self) {
        let msg = read_bgp_message(self.stream.as_mut().unwrap())
            .await
            .unwrap();
        assert!(matches!(msg, BgpMessage::KeepAlive(_)));
    }

    /// Read a NOTIFICATION message (skips any KEEPALIVEs)
    pub async fn read_notification(&mut self) -> NotificationMessage {
        loop {
            let msg = read_bgp_message(self.stream.as_mut().unwrap())
                .await
                .expect("Failed to read message");

            match msg {
                BgpMessage::Notification(notif) => return notif,
                BgpMessage::KeepAlive(_) => continue, // Skip KEEPALIVEs sent by peer
                _ => panic!("Expected NOTIFICATION, got unexpected message type"),
            }
        }
    }

    /// Initiate new connection to server from same IP as this peer.
    /// Returns raw TcpStream (no OPEN sent).
    pub async fn connect_to(&self, server: &TestServer) -> TcpStream {
        use std::net::SocketAddr;
        use tokio::net::TcpSocket;

        let local_addr: SocketAddr = format!("{}:0", self.address).parse().unwrap();
        let server_addr: SocketAddr = format!("{}:{}", server.address, server.bgp_port)
            .parse()
            .unwrap();

        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.bind(local_addr).unwrap();
        socket.connect(server_addr).await.unwrap()
    }
}

// Build raw BGP message from components
pub fn build_raw_message(
    marker: [u8; 16],
    length_override: Option<u16>,
    msg_type: u8,
    body: &[u8],
) -> Vec<u8> {
    let mut msg = marker.to_vec();
    msg.extend_from_slice(&[0x00, 0x00]); // Placeholder for length
    msg.push(msg_type);
    msg.extend_from_slice(body);

    // Fix the length field (unless overridden)
    let len = length_override.unwrap_or(msg.len() as u16);
    msg[16] = (len >> 8) as u8;
    msg[17] = (len & 0xff) as u8;

    msg
}

// Build a raw update message.
pub fn build_raw_update(
    withdrawn: &[u8],
    attrs: &[&[u8]],
    nlri: &[u8],
    total_attr_len_override: Option<u16>,
) -> Vec<u8> {
    let mut body = Vec::new();

    // Withdrawn routes
    body.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
    body.extend_from_slice(withdrawn);

    // Total path attributes length - use override if provided, else calculate correctly
    let total_attr_len = total_attr_len_override
        .unwrap_or_else(|| attrs.iter().map(|a| a.len()).sum::<usize>() as u16);
    body.extend_from_slice(&total_attr_len.to_be_bytes());

    // Path attributes
    for attr in attrs {
        body.extend_from_slice(attr);
    }

    // NLRI
    body.extend_from_slice(nlri);

    build_raw_message(BGP_MARKER, None, MessageType::UPDATE.as_u8(), &body)
}

// Build raw attribute bytes
pub fn build_attr_bytes(flags: u8, attr_type: u8, length: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![flags, attr_type, length];
    bytes.extend_from_slice(value);
    bytes
}

// Pre-built common path attributes for error tests
use bgpgg::bgp::msg_update::{attr_flags, attr_type_code, Origin as MsgOrigin};

pub fn attr_origin_igp() -> Vec<u8> {
    build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::ORIGIN,
        1,
        &[MsgOrigin::IGP as u8],
    )
}

pub fn attr_as_path_empty() -> Vec<u8> {
    build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::AS_PATH, 0, &[])
}

pub fn attr_next_hop(ip: Ipv4Addr) -> Vec<u8> {
    let octets = ip.octets();
    build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::NEXT_HOP, 4, &octets)
}

// Build raw OPEN message with optional custom version, marker, length, and message type
pub fn build_raw_open(
    asn: u16,
    hold_time: u16,
    router_id: u32,
    version_override: Option<u8>,
    marker_override: Option<[u8; 16]>,
    length_override: Option<u16>,
    msg_type_override: Option<u8>,
) -> Vec<u8> {
    let version = version_override.unwrap_or(4);
    let marker = marker_override.unwrap_or(BGP_MARKER);
    let msg_type = msg_type_override.unwrap_or(MessageType::OPEN.as_u8());

    let mut body = Vec::new();
    body.push(version);
    body.extend_from_slice(&asn.to_be_bytes());
    body.extend_from_slice(&hold_time.to_be_bytes());
    body.extend_from_slice(&router_id.to_be_bytes());
    body.push(0); // Optional parameters length = 0

    build_raw_message(marker, length_override, msg_type, &body)
}

// Build raw KEEPALIVE message with optional custom length
pub fn build_raw_keepalive(length_override: Option<u16>) -> Vec<u8> {
    let body = Vec::new(); // KEEPALIVE has no body
    build_raw_message(
        BGP_MARKER,
        length_override,
        MessageType::KEEPALIVE.as_u8(),
        &body,
    )
}

// Build raw NOTIFICATION message with optional custom length
pub fn build_raw_notification(
    error_code: u8,
    error_subcode: u8,
    data: &[u8],
    length_override: Option<u16>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(error_code);
    body.push(error_subcode);
    body.extend_from_slice(data);

    build_raw_message(
        BGP_MARKER,
        length_override,
        MessageType::NOTIFICATION.as_u8(),
        &body,
    )
}
