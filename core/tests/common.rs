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
use bgpgg::grpc::proto::{BgpState, Peer};
use bgpgg::grpc::{BgpClient, BgpGrpcService};
use bgpgg::server::BgpServer;
use std::net::Ipv4Addr;
use tokio::time::{sleep, Duration};

/// Helper to check if peer is in a specific BGP state
pub fn peer_in_state(peer: &Peer, state: BgpState) -> bool {
    peer.state == state as i32
}

/// Starts a single BGP server with gRPC interface for testing
///
/// Returns a tuple of (BgpClient, bgp_port) where:
/// - BgpClient: gRPC client connected to the server
/// - bgp_port: The TCP port the BGP server is listening on
pub async fn start_test_server(asn: u16, router_id: Ipv4Addr) -> (BgpClient, u16) {
    use tokio::net::TcpListener;

    // Bind to port 0 to let OS allocate a free BGP port
    let bgp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bgp_port = bgp_listener.local_addr().unwrap().port();
    drop(bgp_listener);

    // Bind to port 0 to let OS allocate a free gRPC port
    let grpc_listener = TcpListener::bind("[::1]:0").await.unwrap();
    let grpc_port = grpc_listener.local_addr().unwrap().port();
    drop(grpc_listener);

    let config = Config::new(asn, &format!("127.0.0.1:{}", bgp_port), router_id);

    let server = BgpServer::new(config);

    // Create gRPC service
    let grpc_service = BgpGrpcService::new(server.request_tx.clone());

    // Spawn both servers
    tokio::spawn(async move { server.run().await });

    let grpc_addr = format!("[::1]:{}", grpc_port).parse().unwrap();
    tokio::spawn(async move {
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
    (client, bgp_port)
}

/// Sets up two BGP servers with peering established
///
/// Server1 (AS65001) <-----> Server2 (AS65002)
///
/// Returns (client1, client2) gRPC clients for each server.
/// Both servers will be in Established state when this function returns.
pub async fn setup_two_peered_servers() -> (BgpClient, BgpClient) {
    // Start both servers - OS allocates ports automatically
    let (client1, bgp_port1) = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1)).await;
    let (mut client2, _bgp_port2) = start_test_server(65002, Ipv4Addr::new(2, 2, 2, 2)).await;

    // Server2 connects to Server1 via gRPC
    client2
        .add_peer(format!("127.0.0.1:{}", bgp_port1))
        .await
        .expect("Failed to add peer");

    // Wait for peering to establish by polling via gRPC
    for _ in 0..100 {
        let peers1 = client1.get_peers().await.unwrap();
        let peers2 = client2.get_peers().await.unwrap();

        let both_established = peers1.len() == 1
            && peers2.len() == 1
            && peer_in_state(&peers1[0], BgpState::Established)
            && peer_in_state(&peers2[0], BgpState::Established);

        if both_established {
            return (client1, client2);
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
/// Returns (client1, client2, client3) gRPC clients for each server.
/// All servers will have 2 peers each in Established state when this function returns.
pub async fn setup_three_meshed_servers() -> (BgpClient, BgpClient, BgpClient) {
    // Start all three servers - OS allocates ports automatically
    let (mut client1, _bgp_port1) = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1)).await;
    let (mut client2, bgp_port2) = start_test_server(65002, Ipv4Addr::new(2, 2, 2, 2)).await;
    let (client3, bgp_port3) = start_test_server(65003, Ipv4Addr::new(3, 3, 3, 3)).await;

    // Create full mesh: each server peers with the other two
    // Server1 connects to Server2 and Server3
    client1
        .add_peer(format!("127.0.0.1:{}", bgp_port2))
        .await
        .expect("Failed to add peer 2 to server 1");
    client1
        .add_peer(format!("127.0.0.1:{}", bgp_port3))
        .await
        .expect("Failed to add peer 3 to server 1");

    // Server2 connects to Server3 (already connected to Server1)
    client2
        .add_peer(format!("127.0.0.1:{}", bgp_port3))
        .await
        .expect("Failed to add peer 3 to server 2");

    // Wait for all peerings to establish
    for _ in 0..100 {
        let peers1 = client1.get_peers().await.unwrap();
        let peers2 = client2.get_peers().await.unwrap();
        let peers3 = client3.get_peers().await.unwrap();

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
            return (client1, client2, client3);
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
/// Returns (client1, client2, client3, client4) gRPC clients for each server.
/// All servers will have 3 peers each in Established state when this function returns.
pub async fn setup_four_meshed_servers() -> (BgpClient, BgpClient, BgpClient, BgpClient) {
    // Start all four servers - OS allocates ports automatically
    let (mut client1, _bgp_port1) = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1)).await;
    let (mut client2, bgp_port2) = start_test_server(65002, Ipv4Addr::new(2, 2, 2, 2)).await;
    let (mut client3, bgp_port3) = start_test_server(65003, Ipv4Addr::new(3, 3, 3, 3)).await;
    let (client4, bgp_port4) = start_test_server(65004, Ipv4Addr::new(4, 4, 4, 4)).await;

    // Create full mesh: each server peers with the other three
    // Server1 connects to Server2, Server3, and Server4
    client1
        .add_peer(format!("127.0.0.1:{}", bgp_port2))
        .await
        .expect("Failed to add peer 2 to server 1");
    client1
        .add_peer(format!("127.0.0.1:{}", bgp_port3))
        .await
        .expect("Failed to add peer 3 to server 1");
    client1
        .add_peer(format!("127.0.0.1:{}", bgp_port4))
        .await
        .expect("Failed to add peer 4 to server 1");

    // Server2 connects to Server3 and Server4 (already connected to Server1)
    client2
        .add_peer(format!("127.0.0.1:{}", bgp_port3))
        .await
        .expect("Failed to add peer 3 to server 2");
    client2
        .add_peer(format!("127.0.0.1:{}", bgp_port4))
        .await
        .expect("Failed to add peer 4 to server 2");

    // Server3 connects to Server4 (already connected to Server1 and Server2)
    client3
        .add_peer(format!("127.0.0.1:{}", bgp_port4))
        .await
        .expect("Failed to add peer 4 to server 3");

    // Wait for all peerings to establish
    for _ in 0..100 {
        let peers1 = client1.get_peers().await.unwrap();
        let peers2 = client2.get_peers().await.unwrap();
        let peers3 = client3.get_peers().await.unwrap();
        let peers4 = client4.get_peers().await.unwrap();

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
            return (client1, client2, client3, client4);
        }
        sleep(Duration::from_millis(100)).await;
    }

    panic!("Timeout waiting for mesh peers to establish");
}

/// Polls for route propagation to multiple servers with expected AS paths
///
/// # Arguments
/// * `expectations` - Slice of tuples containing (gRPC client, expected AS paths)
/// * `prefix` - The route prefix to check for
/// * `expected_path_count` - Expected number of paths per server
pub async fn poll_route_propagation(
    expectations: &[(&BgpClient, Vec<Vec<u32>>)],
    prefix: &str,
    expected_path_count: usize,
) {
    for _ in 0..100 {
        let mut all_found = true;

        for (client, expected_paths) in expectations.iter() {
            let routes = client.get_routes().await.unwrap();

            if routes.len() != 1 || routes[0].paths.len() != expected_path_count {
                all_found = false;
                break;
            }

            let route = &routes[0];
            assert_eq!(
                route.prefix, prefix,
                "Route prefix mismatch in server {}",
                client.router_id
            );

            let mut as_paths: Vec<_> = route.paths.iter().map(|p| &p.as_path).collect();
            as_paths.sort();

            for exp_path in expected_paths.iter() {
                if !as_paths.contains(&exp_path) {
                    all_found = false;
                    break;
                }
            }

            if !all_found {
                break;
            }
        }

        if all_found {
            return;
        }

        sleep(Duration::from_millis(100)).await;
    }

    panic!("Timeout waiting for route {} to propagate", prefix);
}

/// Polls for route withdrawal from multiple servers
///
/// # Arguments
/// * `servers` - Slice of gRPC clients for servers to check
pub async fn poll_route_withdrawal(servers: &[&BgpClient]) {
    for _ in 0..100 {
        let mut all_withdrawn = true;

        for client in servers.iter() {
            let routes = client.get_routes().await.unwrap();
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
/// * `servers` - Slice of gRPC clients for servers to verify
/// * `expected_peer_count` - Expected number of peers per server
pub async fn verify_peers_established(servers: &[&BgpClient], expected_peer_count: usize) {
    for client in servers.iter() {
        let routes = client.get_routes().await.unwrap();
        assert!(
            routes.is_empty(),
            "Route not withdrawn from server {}",
            client.router_id
        );

        let peers = client.get_peers().await.unwrap();
        assert_eq!(
            peers.len(),
            expected_peer_count,
            "Server {} should have {} peers",
            client.router_id,
            expected_peer_count
        );
        assert!(
            peers
                .iter()
                .all(|p| peer_in_state(p, BgpState::Established)),
            "Server {} peers should be established",
            client.router_id
        );
    }
}
