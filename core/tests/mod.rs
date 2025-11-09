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
        match BgpClient::connect(format!("http://[::1]:{}", grpc_port)).await {
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
/// Server1 (AS1) <-----> Server2 (AS2)
///
/// Returns (client1, client2) gRPC clients for each server.
/// Both servers will be in Established state when this function returns.
pub async fn setup_two_peered_servers(asn1: u16, asn2: u16) -> (BgpClient, BgpClient) {
    // Start both servers - OS allocates ports automatically
    let (mut client1, bgp_port1) = start_test_server(asn1, Ipv4Addr::new(1, 1, 1, 1)).await;
    let (mut client2, _bgp_port2) = start_test_server(asn2, Ipv4Addr::new(2, 2, 2, 2)).await;

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
///     Server1 (AS1)
///       /  \
///      /    \
/// Server2 -- Server3
///  (AS2)      (AS3)
///
/// Returns (client1, client2, client3) gRPC clients for each server.
/// All servers will have 2 peers each in Established state when this function returns.
pub async fn setup_three_meshed_servers(
    asn1: u16,
    asn2: u16,
    asn3: u16,
) -> (BgpClient, BgpClient, BgpClient) {
    // Start all three servers - OS allocates ports automatically
    let (mut client1, _bgp_port1) = start_test_server(asn1, Ipv4Addr::new(1, 1, 1, 1)).await;
    let (mut client2, bgp_port2) = start_test_server(asn2, Ipv4Addr::new(2, 2, 2, 2)).await;
    let (mut client3, bgp_port3) = start_test_server(asn3, Ipv4Addr::new(3, 3, 3, 3)).await;

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
            && peers1.iter().all(|p| peer_in_state(p, BgpState::Established))
            && peers2.iter().all(|p| peer_in_state(p, BgpState::Established))
            && peers3.iter().all(|p| peer_in_state(p, BgpState::Established));

        if all_established {
            return (client1, client2, client3);
        }
        sleep(Duration::from_millis(100)).await;
    }

    panic!("Timeout waiting for mesh peers to establish");
}
