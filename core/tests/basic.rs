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

use bgpgg::config::Config;
use bgpgg::grpc::proto::bgp_service_server::BgpServiceServer;
use bgpgg::grpc::{BgpClient, BgpGrpcService};
use bgpgg::server::BgpServer;
use std::net::Ipv4Addr;
use tokio::time::{sleep, Duration};

async fn start_test_server(asn: u16, bgp_port: u16, grpc_port: u16, router_id: Ipv4Addr) -> BgpClient {
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

    client.expect("Failed to connect to gRPC server after retries")
}

/// Utility function to set up two BGP servers with peering established
/// Returns (client1, client2) gRPC clients for each server
async fn setup_two_peered_servers(
    asn1: u16,
    asn2: u16,
    bgp_port1: u16,
    bgp_port2: u16,
    grpc_port1: u16,
    grpc_port2: u16,
) -> (BgpClient, BgpClient) {
    // Start both servers
    let mut client1 =
        start_test_server(asn1, bgp_port1, grpc_port1, Ipv4Addr::new(1, 1, 1, 1)).await;
    let mut client2 =
        start_test_server(asn2, bgp_port2, grpc_port2, Ipv4Addr::new(2, 2, 2, 2)).await;

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
            && peers1[0].state == "Established"
            && peers2[0].state == "Established";

        if both_established {
            return (client1, client2);
        }
        sleep(Duration::from_millis(100)).await;
    }

    panic!("Timeout waiting for peers to establish");
}

#[tokio::test]
async fn test_two_bgp_servers_peering() {
    let (mut client1, mut client2) =
        setup_two_peered_servers(65100, 65200, 1790, 1791, 50051, 50052).await;

    // Verify that both servers have peers via gRPC
    let peers1 = client1.get_peers().await.unwrap();
    let peers2 = client2.get_peers().await.unwrap();

    assert_eq!(peers1.len(), 1, "Server 1 should have 1 peer");
    assert_eq!(peers2.len(), 1, "Server 2 should have 1 peer");

    // Verify FSM state is Established
    assert_eq!(
        peers1[0].state, "Established",
        "Server 1 peer should be in Established state"
    );
    assert_eq!(
        peers2[0].state, "Established",
        "Server 2 peer should be in Established state"
    );

    // Verify ASNs
    assert_eq!(peers1[0].asn, 65200, "Server 1 peer should have ASN 65200");
    assert_eq!(peers2[0].asn, 65100, "Server 2 peer should have ASN 65100");
}

#[tokio::test]
async fn test_announce_one_route() {
    let (mut client1, mut client2) =
        setup_two_peered_servers(65100, 65001, 1794, 1795, 50053, 50054).await;

    // Server2 announces a route to Server1 via gRPC
    client2
        .announce_route("10.0.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route");

    // Poll for route to appear in Server1's RIB
    let mut route_found = false;
    for _ in 0..100 {
        let routes = client1.get_routes().await.unwrap();

        if routes.len() == 1 {
            let route = &routes[0];
            assert_eq!(route.prefix, "10.0.0.0/24", "Route prefix mismatch");
            assert_eq!(route.paths.len(), 1, "Should have exactly one path");

            let path = &route.paths[0];
            assert_eq!(path.origin, 0, "Origin should be IGP");
            assert_eq!(
                path.as_path,
                vec![65001],
                "AS path should contain only 65001"
            );
            assert_eq!(path.next_hop, "192.168.1.1", "Next hop mismatch");
            assert_eq!(path.local_pref, Some(100), "Local pref should be 100");

            route_found = true;
            break;
        }

        sleep(Duration::from_millis(100)).await;
    }

    assert!(
        route_found,
        "Route 10.0.0.0/24 not found in Server1's RIB"
    );

    // Verify peers are still established after route announcement
    let peers1 = client1.get_peers().await.unwrap();
    let peers2 = client2.get_peers().await.unwrap();

    assert_eq!(peers1.len(), 1, "Server 1 should still have 1 peer");
    assert_eq!(peers2.len(), 1, "Server 2 should still have 1 peer");
    assert_eq!(
        peers1[0].state, "Established",
        "Server 1 peer should still be in Established state"
    );
    assert_eq!(
        peers2[0].state, "Established",
        "Server 2 peer should still be in Established state"
    );
}
