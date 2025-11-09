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

async fn start_test_server(asn: u16, router_id: Ipv4Addr) -> (BgpClient, u16) {
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

/// Utility function to set up two BGP servers with peering established
/// Returns (client1, client2) gRPC clients for each server
async fn setup_two_peered_servers(asn1: u16, asn2: u16) -> (BgpClient, BgpClient) {
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
            && peers1[0].state == "Established"
            && peers2[0].state == "Established";

        if both_established {
            return (client1, client2);
        }
        sleep(Duration::from_millis(100)).await;
    }

    panic!("Timeout waiting for peers to establish");
}

/// Utility function to set up three BGP servers in a full mesh
/// Returns (client1, client2, client3) gRPC clients for each server
async fn setup_three_meshed_servers(
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
            && peers1.iter().all(|p| p.state == "Established")
            && peers2.iter().all(|p| p.state == "Established")
            && peers3.iter().all(|p| p.state == "Established");

        if all_established {
            return (client1, client2, client3);
        }
        sleep(Duration::from_millis(100)).await;
    }

    panic!("Timeout waiting for mesh peers to establish");
}

#[tokio::test]
async fn test_two_bgp_servers_peering() {
    let (mut client1, mut client2) = setup_two_peered_servers(65100, 65200).await;

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
async fn test_announce_withdraw() {
    let (mut client1, mut client2) = setup_two_peered_servers(65100, 65001).await;

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

            route_found = true;
            break;
        }

        sleep(Duration::from_millis(100)).await;
    }

    assert!(route_found, "Route 10.0.0.0/24 not found in Server1's RIB");

    // Server2 withdraws the route
    client2
        .withdraw_route("10.0.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route");

    // Poll for route to disappear from Server1's RIB
    let mut route_withdrawn = false;
    for _ in 0..100 {
        let routes = client1.get_routes().await.unwrap();

        if routes.is_empty() {
            route_withdrawn = true;
            break;
        }

        sleep(Duration::from_millis(100)).await;
    }

    assert!(
        route_withdrawn,
        "Route 10.0.0.0/24 not withdrawn from Server1's RIB"
    );

    // Verify peers are still established after route withdrawal
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

#[tokio::test]
async fn test_three_meshed_servers_announce() {
    let (mut client1, mut client2, mut client3) =
        setup_three_meshed_servers(65001, 65002, 65003).await;

    // Verify all servers have 2 peers each
    let peers1 = client1.get_peers().await.unwrap();
    let peers2 = client2.get_peers().await.unwrap();
    let peers3 = client3.get_peers().await.unwrap();

    assert_eq!(peers1.len(), 2, "Server 1 should have 2 peers");
    assert_eq!(peers2.len(), 2, "Server 2 should have 2 peers");
    assert_eq!(peers3.len(), 2, "Server 3 should have 2 peers");

    // Server1 announces a route
    client1
        .announce_route("10.1.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route to appear in Server2 and Server3's RIBs
    let mut route_found_in_server2 = false;
    let mut route_found_in_server3 = false;

    for _ in 0..100 {
        // Check server2 - should receive route from both server1 and server3
        if !route_found_in_server2 {
            let routes = client2.get_routes().await.unwrap();
            if routes.len() == 1 {
                let route = &routes[0];
                assert_eq!(route.prefix, "10.1.0.0/24", "Route prefix mismatch in server 2");

                // In a full mesh, server2 should receive the route from:
                // 1. Server1 directly: AS path [65001]
                // 2. Server3: AS path [65003, 65001]
                if route.paths.len() == 2 {
                    let mut as_paths: Vec<_> = route.paths.iter().map(|p| &p.as_path).collect();
                    as_paths.sort();

                    assert!(
                        as_paths.contains(&&vec![65001]),
                        "Server2 should have direct path from server1: {:?}",
                        as_paths
                    );
                    assert!(
                        as_paths.contains(&&vec![65003, 65001]),
                        "Server2 should have path via server3: {:?}",
                        as_paths
                    );
                    route_found_in_server2 = true;
                }
            }
        }

        // Check server3 - should receive route from both server1 and server2
        if !route_found_in_server3 {
            let routes = client3.get_routes().await.unwrap();
            if routes.len() == 1 {
                let route = &routes[0];
                assert_eq!(route.prefix, "10.1.0.0/24", "Route prefix mismatch in server 3");

                // In a full mesh, server3 should receive the route from:
                // 1. Server1 directly: AS path [65001]
                // 2. Server2: AS path [65002, 65001]
                if route.paths.len() == 2 {
                    let mut as_paths: Vec<_> = route.paths.iter().map(|p| &p.as_path).collect();
                    as_paths.sort();

                    assert!(
                        as_paths.contains(&&vec![65001]),
                        "Server3 should have direct path from server1: {:?}",
                        as_paths
                    );
                    assert!(
                        as_paths.contains(&&vec![65002, 65001]),
                        "Server3 should have path via server2: {:?}",
                        as_paths
                    );
                    route_found_in_server3 = true;
                }
            }
        }

        if route_found_in_server2 && route_found_in_server3 {
            break;
        }

        sleep(Duration::from_millis(100)).await;
    }

    assert!(
        route_found_in_server2,
        "Route 10.1.0.0/24 not found in Server2's RIB"
    );
    assert!(
        route_found_in_server3,
        "Route 10.1.0.0/24 not found in Server3's RIB"
    );

    // Verify all peers are still established
    let peers1 = client1.get_peers().await.unwrap();
    let peers2 = client2.get_peers().await.unwrap();
    let peers3 = client3.get_peers().await.unwrap();

    assert!(
        peers1.iter().all(|p| p.state == "Established"),
        "All server 1 peers should be established"
    );
    assert!(
        peers2.iter().all(|p| p.state == "Established"),
        "All server 2 peers should be established"
    );
    assert!(
        peers3.iter().all(|p| p.state == "Established"),
        "All server 3 peers should be established"
    );
}
