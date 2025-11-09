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

#[path = "mod.rs"]
mod test_utils;

use bgpgg::grpc::proto::BgpState;
use test_utils::{peer_in_state, setup_three_meshed_servers, setup_two_peered_servers};
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_two_bgp_servers_peering() {
    let (mut client1, mut client2) = setup_two_peered_servers(65100, 65200).await;

    // Verify that both servers have peers via gRPC
    let peers1 = client1.get_peers().await.unwrap();
    let peers2 = client2.get_peers().await.unwrap();

    assert_eq!(peers1.len(), 1, "Server 1 should have 1 peer");
    assert_eq!(peers2.len(), 1, "Server 2 should have 1 peer");

    // Verify FSM state is Established
    assert!(
        peer_in_state(&peers1[0], BgpState::Established),
        "Server 1 peer should be in Established state"
    );
    assert!(
        peer_in_state(&peers2[0], BgpState::Established),
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
    assert!(
        peer_in_state(&peers1[0], BgpState::Established),
        "Server 1 peer should still be in Established state"
    );
    assert!(
        peer_in_state(&peers2[0], BgpState::Established),
        "Server 2 peer should still be in Established state"
    );
}

#[tokio::test]
async fn test_announce_withdraw_mesh() {
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

    // Server1 withdraws the route
    client1
        .withdraw_route("10.1.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route from server 1");

    // Poll for route to disappear from Server2 and Server3's RIBs
    let mut route_withdrawn_from_server2 = false;
    let mut route_withdrawn_from_server3 = false;

    for _ in 0..100 {
        // Check server2
        if !route_withdrawn_from_server2 {
            let routes = client2.get_routes().await.unwrap();
            if routes.is_empty() {
                route_withdrawn_from_server2 = true;
            }
        }

        // Check server3
        if !route_withdrawn_from_server3 {
            let routes = client3.get_routes().await.unwrap();
            if routes.is_empty() {
                route_withdrawn_from_server3 = true;
            }
        }

        if route_withdrawn_from_server2 && route_withdrawn_from_server3 {
            break;
        }

        sleep(Duration::from_millis(100)).await;
    }

    assert!(
        route_withdrawn_from_server2,
        "Route 10.1.0.0/24 not withdrawn from Server2's RIB"
    );
    assert!(
        route_withdrawn_from_server3,
        "Route 10.1.0.0/24 not withdrawn from Server3's RIB"
    );

    // Verify all peers are still established after withdrawal
    let peers1 = client1.get_peers().await.unwrap();
    let peers2 = client2.get_peers().await.unwrap();
    let peers3 = client3.get_peers().await.unwrap();

    assert_eq!(peers1.len(), 2, "Server 1 should still have 2 peers");
    assert_eq!(peers2.len(), 2, "Server 2 should still have 2 peers");
    assert_eq!(peers3.len(), 2, "Server 3 should still have 2 peers");

    assert!(
        peers1.iter().all(|p| peer_in_state(p, BgpState::Established)),
        "All server 1 peers should still be established"
    );
    assert!(
        peers2.iter().all(|p| peer_in_state(p, BgpState::Established)),
        "All server 2 peers should still be established"
    );
    assert!(
        peers3.iter().all(|p| peer_in_state(p, BgpState::Established)),
        "All server 3 peers should still be established"
    );
}
