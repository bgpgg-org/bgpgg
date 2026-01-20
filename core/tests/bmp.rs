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

//! Tests for BMP (BGP Monitoring Protocol)

mod utils;

pub use utils::bmp::*;
pub use utils::*;

use bgpgg::bmp::msg_termination::TerminationReason;
use bgpgg::config::BmpConfig;
use bgpgg::grpc::proto::BgpState;
use bgpgg::net::{IpNetwork, Ipv4Net};
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_add_bmp_server_sends_initiation() {
    let mut bmp_server = FakeBmpServer::new().await;
    let bmp_addr = bmp_server.address();

    let mut server = start_test_server(test_config(65001, 1)).await;

    server.client.add_bmp_server(bmp_addr, None).await.unwrap();

    bmp_server.accept().await;
    bmp_server
        .assert_bmp_initiation(&server.config.sys_name(), &server.config.sys_descr())
        .await;
}

#[tokio::test]
async fn test_add_bmp_server_with_existing_peers() {
    let (mut server, mut peer1, mut peer2) = setup_three_meshed_servers(Some(90)).await;

    // Announce routes from peer1
    announce_route(
        &mut peer1,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Announce routes from peer2
    announce_route(
        &mut peer2,
        RouteParams {
            prefix: "10.0.1.0/24".to_string(),
            next_hop: "192.168.1.2".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Wait for routes to be received
    poll_until(
        || async {
            let routes = server.client.get_routes().await.unwrap();
            routes.len() == 2
        },
        "Timeout waiting for routes",
    )
    .await;

    // Add an idle peer (connection will fail - address doesn't exist)
    server
        .client
        .add_peer("192.168.255.1:179".to_string(), None)
        .await
        .unwrap();

    // Wait for it to reach Idle state
    poll_until(
        || async {
            let peers = server.client.get_peers().await.unwrap();
            peers.len() == 3 && peers.iter().any(|p| p.state == BgpState::Idle as i32)
        },
        "Timeout waiting for idle peer",
    )
    .await;

    let mut bmp_server = FakeBmpServer::new().await;
    setup_bmp_monitoring(&mut server, &mut bmp_server).await;

    // Should receive peer up for ONLY the 2 established peers (not the idle one)
    let peer_up_1 = bmp_server.read_peer_up().await;
    let peer_up_2 = bmp_server.read_peer_up().await;

    // Sort peer_up messages by peer address
    let mut peer_ups = [peer_up_1, peer_up_2];
    peer_ups.sort_by_key(|p| p.peer_header.peer_address);

    // Sort peers by address
    let mut peers = [peer1, peer2];
    peers.sort_by_key(|p| p.address);

    // Verify each peer up message
    assert_bmp_peer_up_msg(
        &peer_ups[0],
        &ExpectedPeerUp {
            local_addr: server.address,
            peer_addr: peers[0].address,
            peer_as: peers[0].asn,
            peer_bgp_id: u32::from(peers[0].client.router_id),
            peer_port: peers[0].bgp_port,
        },
    );
    assert_bmp_peer_up_msg(
        &peer_ups[1],
        &ExpectedPeerUp {
            local_addr: server.address,
            peer_addr: peers[1].address,
            peer_as: peers[1].asn,
            peer_bgp_id: u32::from(peers[1].client.router_id),
            peer_port: peers[1].bgp_port,
        },
    );

    // Should receive route monitoring messages (2 routes per peer = 4 total in mesh)
    // Each peer's Adj-RIB-In contains routes received from the other peer too
    let rm1 = bmp_server.read_route_monitoring().await;
    let rm2 = bmp_server.read_route_monitoring().await;
    let rm3 = bmp_server.read_route_monitoring().await;
    let rm4 = bmp_server.read_route_monitoring().await;

    // Both routes in mesh
    let route_1 = [IpNetwork::V4(Ipv4Net {
        address: Ipv4Addr::new(10, 0, 0, 0),
        prefix_length: 24,
    })];
    let route_2 = [IpNetwork::V4(Ipv4Net {
        address: Ipv4Addr::new(10, 0, 1, 0),
        prefix_length: 24,
    })];

    // Verify each message
    for rm in &[&rm1, &rm2, &rm3, &rm4] {
        let peer_addr = rm.peer_header().peer_address;
        let peer = peers.iter().find(|p| p.address == peer_addr).unwrap();
        let nlri = rm.bgp_update().nlri_list();

        // Must be one of the two routes
        assert!(nlri[..] == route_1[..] || nlri[..] == route_2[..]);

        assert_bmp_route_monitoring_msg(
            rm,
            &ExpectedRouteMonitoring {
                peer_addr: peer.address,
                peer_as: peer.asn,
                peer_bgp_id: u32::from(peer.client.router_id),
                peer_flags: 0,
                nlri: nlri.to_vec(),
                withdrawn: vec![],
            },
        );
    }
}

#[tokio::test]
async fn test_peer_up_down() {
    let mut bmp_server = FakeBmpServer::new().await;
    let mut server1 = start_test_server(test_config(65001, 1)).await;
    let server2 = start_test_server(test_config(65002, 2)).await;

    setup_bmp_monitoring(&mut server1, &mut bmp_server).await;

    // Add BGP peer
    server1.add_peer(&server2).await;

    // Wait for peer to establish
    poll_peers(&server1, vec![server2.to_peer(BgpState::Established, true)]).await;

    // Read and verify PeerUp message
    bmp_server
        .assert_peer_up(&ExpectedPeerUp {
            local_addr: server1.address,
            peer_addr: server2.address,
            peer_as: server2.asn,
            peer_bgp_id: u32::from(server2.client.router_id),
            peer_port: server2.bgp_port,
        })
        .await;

    // Remove peer
    server1.remove_peer(&server2).await;

    // Wait for peer to be removed
    poll_peers(&server1, vec![]).await;

    // Read and verify PeerDown message
    bmp_server
        .assert_peer_down(&ExpectedPeerDown {
            peer_addr: server2.address,
            peer_as: server2.asn,
            peer_bgp_id: u32::from(server2.client.router_id),
            reason: bgpgg::types::PeerDownReason::PeerDeConfigured,
        })
        .await;
}

#[tokio::test]
async fn test_route_monitoring_on_updates() {
    let mut bmp_server = FakeBmpServer::new().await;
    let (mut server1, mut server2) = setup_two_peered_servers(Some(90)).await;

    setup_bmp_monitoring(&mut server1, &mut bmp_server).await;

    // Read PeerUp message (sent when BMP server added to already-established peer)
    let _peer_up = bmp_server.read_peer_up().await;

    // Announce routes from server2
    announce_route(
        &mut server2,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    announce_route(
        &mut server2,
        RouteParams {
            prefix: "10.0.1.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Wait for routes to be received
    poll_until(
        || async {
            let routes = server1.client.get_routes().await.unwrap();
            routes.len() == 2
        },
        "Timeout waiting for routes",
    )
    .await;

    // Should receive 2 RouteMonitoring messages (one per UPDATE from peer)
    bmp_server
        .assert_route_monitoring(&ExpectedRouteMonitoring {
            peer_addr: server2.address,
            peer_as: server2.asn,
            peer_bgp_id: u32::from(server2.client.router_id),
            peer_flags: 0,
            nlri: vec![IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 0, 0),
                prefix_length: 24,
            })],
            withdrawn: vec![],
        })
        .await;

    bmp_server
        .assert_route_monitoring(&ExpectedRouteMonitoring {
            peer_addr: server2.address,
            peer_as: server2.asn,
            peer_bgp_id: u32::from(server2.client.router_id),
            peer_flags: 0,
            nlri: vec![IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 1, 0),
                prefix_length: 24,
            })],
            withdrawn: vec![],
        })
        .await;

    // Withdraw one route
    server2
        .client
        .remove_route("10.0.0.0/24".to_string())
        .await
        .unwrap();

    // Wait for route to be withdrawn
    poll_until(
        || async {
            let routes = server1.client.get_routes().await.unwrap();
            routes.len() == 1
        },
        "Timeout waiting for route withdrawal",
    )
    .await;

    // Add a new route
    announce_route(
        &mut server2,
        RouteParams {
            prefix: "10.0.2.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Wait for new route
    poll_until(
        || async {
            let routes = server1.client.get_routes().await.unwrap();
            routes.len() == 2
        },
        "Timeout waiting for new route",
    )
    .await;

    // Should receive RouteMonitoring for withdrawal
    bmp_server
        .assert_route_monitoring(&ExpectedRouteMonitoring {
            peer_addr: server2.address,
            peer_as: server2.asn,
            peer_bgp_id: u32::from(server2.client.router_id),
            peer_flags: 0,
            nlri: vec![],
            withdrawn: vec![IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 0, 0),
                prefix_length: 24,
            })],
        })
        .await;

    // Should receive RouteMonitoring for new announcement
    bmp_server
        .assert_route_monitoring(&ExpectedRouteMonitoring {
            peer_addr: server2.address,
            peer_as: server2.asn,
            peer_bgp_id: u32::from(server2.client.router_id),
            peer_flags: 0,
            nlri: vec![IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 2, 0),
                prefix_length: 24,
            })],
            withdrawn: vec![],
        })
        .await;
}

#[tokio::test]
async fn test_bmp_termination_on_remove() {
    let mut bmp_server = FakeBmpServer::new().await;
    let mut server = start_test_server(test_config(65001, 1)).await;

    setup_bmp_monitoring(&mut server, &mut bmp_server).await;

    // Remove the BMP server destination
    server
        .client
        .remove_bmp_server(bmp_server.address())
        .await
        .unwrap();

    // Should receive Termination message with reason code PermanentlyAdminClose
    bmp_server
        .assert_termination(TerminationReason::PermanentlyAdminClose)
        .await;
}

#[tokio::test]
async fn test_bmp_statistics() {
    use bgpgg::bmp::msg_statistics::StatType;

    let mut bmp_server = FakeBmpServer::new().await;
    let mut server1 = start_test_server(test_config(65001, 1)).await;
    let mut server2 = start_test_server(test_config(65002, 2)).await;

    // Add BMP server with statistics enabled (1 second interval)
    server1
        .client
        .add_bmp_server(bmp_server.address(), Some(1))
        .await
        .unwrap();

    // Accept BMP connection and read initiation
    bmp_server.accept().await;
    let _initiation = bmp_server.read_initiation().await;

    // Add BGP peer
    server1.add_peer(&server2).await;

    // Wait for peer to establish
    poll_peers(&server1, vec![server2.to_peer(BgpState::Established, true)]).await;

    // Read first two messages - could be PeerUp and StatisticsReport in any order (race condition)
    bmp_server
        .assert_messages_no_order(&[
            ExpectedBmpMessage::PeerUp(ExpectedPeerUp {
                local_addr: server1.address,
                peer_addr: server2.address,
                peer_as: server2.asn,
                peer_bgp_id: u32::from(server2.client.router_id),
                peer_port: server2.bgp_port,
            }),
            ExpectedBmpMessage::Statistics(ExpectedStatistics {
                peer_addr: server2.address,
                peer_as: server2.asn,
                peer_bgp_id: u32::from(server2.client.router_id),
                stats: vec![(StatType::RoutesInAdjRibIn as u16, 0)],
            }),
        ])
        .await;

    // Add routes from server2
    announce_route(
        &mut server2,
        RouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    announce_route(
        &mut server2,
        RouteParams {
            prefix: "10.0.1.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        },
    )
    .await;

    // Wait for routes to be received
    poll_until(
        || async {
            let routes = server1.client.get_routes().await.unwrap();
            routes.len() == 2
        },
        "Timeout waiting for routes",
    )
    .await;

    // Read route monitoring messages
    let _rm1 = bmp_server.read_route_monitoring().await;
    let _rm2 = bmp_server.read_route_monitoring().await;

    // Wait for statistics message (should arrive within ~1-2 seconds)
    bmp_server
        .assert_statistics(&ExpectedStatistics {
            peer_addr: server2.address,
            peer_as: server2.asn,
            peer_bgp_id: u32::from(server2.client.router_id),
            stats: vec![(StatType::RoutesInAdjRibIn as u16, 2)],
        })
        .await;
}

#[tokio::test]
async fn test_configured_bmp_server() {
    let mut bmp_server = FakeBmpServer::new().await;
    let bmp_addr = bmp_server.address();

    // Create config with BMP server configured
    let mut config = test_config(65001, 1);
    config.bmp_servers.push(BmpConfig {
        address: bmp_addr.to_string(),
        statistics_timeout: None,
    });

    let server = start_test_server(config).await;

    // BMP client should automatically connect and send initiation
    bmp_server.accept().await;
    bmp_server
        .assert_bmp_initiation(&server.config.sys_name(), &server.config.sys_descr())
        .await;

    // Verify server is in the list
    let servers = server.client.get_bmp_servers().await.unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0], bmp_addr.to_string());
}
