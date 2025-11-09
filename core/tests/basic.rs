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

mod common;

use bgpgg::grpc::proto::{BgpState, Origin, Path, Peer, Route};
use common::{
    poll_route_propagation, poll_route_withdrawal, setup_four_meshed_servers,
    setup_three_meshed_servers, setup_two_peered_servers, verify_peers,
};

#[tokio::test]
async fn test_announce_withdraw() {
    let (server1, mut server2) = setup_two_peered_servers(None).await;

    // Server2 announces a route to Server1 via gRPC
    server2
        .client
        .announce_route("10.0.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route");

    // Get the actual peer address (with OS-allocated port)
    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    // Poll for route to appear in Server1's RIB
    poll_route_propagation(&[(
        &server1,
        vec![Route {
            prefix: "10.0.0.0/24".to_string(),
            paths: vec![Path {
                origin: Origin::Igp.into(),
                as_path: vec![65002],
                next_hop: "192.168.1.1".to_string(),
                peer_address: peer_addr.clone(),
                local_pref: Some(100),
                med: None,
            }],
        }],
    )])
    .await;

    // Server2 withdraws the route
    server2
        .client
        .withdraw_route("10.0.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route");

    // Poll for withdrawal and verify peers are still established
    poll_route_withdrawal(&[&server1]).await;
    assert!(
        verify_peers(
            &server1,
            vec![Peer {
                address: server2.address.clone(),
                asn: server2.asn as u32,
                state: BgpState::Established.into(),
            }],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![Peer {
                address: server1.address.clone(),
                asn: server1.asn as u32,
                state: BgpState::Established.into(),
            }],
        )
        .await
    );
}

#[tokio::test]
async fn test_announce_withdraw_mesh() {
    let (mut server1, server2, server3) = setup_three_meshed_servers(None).await;

    // Server1 announces a route
    server1
        .client
        .announce_route("10.1.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route propagation with expected AS paths
    // After best path selection, only the best path (shortest AS_PATH) should remain

    // Get actual peer addresses
    let peers2 = server2.client.get_peers().await.unwrap();
    let peer2_from_server1 = peers2.iter().find(|p| p.asn == 65001).unwrap();

    let peers3 = server3.client.get_peers().await.unwrap();
    let peer3_from_server1 = peers3.iter().find(|p| p.asn == 65001).unwrap();

    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: peer2_from_server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: peer3_from_server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
    ])
    .await;

    // Server1 withdraws the route
    server1
        .client
        .withdraw_route("10.1.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route from server 1");

    // Poll for withdrawal and verify peers are still established
    poll_route_withdrawal(&[&server2, &server3]).await;
    assert!(
        verify_peers(
            &server1,
            vec![
                Peer {
                    address: server2.address.clone(),
                    asn: server2.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server3.address.clone(),
                    asn: server3.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![
                Peer {
                    address: server1.address.clone(),
                    asn: server1.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server3.address.clone(),
                    asn: server3.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server3,
            vec![
                Peer {
                    address: server1.address.clone(),
                    asn: server1.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server2.address.clone(),
                    asn: server2.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
}

#[tokio::test]
async fn test_announce_withdraw_four_node_mesh() {
    let (mut server1, server2, server3, server4) = setup_four_meshed_servers(None).await;

    // Server1 announces a route
    server1
        .client
        .announce_route("10.1.0.0/24".to_string(), "192.168.1.1".to_string(), 0)
        .await
        .expect("Failed to announce route from server 1");

    // Poll for route propagation with expected AS paths
    // After best path selection, only the best path (shortest AS_PATH) should remain

    // Get actual peer addresses
    let peers2 = server2.client.get_peers().await.unwrap();
    let peer2_from_server1 = peers2.iter().find(|p| p.asn == 65001).unwrap();

    let peers3 = server3.client.get_peers().await.unwrap();
    let peer3_from_server1 = peers3.iter().find(|p| p.asn == 65001).unwrap();

    let peers4 = server4.client.get_peers().await.unwrap();
    let peer4_from_server1 = peers4.iter().find(|p| p.asn == 65001).unwrap();

    poll_route_propagation(&[
        (
            &server2,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: peer2_from_server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
        (
            &server3,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: peer3_from_server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
        (
            &server4,
            vec![Route {
                prefix: "10.1.0.0/24".to_string(),
                paths: vec![Path {
                    origin: Origin::Igp.into(),
                    as_path: vec![65001],
                    next_hop: "192.168.1.1".to_string(),
                    peer_address: peer4_from_server1.address.clone(),
                    local_pref: Some(100),
                    med: None,
                }],
            }],
        ),
    ])
    .await;

    // Server1 withdraws the route
    server1
        .client
        .withdraw_route("10.1.0.0/24".to_string())
        .await
        .expect("Failed to withdraw route from server 1");

    // Poll for withdrawal and verify peers are still established
    poll_route_withdrawal(&[&server2, &server3, &server4]).await;
    assert!(
        verify_peers(
            &server1,
            vec![
                Peer {
                    address: server2.address.clone(),
                    asn: server2.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server3.address.clone(),
                    asn: server3.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server4.address.clone(),
                    asn: server4.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![
                Peer {
                    address: server1.address.clone(),
                    asn: server1.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server3.address.clone(),
                    asn: server3.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server4.address.clone(),
                    asn: server4.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server3,
            vec![
                Peer {
                    address: server1.address.clone(),
                    asn: server1.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server2.address.clone(),
                    asn: server2.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server4.address.clone(),
                    asn: server4.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server4,
            vec![
                Peer {
                    address: server1.address.clone(),
                    asn: server1.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server2.address.clone(),
                    asn: server2.asn as u32,
                    state: BgpState::Established.into(),
                },
                Peer {
                    address: server3.address.clone(),
                    asn: server3.asn as u32,
                    state: BgpState::Established.into(),
                },
            ],
        )
        .await
    );
}
