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

use bgpgg::grpc::proto::BgpState;

#[tokio::test]
async fn test_add_bmp_server_sends_initiation() {
    let mut bmp_server = FakeBmpServer::new().await;
    let bmp_addr = bmp_server.address();

    let mut server = start_test_server(test_config(65001, 1)).await;

    server.client.add_bmp_server(bmp_addr).await.unwrap();

    bmp_server.accept().await;
    let msg = bmp_server.read_initiation().await;
    assert_bmp_initiation_msg(&msg, &server.config.sys_name(), &server.config.sys_descr());
}

#[tokio::test]
async fn test_add_bmp_server_with_existing_peers() {
    let (mut server, peer1, peer2) = setup_three_meshed_servers(Some(90)).await;

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
        server.address,
        peers[0].address,
        peers[0].asn as u32,
        u32::from(peers[0].client.router_id),
        peers[0].bgp_port,
    );
    assert_bmp_peer_up_msg(
        &peer_ups[1],
        server.address,
        peers[1].address,
        peers[1].asn as u32,
        u32::from(peers[1].client.router_id),
        peers[1].bgp_port,
    );
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
    let peer_up = bmp_server.read_peer_up().await;
    assert_bmp_peer_up_msg(
        &peer_up,
        server1.address,
        server2.address,
        server2.asn as u32,
        u32::from(server2.client.router_id),
        server2.bgp_port,
    );

    // Remove peer
    server1.remove_peer(&server2).await;

    // Wait for peer to be removed
    poll_peers(&server1, vec![]).await;

    // Read and verify PeerDown message
    let peer_down = bmp_server.read_peer_down().await;
    assert_bmp_peer_down_msg(
        &peer_down,
        server2.address,
        server2.asn as u32,
        u32::from(server2.client.router_id),
        &bgpgg::types::PeerDownReason::PeerDeConfigured,
    );
}
