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

mod common;
pub use common::*;

use bgpgg::bmp::msg::MessageType;
use bgpgg::grpc::proto::BgpState;

#[tokio::test]
async fn test_add_bmp_server_sends_initiation() {
    let mut bmp_server = FakeBmpServer::new().await;
    let bmp_addr = bmp_server.address();

    let mut server = start_test_server(test_config(65001, 1)).await;

    server.client.add_bmp_server(bmp_addr).await.unwrap();

    bmp_server.accept().await;
    bmp_server.read_message_type(MessageType::Initiation).await;
}

#[tokio::test]
async fn test_add_bmp_server_with_existing_peers() {
    let (mut server, _peer1, _peer2) = setup_three_meshed_servers(Some(90)).await;

    let mut bmp_server = FakeBmpServer::new().await;
    setup_bmp_monitoring(&mut server, &mut bmp_server).await;

    // Should receive peer up for both existing peers
    bmp_server
        .read_message_type(MessageType::PeerUpNotification)
        .await;
    bmp_server
        .read_message_type(MessageType::PeerUpNotification)
        .await;
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

    // Read PeerUp message (only from server1, which has BMP configured)
    bmp_server
        .read_message_type(MessageType::PeerUpNotification)
        .await;

    // Remove peer
    server1.remove_peer(&server2).await;

    // Wait for peer to be removed
    poll_peers(&server1, vec![]).await;

    // Read PeerDown message (only from server1)
    bmp_server
        .read_message_type(MessageType::PeerDownNotification)
        .await;
}
