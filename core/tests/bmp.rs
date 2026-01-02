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

use bgpgg::bmp::msg::{MessageType, BMP_VERSION};
use bgpgg::config::Config;
use bgpgg::grpc::proto::BgpState;
use std::net::Ipv4Addr;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

#[allow(dead_code)]
struct BmpMessageHeader {
    version: u8,
    length: u32,
    message_type: u8,
}

/// Fake BMP server for testing
struct FakeBmpServer {
    listener: TcpListener,
    stream: Option<TcpStream>,
}

impl FakeBmpServer {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Self {
            listener,
            stream: None,
        }
    }

    fn address(&self) -> String {
        let addr = self.listener.local_addr().unwrap();
        format!("{}:{}", addr.ip(), addr.port())
    }

    async fn accept(&mut self) {
        let (stream, _) = self.listener.accept().await.unwrap();
        self.stream = Some(stream);
    }

    async fn read_message(&mut self) -> (BmpMessageHeader, Vec<u8>) {
        let stream = self.stream.as_mut().unwrap();

        // Read BMP common header (6 bytes)
        let mut header_buf = [0u8; 6];
        stream.read_exact(&mut header_buf).await.unwrap();

        let version = header_buf[0];
        let length =
            u32::from_be_bytes([header_buf[1], header_buf[2], header_buf[3], header_buf[4]]);
        let message_type = header_buf[5];

        assert_eq!(version, BMP_VERSION, "Invalid BMP version");

        // Read message body (length includes the 6-byte header)
        let body_len = length as usize - 6;
        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body).await.unwrap();

        (
            BmpMessageHeader {
                version,
                length,
                message_type,
            },
            body,
        )
    }

    async fn read_initiation(&mut self) {
        let (header, _body) = self.read_message().await;
        assert_eq!(
            header.message_type,
            MessageType::Initiation.as_u8(),
            "Expected Initiation message"
        );
    }

    async fn read_peer_up(&mut self) {
        let (header, _body) = self.read_message().await;
        assert_eq!(
            header.message_type,
            MessageType::PeerUpNotification.as_u8(),
            "Expected PeerUp message"
        );
    }

    async fn read_peer_down(&mut self) {
        let (header, _body) = self.read_message().await;
        assert_eq!(
            header.message_type,
            MessageType::PeerDownNotification.as_u8(),
            "Expected PeerDown message"
        );
    }
}

#[tokio::test]
async fn test_peer_up_down() {
    let mut bmp_server = FakeBmpServer::new().await;
    let bmp_addr = bmp_server.address();

    let mut server1 = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
        true,
    ))
    .await;

    let server2 = start_test_server(Config::new(
        65002,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
        true,
    ))
    .await;

    // Add BMP server to server1
    server1
        .client
        .add_bmp_server(bmp_addr.clone())
        .await
        .unwrap();

    // Accept BMP connection
    bmp_server.accept().await;

    // Read Initiation message sent immediately upon adding destination
    bmp_server.read_initiation().await;

    // Add BGP peer
    server1
        .client
        .add_peer(format!("{}:{}", server2.address, server2.bgp_port), None)
        .await
        .unwrap();

    // Wait for peer to establish
    poll_until(
        || async {
            let peers = server1.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Established as i32
        },
        "Timeout waiting for peer to establish",
    )
    .await;

    // Read PeerUp message (only from server1, which has BMP configured)
    bmp_server.read_peer_up().await;

    // Remove peer
    server1
        .client
        .remove_peer(server2.address.clone())
        .await
        .unwrap();

    // Wait for peer to be removed
    poll_until(
        || async {
            let peers = server1.client.get_peers().await.unwrap();
            peers.is_empty()
        },
        "Timeout waiting for peer to be removed",
    )
    .await;

    // Read PeerDown message (only from server1)
    bmp_server.read_peer_down().await;
}
