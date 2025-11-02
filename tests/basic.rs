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

use bgpgg::bgp::msg::Message;
use bgpgg::bgp::msg_keepalive::KeepAliveMessage;
use bgpgg::bgp::msg_open::OpenMessage;
use bgpgg::server::BgpServer;
use std::io::Write;
use std::net::TcpStream;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_two_bgp_servers_peering() {
    // Start two BGP servers on different ports
    let server1_port = 1790;
    let server2_port = 1791;

    let server1 = BgpServer::new();
    let server2 = BgpServer::new();

    // Clone peer references before moving servers into tasks
    let server1_peers = server1.peers.clone();
    let server2_peers = server2.peers.clone();

    // Start server1 in background
    tokio::spawn(async move {
        server1.run_on(&format!("127.0.0.1:{}", server1_port)).await;
    });

    // Start server2 in background
    tokio::spawn(async move {
        server2.run_on(&format!("127.0.0.1:{}", server2_port)).await;
    });

    // Give servers time to start
    sleep(Duration::from_millis(100)).await;

    // Connect from a test client to server1 and send OPEN + KEEPALIVE
    let client1_handle = tokio::spawn(async move {
        sleep(Duration::from_millis(200)).await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server1_port))
            .expect("Failed to connect to server1");
        println!("Client 1 connected to server 1");

        // Send OPEN message
        let open_msg = OpenMessage::new(65001, 180, 0x01010101);
        stream
            .write_all(&open_msg.serialize())
            .expect("Failed to send OPEN to server1");
        println!("Client 1 sent OPEN to server 1");

        // Send KEEPALIVE message
        sleep(Duration::from_millis(100)).await;
        let keepalive_msg = KeepAliveMessage {};
        stream
            .write_all(&keepalive_msg.serialize())
            .expect("Failed to send KEEPALIVE to server1");
        println!("Client 1 sent KEEPALIVE to server 1");

        // Keep connection alive while we check peer counts
        sleep(Duration::from_millis(500)).await;
        stream
    });

    // Connect from another test client to server2 and send OPEN + KEEPALIVE
    let client2_handle = tokio::spawn(async move {
        sleep(Duration::from_millis(200)).await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server2_port))
            .expect("Failed to connect to server2");
        println!("Client 2 connected to server 2");

        // Send OPEN message
        let open_msg = OpenMessage::new(65002, 180, 0x02020202);
        stream
            .write_all(&open_msg.serialize())
            .expect("Failed to send OPEN to server2");
        println!("Client 2 sent OPEN to server 2");

        // Send KEEPALIVE message
        sleep(Duration::from_millis(100)).await;
        let keepalive_msg = KeepAliveMessage {};
        stream
            .write_all(&keepalive_msg.serialize())
            .expect("Failed to send KEEPALIVE to server2");
        println!("Client 2 sent KEEPALIVE to server 2");

        // Keep connection alive while we check peer counts
        sleep(Duration::from_millis(500)).await;
        stream
    });

    // Give servers time to process messages and establish peering
    sleep(Duration::from_millis(500)).await;

    // Verify that both servers have peers WHILE connections are still open
    {
        let peers1 = server1_peers.lock().await;
        assert_eq!(
            peers1.len(),
            1,
            "Server 1 should have 1 peer after peering"
        );
        println!("Server 1 has {} peer(s)", peers1.len());
    }

    {
        let peers2 = server2_peers.lock().await;
        assert_eq!(
            peers2.len(),
            1,
            "Server 2 should have 1 peer after peering"
        );
        println!("Server 2 has {} peer(s)", peers2.len());
    }

    println!("E2E peering test completed successfully!");

    // Now let the connections close
    let _ = tokio::join!(client1_handle, client2_handle);
}
