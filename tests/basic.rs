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
use bgpgg::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin, UpdateMessage};
use bgpgg::bgp::utils::{IpNetwork, Ipv4Net};
use bgpgg::server::BgpServer;
use std::io::Write;
use std::net::{Ipv4Addr, TcpStream};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_two_bgp_servers_peering() {
    // Start two BGP servers
    let server1 = Arc::new(BgpServer::new(65100));
    let server2 = Arc::new(BgpServer::new(65200));
    tokio::spawn({
        let server = Arc::clone(&server1);
        async move { server.run_on("127.0.0.1:1790").await }
    });
    tokio::spawn({
        let server = Arc::clone(&server2);
        async move { server.run_on("127.0.0.1:1791").await }
    });

    // Server1 connects to Server2
    server1.add_peer("127.0.0.1:1791").await;

    // Wait for peering to establish by polling peer counts
    for _ in 0..100 {
        let peers1 = server1.peers.lock().await.len();
        let peers2 = server2.peers.lock().await.len();
        if peers1 == 1 && peers2 == 1 {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    // Verify that both servers have peers
    assert_eq!(server1.peers.lock().await.len(), 1, "Server 1 should have 1 peer");
    assert_eq!(server2.peers.lock().await.len(), 1, "Server 2 should have 1 peer");
}

#[tokio::test]
async fn test_announce_one_route() {
    // Start a BGP server
    let server_port = 1792;

    let server = BgpServer::new(65100); // ASN 65100
    let server_peers = server.peers.clone();
    let server_rib = server.rib.clone();

    // Start server in background
    tokio::spawn(async move {
        server.run_on(&format!("127.0.0.1:{}", server_port)).await;
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    // Connect from a test client to server and send OPEN + KEEPALIVE + UPDATE
    let client_handle = tokio::spawn(async move {
        sleep(Duration::from_millis(200)).await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server_port))
            .expect("Failed to connect to server");
        println!("Client connected to server");

        // Send OPEN message
        let open_msg = OpenMessage::new(65001, 180, 0x01010101);
        stream
            .write_all(&open_msg.serialize())
            .expect("Failed to send OPEN to server");
        println!("Client sent OPEN to server");

        // Send KEEPALIVE message
        sleep(Duration::from_millis(100)).await;
        let keepalive_msg = KeepAliveMessage {};
        stream
            .write_all(&keepalive_msg.serialize())
            .expect("Failed to send KEEPALIVE to server");
        println!("Client sent KEEPALIVE to server");

        // Send UPDATE message announcing a route
        sleep(Duration::from_millis(100)).await;
        let update_msg = UpdateMessage::new(
            Origin::IGP,
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65001],
            }],
            Ipv4Addr::new(192, 168, 1, 1), // Next hop
            vec![IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 0, 0),
                prefix_length: 24,
            })],
        );
        stream
            .write_all(&update_msg.serialize())
            .expect("Failed to send UPDATE to server");
        println!("Client sent UPDATE announcing route 10.0.0.0/24 to server");

        // Keep connection alive while we verify
        sleep(Duration::from_millis(500)).await;
        stream
    });

    // Give server time to process messages
    sleep(Duration::from_millis(500)).await;

    // Verify that server has established peering
    {
        let peers = server_peers.lock().await;
        assert_eq!(peers.len(), 1, "Server should have 1 peer after peering");
        println!("Server has {} peer(s)", peers.len());
    }

    // Verify that the route is in the Loc-RIB
    let routes = server_rib.query_loc_rib().await.unwrap();

    assert_eq!(routes.len(), 1, "RIB should contain 1 route");

    let route = &routes[0];
    assert_eq!(
        route.prefix,
        IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        }),
        "Route prefix should be 10.0.0.0/24"
    );

    assert_eq!(route.paths.len(), 1, "Route should have 1 path");

    let path = &route.paths[0];
    assert_eq!(path.origin, Origin::IGP, "Origin should be IGP");
    assert_eq!(path.as_path, vec![65001], "AS path should be [65001]");
    assert_eq!(
        path.next_hop,
        Ipv4Addr::new(192, 168, 1, 1),
        "Next hop should be 192.168.1.1"
    );

    println!("E2E route announcement test completed successfully!");
    println!("Verified route 10.0.0.0/24 with next hop 192.168.1.1 via AS 65001");

    // Now let the connection close
    let _ = client_handle.await;
}
