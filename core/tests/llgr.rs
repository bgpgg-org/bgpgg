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

//! Tests for Long-Lived Graceful Restart (RFC 9494)

mod utils;
pub use utils::*;

use bgpgg::grpc::proto::BgpState;
use std::net::Ipv4Addr;

/// RFC 9494 Section 4.5: LLGR capability without GR capability MUST be ignored.
/// FakePeer sends OPEN with LLGR cap (code 71) but no GR cap (code 64).
/// After FakePeer drops, route is swept immediately (no LLGR retention).
#[tokio::test]
async fn test_llgr_ignored_without_gr() {
    let mut config = test_config(65001, 1);
    config.peers.push(bgpgg::config::PeerConfig {
        address: "127.0.0.2".to_string(),
        passive_mode: true,
        ..Default::default()
    });
    let server = start_test_server(config).await;

    // FakePeer connects with LLGR capability but NO GR capability
    let llgr_cap = build_llgr_capability(false, 30);
    let mut fake = FakePeer::connect_and_handshake(
        Some("127.0.0.2"),
        &server,
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
        Some(vec![llgr_cap]),
    )
    .await;

    // Verify established
    poll_peers(&server, vec![fake.to_peer(BgpState::Established)]).await;

    // Announce a route via raw UPDATE
    let update = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(127, 0, 0, 2)),
            &attr_local_pref(100),
        ],
        &[24, 10, 0, 0], // 10.0.0.0/24
        None,
    );
    fake.send_raw(&update).await;

    poll_until(
        || async {
            let Ok(routes) = server.client.get_routes().await else {
                return false;
            };
            routes.iter().any(|route| route.prefix == "10.0.0.0/24")
        },
        "Timeout waiting for route 10.0.0.0/24 to appear",
    )
    .await;

    // Drop TCP - no GR was negotiated (LLGR without GR is ignored),
    // so route should be swept immediately
    drop(fake);

    // Route should be withdrawn promptly (no LLGR retention).
    // Short timeout proves it's immediate, not retained for LLST (30s).
    poll_until_with_timeout(
        || async {
            let Ok(routes) = server.client.get_routes().await else {
                return false;
            };
            routes.is_empty()
        },
        "Route should be withdrawn immediately without LLGR retention",
        Duration::from_secs(2),
    )
    .await;
}
