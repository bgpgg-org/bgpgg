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

//! Routing Information Base (RIB) module
//!
//! This module implements BGP's three types of RIBs:
//! - Adj-RIB-In: Per-peer input tables storing routes received from peers
//! - Loc-RIB: Local routing table containing best paths
//! - Adj-RIB-Out: Per-peer output tables storing routes to advertise
//!
//! The RIB manager coordinates these tables and handles BGP message processing,
//! policy application, and best path selection.

mod rib_in;
mod rib_out;
mod rib_loc;
mod manager;
mod types;

// Re-exports
pub use manager::RibManager;
pub use types::{Path, QueryError, Route};

use crate::bgp::utils::IpNetwork;

/// Common trait for all RIB types
pub(super) trait Rib {
    /// Add a route for a prefix
    fn add_route(&mut self, prefix: IpNetwork, path: Path);

    /// Get all routes stored in this RIB
    fn get_all_routes(&self) -> Vec<Route>;

    /// Clear all routes from this RIB
    fn clear(&mut self);
}

use crate::bgp::msg::BgpMessage;
use std::net::SocketAddr;
use tokio::sync::mpsc;

pub enum RibMessage {
    PeerConnected(SocketAddr),
    PeerDisconnected(SocketAddr),
    BgpMessage { from: SocketAddr, message: BgpMessage },
    QueryLocRib { response_tx: tokio::sync::oneshot::Sender<Vec<Route>> },
    QueryAdjRibIn { peer: SocketAddr, response_tx: tokio::sync::oneshot::Sender<Vec<Route>> },
    QueryAdjRibOut { peer: SocketAddr, response_tx: tokio::sync::oneshot::Sender<Vec<Route>> },
}

/// Handle for interacting with the RIB manager
///
/// This provides a clean async API for sending messages to the RIB
/// and querying its state without directly accessing the internal structures.
#[derive(Clone)]
pub struct RibHandle {
    tx: mpsc::Sender<RibMessage>,
}

impl RibHandle {
    /// Create a new RIB and return a handle to it
    pub fn spawn(local_asn: u16) -> Self {
        let (tx, rx) = mpsc::channel(100);

        let rib = RibManager::new(local_asn);
        tokio::spawn(async move {
            rib.run(rx).await;
        });

        RibHandle { tx }
    }

    /// Notify RIB that a peer has connected
    pub async fn peer_connected(&self, addr: SocketAddr) -> Result<(), mpsc::error::SendError<RibMessage>> {
        self.tx.send(RibMessage::PeerConnected(addr)).await
    }

    /// Notify RIB that a peer has disconnected
    pub async fn peer_disconnected(&self, addr: SocketAddr) -> Result<(), mpsc::error::SendError<RibMessage>> {
        self.tx.send(RibMessage::PeerDisconnected(addr)).await
    }

    /// Send a BGP message to the RIB for processing
    pub async fn process_bgp_message(&self, from: SocketAddr, message: BgpMessage) -> Result<(), mpsc::error::SendError<RibMessage>> {
        self.tx.send(RibMessage::BgpMessage { from, message }).await
    }

    /// Query the Loc-RIB (best routes)
    pub async fn query_loc_rib(&self) -> Result<Vec<Route>, QueryError> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        self.tx.send(RibMessage::QueryLocRib { response_tx })
            .await
            .map_err(|_| QueryError::RibUnavailable)?;
        response_rx.await.map_err(|_| QueryError::RibUnavailable)
    }

    /// Query Adj-RIB-In for a specific peer (routes received from peer)
    pub async fn query_adj_rib_in(&self, peer: SocketAddr) -> Result<Vec<Route>, QueryError> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        self.tx.send(RibMessage::QueryAdjRibIn { peer, response_tx })
            .await
            .map_err(|_| QueryError::RibUnavailable)?;
        response_rx.await.map_err(|_| QueryError::RibUnavailable)
    }

    /// Query Adj-RIB-Out for a specific peer (routes to advertise to peer)
    pub async fn query_adj_rib_out(&self, peer: SocketAddr) -> Result<Vec<Route>, QueryError> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        self.tx.send(RibMessage::QueryAdjRibOut { peer, response_tx })
            .await
            .map_err(|_| QueryError::RibUnavailable)?;
        response_rx.await.map_err(|_| QueryError::RibUnavailable)
    }
}

#[cfg(test)]
mod test_helpers {
    use super::*;
    use crate::bgp::msg_update::Origin;
    use crate::bgp::utils::IpNetwork;
    use std::net::{Ipv4Addr, SocketAddr};

    pub(super) fn create_test_path(peer_addr: SocketAddr) -> Path {
        Path {
            origin: Origin::IGP,
            as_path: vec![100, 200],
            next_hop: Ipv4Addr::new(192, 0, 2, 1),
            from_peer: peer_addr,
            local_pref: Some(100),
            med: Some(0),
        }
    }

    pub(super) fn create_test_prefix() -> IpNetwork {
        IpNetwork::V4(crate::bgp::utils::Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        })
    }
}
