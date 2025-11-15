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

use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpSocket, TcpStream};

/// Create and bind a TCP socket for outgoing BGP connections
///
/// This helper creates an appropriate socket (IPv4 or IPv6) based on the remote address,
/// binds it to the specified local address, and connects to the remote address.
///
/// # Arguments
/// * `local_addr` - Local address to bind to (typically IP:0 for automatic port selection)
/// * `remote_addr` - Remote address to connect to (IP:179 for BGP)
///
/// # Returns
/// `TcpStream` on success, or an `io::Error` on failure
pub async fn create_and_bind_tcp_socket(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> io::Result<TcpStream> {
    // Create appropriate socket based on remote address type
    let socket = if remote_addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    // Bind to local address
    socket.bind(local_addr)?;

    // Connect to remote peer
    socket.connect(remote_addr).await
}
