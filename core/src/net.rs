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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::{TcpSocket, TcpStream};

/// Extract IPv4 address from a SocketAddr, returns None for IPv6.
pub fn ipv4_from_sockaddr(addr: SocketAddr) -> Option<Ipv4Addr> {
    match addr.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

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

/// Extract the peer IP address from a TcpStream.
/// Returns None if peer_addr() fails.
pub fn peer_ip(stream: &TcpStream) -> Option<IpAddr> {
    stream.peer_addr().ok().map(|addr| addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use tokio::net::TcpListener;

    #[test]
    fn test_ipv4_from_sockaddr() {
        let cases = [
            (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 179),
                Some(Ipv4Addr::new(192, 168, 1, 1)),
            ),
            (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Some(Ipv4Addr::LOCALHOST),
            ),
            (SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 179), None),
        ];
        for (addr, expected) in cases {
            assert_eq!(ipv4_from_sockaddr(addr), expected);
        }
    }

    #[tokio::test]
    async fn test_peer_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_stream, _) = listener.accept().await.unwrap();

        assert_eq!(
            peer_ip(&server_stream),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );

        let client_stream = client.await.unwrap();
        assert_eq!(
            peer_ip(&client_stream),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    }
}
