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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::{TcpSocket, TcpStream};

/// BGP protocol port number
pub const BGP_PORT: u16 = 179;

/// Extract IPv4 address from a SocketAddr, returns None for IPv6.
pub fn ipv4_from_sockaddr(addr: SocketAddr) -> Option<Ipv4Addr> {
    match addr.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

/// Extract IPv6 address from a SocketAddr, returns None for IPv4.
pub fn ipv6_from_sockaddr(addr: SocketAddr) -> Option<Ipv6Addr> {
    match addr.ip() {
        IpAddr::V6(ip) => Some(ip),
        IpAddr::V4(_) => None,
    }
}

/// Extract IPv4 from IpAddr, returns error for IPv6.
pub fn ipv4_from_ipaddr(addr: IpAddr) -> Result<Ipv4Addr, &'static str> {
    match addr {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err("IPv6 not supported"),
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

/// Extract the local IP address from a TcpStream.
/// Returns None if local_addr() fails.
pub fn local_ip(stream: &TcpStream) -> Option<IpAddr> {
    stream.local_addr().ok().map(|addr| addr.ip())
}

/// Create SocketAddr for binding with port 0 for automatic port selection.
pub fn bind_addr_from_ip(ip: impl Into<IpAddr>) -> SocketAddr {
    SocketAddr::new(ip.into(), 0)
}

/// Parse address string into SocketAddr with optional default port.
/// Accepts formats: "IP:PORT" or "IP" (uses default_port).
pub fn parse_sockaddr(addr: &str, default_port: u16) -> Result<SocketAddr, String> {
    addr.parse()
        .or_else(|_| format!("{}:{}", addr, default_port).parse())
        .map_err(|e| format!("invalid address: {}", e))
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

    #[test]
    fn test_ipv6_from_sockaddr() {
        let cases = [
            (
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 179),
                Some(Ipv6Addr::LOCALHOST),
            ),
            (
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    0,
                ),
                Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ),
            (SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 179), None),
        ];
        for (addr, expected) in cases {
            assert_eq!(ipv6_from_sockaddr(addr), expected);
        }
    }

    #[test]
    fn test_ipv4_from_ipaddr() {
        let cases = [
            (
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                Ok(Ipv4Addr::new(192, 168, 1, 1)),
            ),
            (IpAddr::V4(Ipv4Addr::LOCALHOST), Ok(Ipv4Addr::LOCALHOST)),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), Err("IPv6 not supported")),
        ];
        for (addr, expected) in cases {
            assert_eq!(ipv4_from_ipaddr(addr), expected);
        }
    }

    #[test]
    fn test_bind_addr_from_ip() {
        let cases = [
            (
                Ipv4Addr::LOCALHOST,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            ),
            (
                Ipv4Addr::new(10, 0, 0, 1),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 0),
            ),
        ];
        for (ip, expected) in cases {
            assert_eq!(bind_addr_from_ip(ip), expected);
        }
    }

    #[test]
    fn test_parse_sockaddr() {
        let cases = [
            (
                "127.0.0.1:179",
                179,
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 179)),
            ),
            (
                "127.0.0.1",
                179,
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 179)),
            ),
            (
                "10.0.0.1:8080",
                179,
                Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    8080,
                )),
            ),
            (
                "10.0.0.1",
                8080,
                Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    8080,
                )),
            ),
        ];
        for (addr, default_port, expected) in cases {
            assert_eq!(parse_sockaddr(addr, default_port), expected);
        }

        assert!(parse_sockaddr("invalid", 179).is_err());
        assert!(parse_sockaddr("999.999.999.999", 179).is_err());
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

    #[tokio::test]
    async fn test_local_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_stream, _) = listener.accept().await.unwrap();

        assert_eq!(
            local_ip(&server_stream),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );

        let client_stream = client.await.unwrap();
        assert_eq!(
            local_ip(&client_stream),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    }
}
