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

#[cfg(target_os = "linux")]
use std::mem;
#[cfg(target_os = "linux")]
use std::ptr::addr_of_mut;
#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, RawFd};

/// BGP protocol port number
pub const BGP_PORT: u16 = 179;

/// IP network prefix (IPv4 or IPv6)
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum IpNetwork {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

impl IpNetwork {
    /// Get the prefix length of this network
    pub fn prefix_len(&self) -> u8 {
        match self {
            IpNetwork::V4(net) => net.prefix_length,
            IpNetwork::V6(net) => net.prefix_length,
        }
    }

    /// Check if another prefix is contained within this network
    pub fn contains(&self, other: &IpNetwork) -> bool {
        match (self, other) {
            (IpNetwork::V4(net), IpNetwork::V4(p)) => {
                let net_addr = u32::from_be_bytes(net.address.octets());
                let p_addr = u32::from_be_bytes(p.address.octets());
                let mask = !0u32 << (32 - net.prefix_length);
                (net_addr & mask) == (p_addr & mask)
            }
            (IpNetwork::V6(net), IpNetwork::V6(p)) => {
                let net_addr = u128::from_be_bytes(net.address.octets());
                let p_addr = u128::from_be_bytes(p.address.octets());
                let mask = !0u128 << (128 - net.prefix_length);
                (net_addr & mask) == (p_addr & mask)
            }
            _ => false, // IPv4 vs IPv6 mismatch
        }
    }

    /// Get the AFI/SAFI for this network (assumes Unicast)
    pub fn afi_safi(&self) -> crate::bgp::multiprotocol::AfiSafi {
        use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
        match self {
            IpNetwork::V4(_) => AfiSafi::new(Afi::Ipv4, Safi::Unicast),
            IpNetwork::V6(_) => AfiSafi::new(Afi::Ipv6, Safi::Unicast),
        }
    }
}

impl std::fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpNetwork::V4(net) => write!(f, "{}/{}", net.address, net.prefix_length),
            IpNetwork::V6(net) => write!(f, "{}/{}", net.address, net.prefix_length),
        }
    }
}

/// IPv4 network prefix
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Ipv4Net {
    pub address: Ipv4Addr,
    pub prefix_length: u8,
}

impl Ipv4Net {
    /// Returns true if this is a multicast prefix (224.0.0.0/4).
    pub fn is_multicast(&self) -> bool {
        self.address.octets()[0] >= 224 && self.address.octets()[0] <= 239
    }
}

/// IPv6 network prefix
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Ipv6Net {
    pub address: Ipv6Addr,
    pub prefix_length: u8,
}

/// Parse CIDR notation string into IpNetwork
impl std::str::FromStr for IpNetwork {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(format!(
                "invalid CIDR format '{}' (expected address/length)",
                s
            ));
        }

        let addr = parts[0];
        let prefix_len = parts[1]
            .parse::<u8>()
            .map_err(|_| format!("invalid prefix length '{}'", parts[1]))?;

        // Try IPv4 first
        if let Ok(ipv4_addr) = addr.parse::<Ipv4Addr>() {
            if prefix_len > 32 {
                return Err(format!("IPv4 prefix length {} exceeds 32", prefix_len));
            }
            return Ok(IpNetwork::V4(Ipv4Net {
                address: ipv4_addr,
                prefix_length: prefix_len,
            }));
        }

        // Try IPv6
        if let Ok(ipv6_addr) = addr.parse::<Ipv6Addr>() {
            if prefix_len > 128 {
                return Err(format!("IPv6 prefix length {} exceeds 128", prefix_len));
            }
            return Ok(IpNetwork::V6(Ipv6Net {
                address: ipv6_addr,
                prefix_length: prefix_len,
            }));
        }

        Err(format!("invalid IP address '{}'", addr))
    }
}

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

/// struct tcp_md5sig (linux/tcp.h)
#[cfg(target_os = "linux")]
#[repr(C)]
struct TcpMd5sig {
    peer_addr: libc::sockaddr_storage,     // tcpm_addr
    flags: u8,                             // tcpm_flags: 0 for basic use
    prefixlen: u8,                         // tcpm_prefixlen: 0 = exact IP match
    keylen: u16,                           // tcpm_keylen
    ifindex: i32,                          // tcpm_ifindex: 0 = any interface
    key: [u8; libc::TCP_MD5SIG_MAXKEYLEN], // tcpm_key
}

// Builds a TcpMd5sig to pass to setsockopt(TCP_MD5SIG). The struct layout
// mirrors linux/tcp.h and is interpreted directly by the kernel.
#[cfg(target_os = "linux")]
fn tcp_md5sig(peer_addr: IpAddr, key: &[u8]) -> TcpMd5sig {
    let mut sig: TcpMd5sig = unsafe { mem::zeroed() };
    sig.keylen = key.len() as u16;
    sig.key[..key.len()].copy_from_slice(key);

    match peer_addr {
        // sin_port is left zero; the kernel matches MD5 keys by IP address only.
        IpAddr::V4(v4) => unsafe {
            let sa = addr_of_mut!(sig.peer_addr) as *mut libc::sockaddr_in;
            (*sa).sin_family = libc::AF_INET as u16;
            // octets() is already in network byte order; from_ne_bytes copies
            // the bytes as-is into s_addr without reordering.
            (*sa).sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
        },
        IpAddr::V6(v6) => unsafe {
            let sa = addr_of_mut!(sig.peer_addr) as *mut libc::sockaddr_in6;
            (*sa).sin6_family = libc::AF_INET6 as u16;
            (*sa).sin6_addr.s6_addr = v6.octets();
        },
    }

    sig
}

/// Set TCP MD5 signature key on a socket for the given peer address (RFC 2385).
#[cfg(target_os = "linux")]
pub fn apply_tcp_md5(fd: RawFd, peer_addr: IpAddr, key: &[u8]) -> io::Result<()> {
    if key.len() > libc::TCP_MD5SIG_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MD5 key too long (max 80 bytes)",
        ));
    }

    let sig = tcp_md5sig(peer_addr, key);

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            &sig as *const _ as *const libc::c_void,
            mem::size_of_val(&sig) as libc::socklen_t,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
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
/// * `md5_key` - Optional TCP MD5 key bytes (RFC 2385, Linux only)
///
/// # Returns
/// `TcpStream` on success, or an `io::Error` on failure
pub async fn create_and_bind_tcp_socket(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    md5_key: Option<&[u8]>,
) -> io::Result<TcpStream> {
    // Create appropriate socket based on remote address type
    let socket = if remote_addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    // Bind to local address
    socket.bind(local_addr)?;

    // Apply TCP MD5 key before connect (Linux only)
    #[cfg(target_os = "linux")]
    if let Some(key) = md5_key {
        apply_tcp_md5(socket.as_raw_fd(), remote_addr.ip(), key)?;
    }

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

/// Helper to create IPv4 IpAddr for tests
#[cfg(test)]
pub(crate) const fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use tokio::net::TcpListener;
    #[cfg(target_os = "linux")]
    use tokio::net::TcpSocket;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_tcp_md5sig() {
        use std::ptr::addr_of;
        let key = b"secret";
        let cases: &[(IpAddr, u16, u32)] = &[
            // (addr, expected AF, expected s_addr)
            (
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                libc::AF_INET as u16,
                u32::from_ne_bytes([10, 0, 0, 1]),
            ),
            (
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                libc::AF_INET as u16,
                u32::from_ne_bytes([192, 168, 1, 1]),
            ),
        ];
        for (addr, expected_family, expected_s_addr) in cases {
            let sig = tcp_md5sig(*addr, key);
            assert_eq!(sig.keylen, key.len() as u16);
            assert_eq!(&sig.key[..key.len()], key.as_ref());
            unsafe {
                let sa = addr_of!(sig.peer_addr) as *const libc::sockaddr_in;
                assert_eq!((*sa).sin_family, *expected_family);
                assert_eq!((*sa).sin_addr.s_addr, *expected_s_addr);
            }
        }
    }

    /// Test that apply_tcp_md5 succeeds on a real socket.
    /// Requires CAP_NET_ADMIN on some kernel configurations; marked ignore by default.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "may require CAP_NET_ADMIN"]
    async fn test_apply_tcp_md5_v4() {
        let socket = TcpSocket::new_v4().unwrap();
        let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
        let key = b"test-bgp-md5-key";
        let result = apply_tcp_md5(socket.as_raw_fd(), peer_addr, key);
        assert!(result.is_ok(), "apply_tcp_md5 failed: {:?}", result.err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_apply_tcp_md5_key_too_long() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let socket = TcpSocket::new_v4().unwrap();
            let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
            let key = vec![0u8; 81]; // exceeds TCP_MD5SIG_MAXKEYLEN
            let result = apply_tcp_md5(socket.as_raw_fd(), peer_addr, &key);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn test_ipv4_from_sockaddr() {
        let cases = [
            (
                SocketAddr::new(ipv4(192, 168, 1, 1), 179),
                Some(Ipv4Addr::new(192, 168, 1, 1)),
            ),
            (
                SocketAddr::new(ipv4(127, 0, 0, 1), 0),
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
            (SocketAddr::new(ipv4(127, 0, 0, 1), 179), None),
        ];
        for (addr, expected) in cases {
            assert_eq!(ipv6_from_sockaddr(addr), expected);
        }
    }

    #[test]
    fn test_bind_addr_from_ip() {
        let cases = [
            (Ipv4Addr::LOCALHOST, SocketAddr::new(ipv4(127, 0, 0, 1), 0)),
            (
                Ipv4Addr::new(10, 0, 0, 1),
                SocketAddr::new(ipv4(10, 0, 0, 1), 0),
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
                Ok(SocketAddr::new(ipv4(127, 0, 0, 1), 179)),
            ),
            (
                "127.0.0.1",
                179,
                Ok(SocketAddr::new(ipv4(127, 0, 0, 1), 179)),
            ),
            (
                "10.0.0.1:8080",
                179,
                Ok(SocketAddr::new(ipv4(10, 0, 0, 1), 8080)),
            ),
            (
                "10.0.0.1",
                8080,
                Ok(SocketAddr::new(ipv4(10, 0, 0, 1), 8080)),
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

        assert_eq!(peer_ip(&server_stream), Some(ipv4(127, 0, 0, 1)));

        let client_stream = client.await.unwrap();
        assert_eq!(peer_ip(&client_stream), Some(ipv4(127, 0, 0, 1)));
    }

    #[tokio::test]
    async fn test_local_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_stream, _) = listener.accept().await.unwrap();

        assert_eq!(local_ip(&server_stream), Some(ipv4(127, 0, 0, 1)));

        let client_stream = client.await.unwrap();
        assert_eq!(local_ip(&client_stream), Some(ipv4(127, 0, 0, 1)));
    }

    #[test]
    fn test_ipv4net_is_multicast() {
        let multicast = Ipv4Net {
            address: Ipv4Addr::new(224, 0, 0, 1),
            prefix_length: 24,
        };
        assert!(multicast.is_multicast());

        let unicast = Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        };
        assert!(!unicast.is_multicast());
    }

    #[test]
    fn test_ipnetwork_from_str() {
        use std::str::FromStr;

        // Valid IPv4
        assert_eq!(
            IpNetwork::from_str("10.0.0.0/24").unwrap(),
            IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 0, 0),
                prefix_length: 24,
            })
        );

        // Valid IPv6
        assert_eq!(
            IpNetwork::from_str("2001:db8::/32").unwrap(),
            IpNetwork::V6(Ipv6Net {
                address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                prefix_length: 32,
            })
        );

        // Invalid format
        assert!(IpNetwork::from_str("10.0.0.0").is_err());
        assert!(IpNetwork::from_str("10.0.0.0/24/32").is_err());

        // Invalid prefix length
        assert!(IpNetwork::from_str("10.0.0.0/33").is_err());
        assert!(IpNetwork::from_str("2001:db8::/129").is_err());

        // Invalid IP
        assert!(IpNetwork::from_str("999.999.999.999/24").is_err());
    }

    #[test]
    fn test_ipnetwork_contains() {
        let net = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 8,
        });

        let contained = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 1, 2, 0),
            prefix_length: 24,
        });

        let not_contained = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(192, 168, 1, 0),
            prefix_length: 24,
        });

        assert!(net.contains(&contained));
        assert!(!net.contains(&not_contained));

        // IPv4 vs IPv6 mismatch
        let ipv6_net = IpNetwork::V6(Ipv6Net {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            prefix_length: 32,
        });
        assert!(!net.contains(&ipv6_net));
    }

    #[test]
    fn test_ipnetwork_prefix_len() {
        let v4 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        });
        assert_eq!(v4.prefix_len(), 24);

        let v6 = IpNetwork::V6(Ipv6Net {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            prefix_length: 48,
        });
        assert_eq!(v6.prefix_len(), 48);
    }
}
