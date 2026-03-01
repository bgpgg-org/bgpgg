// Copyright 2026 bgpgg Authors
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
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::ptr::addr_of_mut;

/// struct tcp_md5sig (linux/tcp.h)
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
pub fn apply_tcp_md5(fd: RawFd, peer_addr: IpAddr, key: &[u8]) -> io::Result<()> {
    apply_tcp_md5_impl(fd, peer_addr, key, do_setsockopt)
}

fn do_setsockopt(fd: RawFd, sig: &TcpMd5sig) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            sig as *const _ as *const libc::c_void,
            mem::size_of_val(sig) as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn apply_tcp_md5_impl(
    fd: RawFd,
    peer_addr: IpAddr,
    key: &[u8],
    mut apply_fn: impl FnMut(RawFd, &TcpMd5sig) -> io::Result<()>,
) -> io::Result<()> {
    if key.len() > libc::TCP_MD5SIG_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MD5 key too long (max 80 bytes)",
        ));
    }
    let sig = tcp_md5sig(peer_addr, key);
    apply_fn(fd, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpSocket;

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

    // Verifies the sig is constructed correctly and passed to setsockopt, without
    // requiring CAP_NET_ADMIN. The closure captures what apply_tcp_md5_impl hands off.
    #[test]
    fn test_apply_tcp_md5_v4() {
        use std::ptr::addr_of;

        let socket = TcpSocket::new_v4().unwrap();
        let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
        let key = b"test-bgp-md5-key";

        let mut captured_family = 0u16;
        let mut captured_keylen = 0u16;
        let result = apply_tcp_md5_impl(socket.as_raw_fd(), peer_addr, key, |_fd, sig| {
            unsafe {
                let sa = addr_of!(sig.peer_addr) as *const libc::sockaddr_in;
                captured_family = (*sa).sin_family;
            }
            captured_keylen = sig.keylen;
            Ok(())
        });

        assert!(result.is_ok());
        assert_eq!(captured_family, libc::AF_INET as u16);
        assert_eq!(captured_keylen, key.len() as u16);
    }

    #[test]
    fn test_apply_tcp_md5_key_too_long() {
        let socket = TcpSocket::new_v4().unwrap();
        let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
        let key = vec![0u8; 81]; // exceeds TCP_MD5SIG_MAXKEYLEN
        let result = apply_tcp_md5_impl(socket.as_raw_fd(), peer_addr, &key, |_, _| Ok(()));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
}
