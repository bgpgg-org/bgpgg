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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;

// Constants from <sys/net/pfkeyv2.h> and <sys/netipsec/ipsec.h>
const PF_KEY_V2: libc::c_int = 2;
// FreeBSD requires SPI=0x1000 for TCP-MD5 (per tcp(4) man page).
const TCP_SIG_SPI: u32 = 0x1000;
const SADB_ADD: u8 = 3;
const SADB_DELETE: u8 = 4;
const SADB_X_SATYPE_TCPSIGNATURE: u8 = 11;
const SADB_EXT_SA: u16 = 1;
const SADB_EXT_KEY_AUTH: u16 = 8;
const SADB_EXT_ADDRESS_SRC: u16 = 5;
const SADB_EXT_ADDRESS_DST: u16 = 6;
const SADB_X_EXT_SA2: u16 = 19;
const SADB_X_AALG_TCP_MD5: u8 = 252;
const SADB_EALG_NONE: u8 = 0;
const SADB_X_EXT_CYCSEQ: u32 = 0x0020;
const IPSEC_MODE_ANY: u8 = 0;
const IPSEC_ULPROTO_ANY: u8 = 255;
const TCP_MD5_MAXKEYLEN: usize = 80;

// SADB message header (sys/net/pfkeyv2.h: sadb_msg). All len fields are in 64-bit units.
#[repr(C)]
struct SadbMsg {
    version: u8,
    msg_type: u8,
    errno: u8,
    satype: u8,
    len: u16,
    reserved: u16,
    seq: u32,
    pid: u32,
}

// SADB authentication/encryption key extension (sys/net/pfkeyv2.h: sadb_key).
// Immediately followed by key bytes, padded to 8 bytes.
#[repr(C)]
struct SadbKey {
    len: u16,
    exttype: u16,
    bits: u16,
    reserved: u16,
}

// SADB security association extension (sys/net/pfkeyv2.h: sadb_sa).
#[repr(C)]
struct SadbSa {
    len: u16,
    exttype: u16,
    spi: u32,
    replay: u8,
    state: u8,
    auth: u8,
    encrypt: u8,
    flags: u32,
}

// SADB extended SA2 extension (sys/net/pfkeyv2.h: sadb_x_sa2).
#[repr(C)]
struct SadbXSa2 {
    len: u16,
    exttype: u16,
    mode: u8,
    reserved1: u8,
    reserved2: u16,
    sequence: u32,
    reqid: u32,
}

// SADB address extension (sys/net/pfkeyv2.h: sadb_address).
// Immediately followed by a sockaddr, padded to 8 bytes.
#[repr(C)]
struct SadbAddress {
    len: u16,
    exttype: u16,
    proto: u8,
    prefixlen: u8,
    reserved: u16,
}

// Round up to 8-byte alignment (SADB extension boundary requirement)
fn pfkey_align8(n: usize) -> usize {
    (n + 7) & !7
}

// Convert byte length to SADB 64-bit units
fn pfkey_unit64(n: usize) -> u16 {
    (n / 8) as u16
}

// Write value into byte slice at position using pointer cast
unsafe fn write_at<T: Sized>(buf: &mut [u8], pos: usize, val: T) {
    let ptr = buf[pos..].as_mut_ptr() as *mut T;
    ptr.write_unaligned(val);
}

// Encode a sockaddr_in or sockaddr_in6 into the buffer at pos.
// Returns the number of bytes written (padded to 8).
unsafe fn write_sockaddr(buf: &mut [u8], pos: usize, addr: IpAddr) -> usize {
    match addr {
        IpAddr::V4(v4) => {
            let sa_size = mem::size_of::<libc::sockaddr_in>();
            let padded = pfkey_align8(sa_size);
            // Zero the region first (ensures padding bytes are zero)
            buf[pos..pos + padded].fill(0);
            let sa = buf[pos..].as_mut_ptr() as *mut libc::sockaddr_in;
            (*sa).sin_len = sa_size as u8;
            (*sa).sin_family = libc::AF_INET as u8;
            (*sa).sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
            padded
        }
        IpAddr::V6(v6) => {
            let sa_size = mem::size_of::<libc::sockaddr_in6>();
            let padded = pfkey_align8(sa_size);
            buf[pos..pos + padded].fill(0);
            let sa = buf[pos..].as_mut_ptr() as *mut libc::sockaddr_in6;
            (*sa).sin6_len = sa_size as u8;
            (*sa).sin6_family = libc::AF_INET6 as u8;
            (*sa).sin6_addr.s6_addr = v6.octets();
            padded
        }
    }
}

// Prefix length for exact match based on address family
fn exact_prefixlen(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

// Build the flat SADB message buffer for a given msg_type, src, dst, and key.
fn build_sadb_buf(msg_type: u8, src: IpAddr, dst: IpAddr, key: &[u8]) -> Vec<u8> {
    // Compute sizes for each SADB extension
    let key_padded = pfkey_align8(mem::size_of::<SadbKey>() + key.len());
    let sa_size = mem::size_of::<SadbSa>();
    let sa_padded = pfkey_align8(sa_size);
    let x_sa2_padded = pfkey_align8(mem::size_of::<SadbXSa2>());

    let src_sa_padded = match src {
        IpAddr::V4(_) => pfkey_align8(mem::size_of::<libc::sockaddr_in>()),
        IpAddr::V6(_) => pfkey_align8(mem::size_of::<libc::sockaddr_in6>()),
    };
    let src_addr_ext_padded = pfkey_align8(mem::size_of::<SadbAddress>()) + src_sa_padded;

    let dst_sa_padded = match dst {
        IpAddr::V4(_) => pfkey_align8(mem::size_of::<libc::sockaddr_in>()),
        IpAddr::V6(_) => pfkey_align8(mem::size_of::<libc::sockaddr_in6>()),
    };
    let dst_addr_ext_padded = pfkey_align8(mem::size_of::<SadbAddress>()) + dst_sa_padded;

    let msg_size = mem::size_of::<SadbMsg>();
    let total = msg_size
        + key_padded
        + sa_padded
        + x_sa2_padded
        + src_addr_ext_padded
        + dst_addr_ext_padded;

    let mut buf = vec![0u8; total];
    let mut pos = 0;

    unsafe {
        // SadbMsg header
        write_at(
            &mut buf,
            pos,
            SadbMsg {
                version: PF_KEY_V2 as u8,
                msg_type,
                errno: 0,
                satype: SADB_X_SATYPE_TCPSIGNATURE,
                len: pfkey_unit64(total),
                reserved: 0,
                seq: 0,
                pid: libc::getpid() as u32,
            },
        );
        pos += msg_size;

        // SadbKey (auth key)
        write_at(
            &mut buf,
            pos,
            SadbKey {
                len: pfkey_unit64(key_padded),
                exttype: SADB_EXT_KEY_AUTH,
                bits: (key.len() * 8) as u16,
                reserved: 0,
            },
        );
        pos += mem::size_of::<SadbKey>();
        buf[pos..pos + key.len()].copy_from_slice(key);
        pos += key_padded - mem::size_of::<SadbKey>();

        // SadbSa
        write_at(
            &mut buf,
            pos,
            SadbSa {
                len: pfkey_unit64(sa_padded),
                exttype: SADB_EXT_SA,
                spi: TCP_SIG_SPI.to_be(),
                replay: 0,
                state: 0,
                auth: SADB_X_AALG_TCP_MD5,
                encrypt: SADB_EALG_NONE,
                flags: SADB_X_EXT_CYCSEQ,
            },
        );
        pos += sa_padded;

        // SadbXSa2
        write_at(
            &mut buf,
            pos,
            SadbXSa2 {
                len: pfkey_unit64(x_sa2_padded),
                exttype: SADB_X_EXT_SA2,
                mode: IPSEC_MODE_ANY,
                reserved1: 0,
                reserved2: 0,
                sequence: 0,
                reqid: 0,
            },
        );
        pos += x_sa2_padded;

        // SadbAddress (src) - wildcard (prefixlen=0)
        let addr_hdr_size = mem::size_of::<SadbAddress>();
        let addr_hdr_padded = pfkey_align8(addr_hdr_size);
        write_at(
            &mut buf,
            pos,
            SadbAddress {
                len: pfkey_unit64(src_addr_ext_padded),
                exttype: SADB_EXT_ADDRESS_SRC,
                proto: IPSEC_ULPROTO_ANY,
                prefixlen: 0, // wildcard local address
                reserved: 0,
            },
        );
        pos += addr_hdr_padded;
        let written = write_sockaddr(&mut buf, pos, src);
        pos += written;

        // SadbAddress (dst) - exact match
        write_at(
            &mut buf,
            pos,
            SadbAddress {
                len: pfkey_unit64(dst_addr_ext_padded),
                exttype: SADB_EXT_ADDRESS_DST,
                proto: IPSEC_ULPROTO_ANY,
                prefixlen: exact_prefixlen(dst),
                reserved: 0,
            },
        );
        pos += addr_hdr_padded;
        write_sockaddr(&mut buf, pos, dst);
    }

    buf
}

// Get local address from a socket using getsockname.
fn get_local_addr(fd: RawFd) -> io::Result<IpAddr> {
    // Try IPv4 first
    let mut addr4: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len4 = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret =
        unsafe { libc::getsockname(fd, &mut addr4 as *mut _ as *mut libc::sockaddr, &mut len4) };
    if ret == 0 && addr4.sin_family == libc::AF_INET as u8 {
        let octets = addr4.sin_addr.s_addr.to_ne_bytes();
        return Ok(IpAddr::V4(Ipv4Addr::from(octets)));
    }

    // Try IPv6
    let mut addr6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    let mut len6 = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let ret =
        unsafe { libc::getsockname(fd, &mut addr6 as *mut _ as *mut libc::sockaddr, &mut len6) };
    if ret == 0 && addr6.sin6_family == libc::AF_INET6 as u8 {
        return Ok(IpAddr::V6(Ipv6Addr::from(addr6.sin6_addr.s6_addr)));
    }

    Err(io::Error::last_os_error())
}

// Send an SADB message via a PF_KEY socket and read the kernel's reply.
fn sadb_send_one(sock: libc::c_int, buf: &[u8]) -> io::Result<()> {
    let ret = unsafe { libc::send(sock, buf.as_ptr() as *const libc::c_void, buf.len(), 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Read kernel reply to check for errors
    let mut reply = [0u8; 512];
    let recv_ret = unsafe {
        libc::recv(
            sock,
            reply.as_mut_ptr() as *mut libc::c_void,
            reply.len(),
            0,
        )
    };

    if recv_ret < mem::size_of::<SadbMsg>() as isize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SADB reply too short",
        ));
    }

    // Check errno field in reply header (byte 2 of SadbMsg)
    let errno = reply[2];
    if errno != 0 {
        return Err(io::Error::from_raw_os_error(errno as i32));
    }

    Ok(())
}

// Add an SA, replacing any existing one (handles EEXIST by retrying after delete).
fn sadb_add(src: IpAddr, dst: IpAddr, key: &[u8]) -> io::Result<()> {
    let sock = unsafe { libc::socket(libc::PF_KEY, libc::SOCK_RAW, PF_KEY_V2) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let add_buf = build_sadb_buf(SADB_ADD, src, dst, key);
    let result = sadb_send_one(sock, &add_buf);

    // If SA already exists (EEXIST), delete it and retry
    if let Err(ref e) = result {
        if e.raw_os_error() == Some(libc::EEXIST) {
            let del_buf = build_sadb_buf(SADB_DELETE, src, dst, key);
            let _ = sadb_send_one(sock, &del_buf);
            let result = sadb_send_one(sock, &add_buf);
            unsafe { libc::close(sock) };
            return result;
        }
    }

    unsafe { libc::close(sock) };
    result
}

/// Set TCP MD5 signature key on a socket for the given peer address (RFC 2385).
///
/// On FreeBSD, keys are registered in the kernel SADB via PF_KEY, then the
/// socket is enabled for TCP MD5 with TCP_MD5SIG setsockopt.
pub fn apply_tcp_md5(fd: RawFd, peer_addr: IpAddr, key: &[u8]) -> io::Result<()> {
    if key.len() > TCP_MD5_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MD5 key too long (max 80 bytes)",
        ));
    }

    // Get local address from the socket (required - FreeBSD doesn't accept 0.0.0.0)
    let local_addr = get_local_addr(fd)?;

    sadb_add(local_addr, peer_addr, key)?;
    sadb_add(peer_addr, local_addr, key)?;

    let enable: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            &enable as *const _ as *const libc::c_void,
            mem::size_of_val(&enable) as libc::socklen_t,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpSocket;

    #[test]
    fn test_pfkey_helpers() {
        assert_eq!(pfkey_align8(0), 0);
        assert_eq!(pfkey_align8(1), 8);
        assert_eq!(pfkey_align8(7), 8);
        assert_eq!(pfkey_align8(8), 8);
        assert_eq!(pfkey_align8(9), 16);

        assert_eq!(pfkey_unit64(8), 1);
        assert_eq!(pfkey_unit64(16), 2);
        assert_eq!(pfkey_unit64(24), 3);
    }

    #[test]
    fn test_apply_tcp_md5_key_too_long() {
        let socket = TcpSocket::new_v4().unwrap();
        let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
        let key = vec![0u8; 81]; // exceeds TCP_MD5_MAXKEYLEN
        let result = apply_tcp_md5(socket.as_raw_fd(), peer_addr, &key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_apply_tcp_md5_v4() {
        let socket = TcpSocket::new_v4().unwrap();
        let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
        let key = b"test-bgp-md5-key";
        let result = apply_tcp_md5(socket.as_raw_fd(), peer_addr, key);
        assert!(result.is_ok(), "apply_tcp_md5 failed: {:?}", result.err());
    }
}
