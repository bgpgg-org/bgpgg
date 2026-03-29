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

use bgpgg::net::IpNetwork;
use bgpgg::rpki::rtr::{
    CacheResponse, EndOfData, Ipv4Prefix, Ipv6Prefix, Message, ParseError, Serial,
};
use bgpgg::rpki::vrp::Vrp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// FakeCache: test helper that speaks RTR protocol (RFC 8210).
/// Listens on TCP, accepts CacheSession connections, sends VRPs.
pub struct FakeCache {
    listener: TcpListener,
    stream: Option<TcpStream>,
    session_id: u16,
    serial: u32,
}

impl FakeCache {
    /// Bind to a random port and start listening.
    pub async fn listen() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        FakeCache {
            listener,
            stream: None,
            session_id: 1,
            serial: 0,
        }
    }

    /// Returns the address this cache is listening on (for config).
    pub fn address(&self) -> String {
        self.listener.local_addr().unwrap().to_string()
    }

    /// Accept a CacheSession connection.
    pub async fn accept(&mut self) {
        let (stream, _) = self.listener.accept().await.unwrap();
        self.stream = Some(stream);
    }

    /// Read the next RTR message from the connected CacheSession.
    pub async fn read_message(&mut self) -> Message {
        let stream = self.stream.as_mut().unwrap();
        let mut buf = vec![0u8; 4096];
        let mut filled = 0;
        loop {
            let n = stream.read(&mut buf[filled..]).await.unwrap();
            assert!(n > 0, "FakeCache: connection closed while reading");
            filled += n;
            match Message::from_bytes(&buf[..filled]) {
                Ok((msg, _)) => return msg,
                Err(ParseError::TooShort { .. }) => continue,
                Err(err) => panic!("FakeCache: parse error: {:?}", err),
            }
        }
    }

    /// Read and expect a Reset Query from the CacheSession.
    pub async fn read_reset_query(&mut self) {
        let msg = self.read_message().await;
        assert!(
            matches!(msg, Message::ResetQuery(_)),
            "expected ResetQuery, got {:?}",
            msg
        );
    }

    /// Send VRPs as a complete sync: Cache Response + prefix PDUs + End of Data.
    pub async fn send_vrps(&mut self, vrps: &[Vrp]) {
        let stream = self.stream.as_mut().unwrap();

        let cache_response = Message::CacheResponse(CacheResponse {
            session_id: self.session_id,
        });
        stream.write_all(&cache_response.serialize()).await.unwrap();

        for vrp in vrps {
            let msg = match vrp.prefix {
                IpNetwork::V4(v4) => Message::Ipv4Prefix(Ipv4Prefix {
                    flags: 1, // announce
                    prefix_length: v4.prefix_length,
                    max_length: vrp.max_length,
                    prefix: v4.address,
                    asn: vrp.origin_as,
                }),
                IpNetwork::V6(v6) => Message::Ipv6Prefix(Ipv6Prefix {
                    flags: 1,
                    prefix_length: v6.prefix_length,
                    max_length: vrp.max_length,
                    prefix: v6.address,
                    asn: vrp.origin_as,
                }),
            };
            stream.write_all(&msg.serialize()).await.unwrap();
        }

        self.serial += 1;
        let end_of_data = Message::EndOfData(EndOfData {
            session_id: self.session_id,
            serial: Serial(self.serial),
            refresh_interval: 3600,
            retry_interval: 600,
            expire_interval: 7200,
        });
        stream.write_all(&end_of_data.serialize()).await.unwrap();
    }
}
