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
use russh::keys::ssh_key::{self, rand_core::OsRng};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId, ChannelStream};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Core RTR cache protocol logic, generic over the stream type.
/// Both TCP and SSH fake caches wrap this to avoid duplicating RTR protocol code.
pub struct FakeCache<S> {
    stream: Option<S>,
    session_id: u16,
    serial: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> FakeCache<S> {
    fn new() -> Self {
        FakeCache {
            stream: None,
            session_id: 1,
            serial: 0,
        }
    }

    fn set_stream(&mut self, stream: S) {
        self.stream = Some(stream);
    }

    /// Read the next RTR message from the connected CacheSession.
    pub async fn read_message(&mut self) -> Message {
        let stream = self.stream.as_mut().expect("not connected");
        let mut buf = vec![0u8; 4096];
        let mut filled = 0;
        loop {
            let n = stream.read(&mut buf[filled..]).await.unwrap();
            assert!(n > 0, "FakeCache: connection closed while reading");
            filled += n;
            match Message::from_bytes(&buf[..filled]) {
                Ok((msg, _)) => return msg,
                Err(ParseError::TooShort { .. }) => continue,
                Err(err) => panic!("FakeCache: parse error: {err:?}"),
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
        let stream = self.stream.as_mut().expect("not connected");

        let cache_response = Message::CacheResponse(CacheResponse {
            session_id: self.session_id,
        });
        stream.write_all(&cache_response.serialize()).await.unwrap();

        for vrp in vrps {
            let msg = match vrp.prefix {
                IpNetwork::V4(v4) => Message::Ipv4Prefix(Ipv4Prefix {
                    flags: 1,
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

/// FakeTcpCache: speaks RTR over a plain TCP connection.
pub struct FakeTcpCache {
    listener: TcpListener,
    pub cache: FakeCache<TcpStream>,
}

impl FakeTcpCache {
    pub async fn listen() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        FakeTcpCache {
            listener,
            cache: FakeCache::new(),
        }
    }

    pub fn address(&self) -> String {
        self.listener.local_addr().unwrap().to_string()
    }

    pub async fn accept(&mut self) {
        let (stream, _) = self.listener.accept().await.unwrap();
        self.cache.set_stream(stream);
    }

    pub async fn read_message(&mut self) -> Message {
        self.cache.read_message().await
    }

    pub async fn read_reset_query(&mut self) {
        self.cache.read_reset_query().await;
    }

    pub async fn send_vrps(&mut self, vrps: &[Vrp]) {
        self.cache.send_vrps(vrps).await;
    }
}

/// FakeSshCache: speaks RTR over SSH using the rpki-rtr subsystem.
pub struct FakeSshCache {
    address: String,
    client_key_path: String,
    pub cache: FakeCache<ChannelStream<Msg>>,
    channel_rx: tokio::sync::mpsc::Receiver<Channel<Msg>>,
}

impl FakeSshCache {
    pub async fn listen() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();

        let server_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let client_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();

        let client_key_path = format!("/tmp/bgpgg_test_ssh_key_{}", std::process::id());
        let key_pem = client_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        std::fs::write(&client_key_path, key_pem.as_bytes()).unwrap();

        let mut config = russh::server::Config::default();
        config.keys.push(server_key);
        config.auth_rejection_time = std::time::Duration::ZERO;
        config.inactivity_timeout = None;
        let config = Arc::new(config);

        let (channel_tx, channel_rx) = tokio::sync::mpsc::channel(1);

        tokio::spawn(async move {
            loop {
                let (socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let config = config.clone();
                let channel_tx = channel_tx.clone();
                tokio::spawn(async move {
                    let handler = FakeSshHandler {
                        channels: Arc::new(Mutex::new(HashMap::new())),
                        channel_tx,
                    };
                    let _ = russh::server::run_stream(config, socket, handler).await;
                });
            }
        });

        FakeSshCache {
            address,
            client_key_path,
            cache: FakeCache::new(),
            channel_rx,
        }
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn client_key_path(&self) -> &str {
        &self.client_key_path
    }

    pub async fn accept(&mut self) {
        let channel = self.channel_rx.recv().await.unwrap();
        self.cache.set_stream(channel.into_stream());
    }

    pub async fn read_message(&mut self) -> Message {
        self.cache.read_message().await
    }

    pub async fn read_reset_query(&mut self) {
        self.cache.read_reset_query().await;
    }

    pub async fn send_vrps(&mut self, vrps: &[Vrp]) {
        self.cache.send_vrps(vrps).await;
    }
}

impl Drop for FakeSshCache {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.client_key_path);
    }
}

/// SSH server handler for FakeSshCache tests.
struct FakeSshHandler {
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    channel_tx: tokio::sync::mpsc::Sender<Channel<Msg>>,
}

impl russh::server::Server for FakeSshHandler {
    type Handler = Self;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        FakeSshHandler {
            channels: self.channels.clone(),
            channel_tx: self.channel_tx.clone(),
        }
    }
}

impl russh::server::Handler for FakeSshHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let mut channels = self.channels.lock().await;
        channels.insert(channel.id(), channel);
        Ok(true)
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "rpki-rtr" {
            let mut channels = self.channels.lock().await;
            if let Some(channel) = channels.remove(&channel_id) {
                session.channel_success(channel_id)?;
                let _ = self.channel_tx.send(channel).await;
            }
        } else {
            session.channel_failure(channel_id)?;
        }
        Ok(())
    }
}
