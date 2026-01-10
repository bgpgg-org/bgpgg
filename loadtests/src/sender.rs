use crate::{bgp_handshake, create_update_message};
use bgpgg::bgp::utils::IpNetwork;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct SenderConnection {
    pub stream: TcpStream,
    pub local_asn: u16,
    pub next_hop: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub struct SenderStats {
    pub routes_sent: usize,
    pub duration: Duration,
    pub start_time: Instant,
    pub end_time: Instant,
}

/// Run a lightweight BGP sender that blasts UPDATE messages
pub async fn run_sender(
    target_addr: SocketAddr,
    local_asn: u16,
    local_router_id: Ipv4Addr,
    peer_asn: u16,
    routes: Vec<IpNetwork>,
    next_hop: Ipv4Addr,
    batch_size: usize,
) -> io::Result<SenderStats> {
    // Connect to bgpgg
    let mut stream = TcpStream::connect(target_addr).await?;

    // Perform BGP handshake
    bgp_handshake(&mut stream, local_asn, local_router_id, peer_asn, 180).await?;

    // Return early if no routes to send (just establishing connection)
    if routes.is_empty() {
        return Ok(SenderStats {
            routes_sent: 0,
            duration: Duration::from_secs(0),
            start_time: Instant::now(),
            end_time: Instant::now(),
        });
    }

    // Pre-serialize all UPDATE messages
    let mut update_messages = Vec::new();
    for chunk in routes.chunks(batch_size) {
        let msg = create_update_message(chunk.to_vec(), next_hop, vec![local_asn]);
        update_messages.push(msg);
    }

    // Start timer and blast all UPDATEs
    let start_time = Instant::now();

    for msg in &update_messages {
        stream.write_all(msg).await?;
    }

    // Flush to ensure all data is sent
    stream.flush().await?;

    let end_time = Instant::now();

    Ok(SenderStats {
        routes_sent: routes.len(),
        duration: end_time - start_time,
        start_time,
        end_time,
    })
}

/// Establish BGP connection without sending routes
pub async fn establish_connection(
    target_addr: SocketAddr,
    local_asn: u16,
    local_router_id: Ipv4Addr,
    peer_asn: u16,
    next_hop: Ipv4Addr,
    bind_addr: Option<SocketAddr>,
) -> io::Result<SenderConnection> {
    use tokio::net::TcpSocket;

    let mut stream = if let Some(bind) = bind_addr {
        // Bind to specific local address
        let socket = if bind.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.bind(bind)?;
        socket.connect(target_addr).await?
    } else {
        TcpStream::connect(target_addr).await?
    };

    bgp_handshake(&mut stream, local_asn, local_router_id, peer_asn, 180).await?;

    Ok(SenderConnection {
        stream,
        local_asn,
        next_hop,
    })
}

/// Send routes on an already-established connection
/// Spawns a background task to keep the connection alive and drain incoming messages
pub async fn send_routes(
    mut conn: SenderConnection,
    routes: Vec<IpNetwork>,
    batch_size: usize,
) -> io::Result<SenderStats> {
    if routes.is_empty() {
        return Ok(SenderStats {
            routes_sent: 0,
            duration: Duration::from_secs(0),
            start_time: Instant::now(),
            end_time: Instant::now(),
        });
    }

    // Pre-serialize all UPDATE messages
    let mut update_messages = Vec::new();
    for chunk in routes.chunks(batch_size) {
        let msg = create_update_message(chunk.to_vec(), conn.next_hop, vec![conn.local_asn]);
        update_messages.push(msg);
    }

    // Start timer and blast all UPDATEs
    let start_time = Instant::now();

    for msg in &update_messages {
        conn.stream.write_all(msg).await?;
    }

    conn.stream.flush().await?;

    let end_time = Instant::now();

    let stats = SenderStats {
        routes_sent: routes.len(),
        duration: end_time - start_time,
        start_time,
        end_time,
    };

    // Spawn a task to keep draining incoming BGP messages (bgpgg sends UPDATEs back)
    // This prevents the TCP receive buffer from filling up and keeps the connection alive
    tokio::spawn(async move {
        use std::time::Duration;
        loop {
            // Read BGP messages properly to maintain framing
            match bgpgg::bgp::msg::read_bgp_message(&mut conn.stream).await {
                Ok(_msg) => {
                    // Successfully read a message, continue immediately
                }
                Err(_) => {
                    // Error reading - sleep briefly to avoid tight error loop
                    // This could be a transient error or connection close
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
    });

    Ok(stats)
}
