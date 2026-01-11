use crate::route_generator::PeerRoute;
use crate::{bgp_handshake, create_update_message};
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

    // Use very long hold time (3600s = 1 hour) so we don't need to send KEEPALIVEs during test
    bgp_handshake(&mut stream, local_asn, local_router_id, peer_asn, 3600).await?;

    Ok(SenderConnection {
        stream,
        local_asn,
        next_hop,
    })
}

/// Send routes on an already-established connection
/// Returns the connection so caller can keep it alive
pub async fn send_routes(
    mut conn: SenderConnection,
    routes: Vec<PeerRoute>,
    batch_size: usize,
) -> io::Result<(SenderConnection, SenderStats)> {
    if routes.is_empty() {
        return Ok((
            conn,
            SenderStats {
                routes_sent: 0,
                duration: Duration::from_secs(0),
                start_time: Instant::now(),
                end_time: Instant::now(),
            },
        ));
    }

    // Pre-serialize all UPDATE messages
    let mut update_messages = Vec::new();
    for chunk in routes.chunks(batch_size) {
        let prefixes: Vec<_> = chunk.iter().map(|r| r.prefix).collect();

        // Use attributes from first route in chunk (all should be similar in chunk)
        let first = &chunk[0];
        let msg = create_update_message(
            prefixes,
            conn.next_hop,
            first.as_path.clone(),
            first.origin,
            first.med,
            None, // local_pref
            first.communities.clone(),
        );
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

    Ok((conn, stats))
}
