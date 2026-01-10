use bgpgg::config::Config;
use bgpgg::grpc::proto::bgp_service_client::BgpServiceClient;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tonic::transport::Channel;

type BgpClient = BgpServiceClient<Channel>;

/// Helper to spawn bgpggd binary with a config file
struct BgpggProcess {
    process: Child,
    _config_file: tempfile::NamedTempFile,
    bgp_port: u16,
    grpc_addr: String,
}

impl BgpggProcess {
    async fn spawn(asn: u16, router_id: Ipv4Addr) -> std::io::Result<Self> {
        // Create temporary config file
        use std::io::Write;
        let mut config_file = tempfile::NamedTempFile::new()?;

        // Use port 0 for dynamic BGP port, but fixed gRPC port for easy connection
        let grpc_port = 50051 + (asn - 65000); // Offset by ASN to avoid conflicts
        let grpc_addr = format!("127.0.0.1:{}", grpc_port);

        let config = Config {
            asn,
            listen_addr: "127.0.0.1:0".to_string(),
            router_id,
            grpc_listen_addr: grpc_addr.clone(),
            hold_time_secs: 180,
            connect_retry_secs: 30,
            accept_unconfigured_peers: true,
            peers: vec![],
            bmp_servers: vec![],
            sys_name: None,
            sys_descr: None,
        };

        let yaml = serde_yaml::to_string(&config).unwrap();
        config_file.write_all(yaml.as_bytes())?;
        config_file.flush()?;

        // Spawn bgpggd binary
        let process = Command::new("../target/debug/bgpggd")
            .arg("--config")
            .arg(config_file.path())
            .spawn()?;

        // Wait a bit for server to start
        sleep(Duration::from_millis(500)).await;

        Ok(Self {
            process,
            _config_file: config_file,
            bgp_port: 0, // Will be populated after connecting
            grpc_addr: format!("http://{}", grpc_addr),
        })
    }

    async fn connect_grpc(&mut self) -> Result<BgpClient, Box<dyn std::error::Error>> {
        // Try to connect to gRPC with retries
        for _ in 0..10 {
            match BgpClient::connect(self.grpc_addr.clone()).await {
                Ok(client) => {
                    // Get server info to find out the BGP port
                    let mut c = client.clone();
                    let info = c
                        .get_server_info(bgpgg::grpc::proto::GetServerInfoRequest {})
                        .await?;
                    self.bgp_port = info.into_inner().listen_port as u16;
                    return Ok(client);
                }
                Err(_) => {
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Err("Failed to connect to gRPC".into())
    }

    fn kill(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Drop for BgpggProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

#[tokio::test]
async fn test_route_ingestion_10_peers_100k_routes() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init()
        .ok();

    // Spawn bgpggd binary
    let mut bgpgg = BgpggProcess::spawn(65000, Ipv4Addr::new(1, 1, 1, 1))
        .await
        .expect("Failed to spawn bgpggd");

    let mut client = bgpgg
        .connect_grpc()
        .await
        .expect("Failed to connect to gRPC");
    let bgp_addr = format!("127.0.0.1:{}", bgpgg.bgp_port);

    tracing::info!("bgpggd listening on BGP port {}", bgpgg.bgp_port);

    // Generate 100,000 test routes
    let all_routes = crate::generate_test_routes(Ipv4Addr::new(10, 0, 0, 0), 100_000, 24);

    // PHASE 1: Establish all peer connections
    tracing::info!("Phase 1: Establishing 10 peer connections...");
    let mut connections = Vec::new();
    let mut route_chunks = Vec::new();

    for (i, chunk) in all_routes.chunks(10_000).enumerate() {
        let target: SocketAddr = bgp_addr.parse().unwrap();
        let sender_asn = 65001 + i as u16;
        let sender_router_id = Ipv4Addr::new(2, 0, 0, 1 + i as u8);

        // Use different loopback IP for each sender (127.0.0.1, 127.0.0.2, etc.)
        // This is necessary because bgpgg identifies peers by source IP address
        let bind_addr: SocketAddr = format!("127.0.0.{}:0", 1 + i).parse().unwrap();

        tracing::info!("Connecting peer {} (AS{}) from {}...", i, sender_asn, bind_addr.ip());

        match crate::sender::establish_connection(
            target,
            sender_asn,
            sender_router_id,
            65000,
            sender_router_id,
            Some(bind_addr),
        )
        .await
        {
            Ok(conn) => {
                tracing::info!("Peer {} connected successfully", i);
                connections.push(conn);
                route_chunks.push(chunk.to_vec());
            }
            Err(e) => {
                tracing::error!("Failed to connect peer {}: {:?}", i, e);
            }
        }
    }

    tracing::info!("{} peers connected", connections.len());

    // PHASE 2: Verify topology
    tracing::info!("Phase 2: Verifying topology...");
    sleep(Duration::from_secs(1)).await;

    let peers_response = client
        .list_peers(bgpgg::grpc::proto::ListPeersRequest {})
        .await
        .unwrap();
    let peers = peers_response.into_inner().peers;
    tracing::info!("bgpgg reports {} peers", peers.len());

    for peer in &peers {
        tracing::info!(
            "  Peer: {} (AS{}, state={:?})",
            peer.address,
            peer.asn,
            peer.state
        );
    }

    assert_eq!(connections.len(), peers.len(), "Peer count mismatch");

    // PHASE 3: Blast routes from all peers in parallel
    tracing::info!(
        "Phase 3: Blasting 100k routes from {} peers...",
        connections.len()
    );

    // Channel to receive results but keep connections alive
    let (result_tx, mut result_rx) = tokio::sync::mpsc::channel(10);
    let start_time = Instant::now();

    for (i, (conn, routes)) in connections.into_iter().zip(route_chunks).enumerate() {
        let tx = result_tx.clone();
        tokio::spawn(async move {
            match crate::sender::send_routes(conn, routes, 100).await {
                Ok(stats) => {
                    let _ = tx.send((i, Ok(stats))).await;
                }
                Err(e) => {
                    let _ = tx.send((i, Err(e))).await;
                }
            }
        });
    }
    drop(result_tx); // Drop original so channel closes after all senders report

    // Collect results
    let mut sender_stats = Vec::new();
    while let Some((i, result)) = result_rx.recv().await {
        match result {
            Ok(stats) => {
                tracing::info!(
                    "Peer {} sent {} routes in {:?} ({:.0} routes/sec)",
                    i,
                    stats.routes_sent,
                    stats.duration,
                    stats.routes_sent as f64 / stats.duration.as_secs_f64()
                );
                sender_stats.push(stats);
            }
            Err(e) => {
                tracing::error!("Peer {} failed to send routes: {:?}", i, e);
            }
        }
    }

    let ingestion_time = Instant::now() - start_time;
    tracing::info!("All peers completed sending in {:?}", ingestion_time);

    // PHASE 4: Wait for bgpgg to process all routes
    tracing::info!("Phase 4: Waiting for bgpgg to process routes...");
    let start = Instant::now();
    let mut success = false;
    let mut last_count = 0;
    while start.elapsed().as_secs() < 60 {
        match client
            .list_routes_stream(bgpgg::grpc::proto::ListRoutesRequest {})
            .await
        {
            Ok(response) => {
                let mut stream = response.into_inner();
                let mut count = 0;
                use tokio_stream::StreamExt;
                while let Some(Ok(_)) = stream.next().await {
                    count += 1;
                }
                tracing::info!("Current route count: {}", count);
                if count == 100_000 {
                    success = true;
                    break;
                }
                if count < last_count {
                    tracing::warn!("Route count decreased from {} to {}", last_count, count);
                } else if count == last_count && last_count > 0 {
                    tracing::warn!("Route count stuck at {}", count);
                }
                last_count = count;
            }
            Err(e) => {
                tracing::warn!("Failed to list routes: {:?}", e);
            }
        }
        sleep(Duration::from_millis(500)).await;
    }

    assert!(success, "Timeout waiting for 100k routes in RIB");

    // Verify per-peer statistics
    let peers_response = client
        .list_peers(bgpgg::grpc::proto::ListPeersRequest {})
        .await
        .unwrap();
    let peers = peers_response.into_inner().peers;
    tracing::info!("Verifying {} peers", peers.len());

    for peer in &peers {
        let peer_response = client
            .get_peer(bgpgg::grpc::proto::GetPeerRequest {
                address: peer.address.clone(),
            })
            .await
            .unwrap();
        let peer_info = peer_response.into_inner();

        if let Some(stats) = peer_info.statistics {
            tracing::info!(
                "Peer {}: received {} UPDATEs",
                peer.address,
                stats.update_received
            );

            assert_eq!(
                stats.update_received, 100,
                "Peer {} should have received 100 UPDATEs",
                peer.address
            );
        }
    }

    // Report final statistics
    let total_routes: usize = sender_stats.iter().map(|s| s.routes_sent).sum();
    let avg_rate = total_routes as f64 / ingestion_time.as_secs_f64();

    tracing::info!("\n=== Ingestion Test Results ===");
    tracing::info!("Total routes sent: {}", total_routes);
    tracing::info!("Send time: {:?}", ingestion_time);
    tracing::info!("Average send rate: {:.0} routes/sec", avg_rate);
    tracing::info!("Peers: {}", sender_stats.len());

    bgpgg.kill();
}
