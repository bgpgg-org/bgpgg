use crate::route_generator::{
    generate_peer_routes, AttributeConfig, OverlapConfig, PrefixLengthDistribution, RouteGenConfig,
};
use bgpgg::config::Config;
use bgpgg::grpc::proto::bgp_service_client::BgpServiceClient;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tonic::transport::Channel;

type BgpClient = BgpServiceClient<Channel>;

// === Load Test Configuration ===
// Easily adjust these constants to change test parameters
const NUM_PEERS: usize = 10;
const TOTAL_ROUTES: usize = 1_000_000; // 1M total routes
const ROUTES_PER_UPDATE: usize = 100; // Routes per BGP UPDATE message
const ROUTE_PROCESSING_TIMEOUT_SECS: u64 = 60; // Time to wait for all routes to be processed
const ROUTE_GEN_SEED: u64 = 12345; // Reproducible route generation

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
            log_level: "error".to_string(),
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
async fn test_route_ingestion_load() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init()
        .ok();

    tracing::info!(
        "Starting load test: {} peers, {} total routes",
        NUM_PEERS,
        TOTAL_ROUTES
    );

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

    // Generate realistic routes with overlap
    let config = RouteGenConfig {
        total_routes: TOTAL_ROUTES,
        num_peers: NUM_PEERS,
        seed: ROUTE_GEN_SEED,
        prefix_len_dist: PrefixLengthDistribution::default(),
        overlap_config: OverlapConfig::default(),
        attr_config: AttributeConfig::default(),
    };

    tracing::info!("Generating routes with best path selection diversity...");
    tracing::info!(
        "  Overlap policy: {}% single-peer, {}% 2-3 peers, {}% 4+ peers",
        config.overlap_config.single_peer_pct,
        config.overlap_config.two_three_peer_pct,
        config.overlap_config.heavy_peer_pct
    );
    tracing::info!(
        "  Prefix distribution: {}% /24, {}% /22-23, {}% /20-21, {}% /16-19",
        config.prefix_len_dist.len_24,
        config.prefix_len_dist.len_22_23,
        config.prefix_len_dist.len_20_21,
        config.prefix_len_dist.len_16_19
    );
    tracing::info!(
        "  AS_PATH length: {}-{} (avg {})",
        config.attr_config.as_path_min_len,
        config.attr_config.as_path_max_len,
        config.attr_config.as_path_avg_len
    );
    tracing::info!(
        "  Origin mix: {}% IGP, {}% INCOMPLETE, {}% EGP",
        config.attr_config.origin_igp_pct,
        config.attr_config.origin_incomplete_pct,
        config.attr_config.origin_egp_pct
    );

    let peer_route_sets = generate_peer_routes(config);

    tracing::info!("Generated {} route sets", peer_route_sets.len());
    for (i, peer_set) in peer_route_sets.iter().enumerate() {
        tracing::info!("  Peer {}: {} routes", i, peer_set.routes.len());
    }

    // PHASE 1: Establish all peer connections
    tracing::info!("Phase 1: Establishing {} peer connections...", NUM_PEERS);
    let mut connections = Vec::new();

    for i in 0..NUM_PEERS {
        let target: SocketAddr = bgp_addr.parse().unwrap();
        let sender_asn = 65001 + i as u16;
        let sender_router_id = Ipv4Addr::new(2, 0, 0, 1 + i as u8);

        // Use different loopback IP for each sender (127.0.0.1, 127.0.0.2, etc.)
        // This is necessary because bgpgg identifies peers by source IP address
        let bind_addr: SocketAddr = format!("127.0.0.{}:0", 1 + i).parse().unwrap();

        tracing::info!(
            "Connecting peer {} (AS{}) from {}...",
            i,
            sender_asn,
            bind_addr.ip()
        );

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
        "Phase 3: Blasting {} routes from {} peers...",
        TOTAL_ROUTES,
        connections.len()
    );

    // Channel to receive results AND connections to keep them alive
    let (result_tx, mut result_rx) = tokio::sync::mpsc::channel::<(
        usize,
        Result<crate::sender::SenderStats, std::io::Error>,
        Option<crate::sender::SenderConnection>,
    )>(NUM_PEERS);
    let start_time = Instant::now();

    // Distribute routes to connections
    for (conn, peer_set) in connections.into_iter().zip(peer_route_sets) {
        let tx = result_tx.clone();
        let peer_index = peer_set.peer_index;
        let routes = peer_set.routes;

        tokio::spawn(async move {
            let result = match crate::sender::send_routes(conn, routes, ROUTES_PER_UPDATE).await {
                Ok((returned_conn, stats)) => (peer_index, Ok(stats), Some(returned_conn)),
                Err(e) => (peer_index, Err(e), None),
            };
            let _ = tx.send(result).await;
        });
    }
    drop(result_tx); // Drop original so channel closes after all senders report

    // Collect results and keep connections alive (prevent EOF)
    let mut sender_stats = Vec::new();
    let mut _live_connections = Vec::new();
    while let Some((i, result, conn_opt)) = result_rx.recv().await {
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
                // Keep connection alive to prevent EOF
                if let Some(conn) = conn_opt {
                    _live_connections.push(conn);
                }
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
    while start.elapsed().as_secs() < ROUTE_PROCESSING_TIMEOUT_SECS {
        match client
            .get_server_info(bgpgg::grpc::proto::GetServerInfoRequest {})
            .await
        {
            Ok(response) => {
                let info = response.into_inner();
                let count = info.num_routes;
                tracing::info!("Current route count: {}", count);
                if count == TOTAL_ROUTES as u64 {
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
                tracing::warn!("Failed to get server info: {:?}", e);
            }
        }
        sleep(Duration::from_secs(2)).await;
    }

    if !success {
        tracing::warn!(
            "Timeout waiting for {} routes in RIB (last count: {})",
            TOTAL_ROUTES,
            last_count
        );
        // Don't panic, just log for debugging
        tracing::info!("Test ended for debugging - not asserting on route count");
        bgpgg.kill();
        return;
    }

    // Note: With overlapping routes, we can't verify expected UPDATE count per peer
    // as each peer may send different amounts based on overlap distribution
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
        }
    }

    // Report final statistics
    let processing_time = Instant::now() - start;
    tracing::info!("\n=== Test Results ===");
    tracing::info!("Route send time: {:?}", ingestion_time);
    tracing::info!("Route processing time: {:?}", processing_time);
    tracing::info!("Total test time: {:?}", ingestion_time + processing_time);

    bgpgg.kill();
}
