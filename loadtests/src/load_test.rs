use crate::calculate_expected_best_paths;
use crate::route_generator::{
    generate_peer_routes, AttributeConfig, OverlapConfig, PrefixLengthDistribution, RouteGenConfig,
};
use bgpgg::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin};
use bgpgg::config::Config;
use bgpgg::grpc::proto::bgp_service_client::BgpServiceClient;
use bgpgg::rib::{Path, RouteSource};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tonic::transport::Channel;

type BgpClient = BgpServiceClient<Channel>;

/// Transform a path to match what would be exported to an eBGP peer
/// (prepend local ASN, rewrite next_hop, remove local_pref and MED)
fn transform_path_for_ebgp_export(path: &Path, local_asn: u16, local_router_id: Ipv4Addr) -> Path {
    let mut exported = path.clone();

    // Prepend local ASN to AS_PATH
    if !exported.as_path.is_empty() {
        let first_segment = &exported.as_path[0];
        if first_segment.segment_type == AsPathSegmentType::AsSequence {
            // Prepend to existing AS_SEQUENCE
            let mut new_asn_list = vec![local_asn];
            new_asn_list.extend_from_slice(&first_segment.asn_list);
            exported.as_path[0] = AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: new_asn_list.len() as u8,
                asn_list: new_asn_list,
            };
        } else {
            // Create new AS_SEQUENCE with local ASN
            let mut new_segments = vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![local_asn],
            }];
            new_segments.extend_from_slice(&exported.as_path);
            exported.as_path = new_segments;
        }
    } else {
        // Empty AS_PATH, create new segment
        exported.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 1,
            asn_list: vec![local_asn],
        }];
    }

    // Rewrite next_hop to local router ID
    exported.next_hop = local_router_id;

    // Remove local_pref (not used in eBGP)
    exported.local_pref = None;

    // Remove MED (typically not propagated across AS boundaries)
    exported.med = None;

    exported
}

// === Load Test Configuration ===
// Easily adjust these constants to change test parameters
const NUM_PEERS: usize = 10;
const TOTAL_ROUTES: usize = 1_000_000; // 1M total routes
const ROUTES_PER_UPDATE: usize = 100; // Routes per BGP UPDATE message
const ROUTE_PROCESSING_TIMEOUT_SECS: u64 = 300; // Time to wait for all routes to be processed (5 minutes)
const ROUTE_GEN_SEED: u64 = 12345; // Reproducible route generation

/// Convert proto::Path (from gRPC) to rib::Path for comparison
fn proto_path_to_rib_path(proto_path: &bgpgg::grpc::proto::Path) -> Result<Path, String> {
    // Convert origin
    let origin = match proto_path.origin {
        0 => Origin::IGP,
        1 => Origin::EGP,
        2 => Origin::INCOMPLETE,
        _ => return Err(format!("Invalid origin: {}", proto_path.origin)),
    };

    // Convert AS_PATH
    let as_path: Vec<AsPathSegment> = proto_path
        .as_path
        .iter()
        .map(|seg| {
            let segment_type = match seg.segment_type() {
                bgpgg::grpc::proto::AsPathSegmentType::AsSet => AsPathSegmentType::AsSet,
                bgpgg::grpc::proto::AsPathSegmentType::AsSequence => AsPathSegmentType::AsSequence,
            };
            AsPathSegment {
                segment_type,
                segment_len: seg.asns.len() as u8,
                asn_list: seg.asns.iter().map(|asn| *asn as u16).collect(),
            }
        })
        .collect();

    // Parse next hop
    let next_hop: Ipv4Addr = proto_path
        .next_hop
        .parse()
        .map_err(|_| format!("Invalid next_hop: {}", proto_path.next_hop))?;

    // Parse peer address for source
    let peer_ip: IpAddr = proto_path
        .peer_address
        .parse()
        .map_err(|_| format!("Invalid peer_address: {}", proto_path.peer_address))?;
    let source = RouteSource::Ebgp(peer_ip);

    // Convert communities
    let communities: Vec<u32> = proto_path.communities.clone();

    Ok(Path::from_attributes(
        origin,
        as_path,
        next_hop,
        source,
        proto_path.local_pref,
        proto_path.med,
        proto_path.atomic_aggregate,
        communities,
        vec![], // unknown_attrs not compared
    ))
}

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
            hold_time_secs: 3600, // 1 hour for long-running load tests
            connect_retry_secs: 30,
            accept_unconfigured_peers: true,
            peers: vec![],
            bmp_servers: vec![],
            defined_sets: Default::default(),
            policy_definitions: vec![],
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

    // Create reject-all export policy to prevent route redistribution
    // This eliminates TCP backpressure from route redistribution in load tests
    tracing::info!("Creating reject-all export policy...");
    client
        .add_policy(bgpgg::grpc::proto::AddPolicyRequest {
            name: "reject-all".to_string(),
            statements: vec![bgpgg::grpc::proto::StatementConfig {
                conditions: None,
                actions: Some(bgpgg::grpc::proto::ActionsConfig {
                    accept: None,
                    reject: Some(true),
                    local_pref: None,
                    med: None,
                    add_communities: vec![],
                    remove_communities: vec![],
                }),
            }],
        })
        .await
        .expect("Failed to create reject-all policy");

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

    // Calculate expected best paths using BGP decision process
    tracing::info!("Calculating expected best paths...");
    let expected_best_paths = calculate_expected_best_paths(&peer_route_sets);
    tracing::info!(
        "Expected {} unique prefixes with best paths selected",
        expected_best_paths.len()
    );

    // Debug: Count total routes being sent
    let total_routes_to_send: usize = peer_route_sets.iter().map(|ps| ps.routes.len()).sum();
    tracing::info!(
        "Total routes to send: {} (across {} peers)",
        total_routes_to_send,
        peer_route_sets.len()
    );

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

                // Apply reject-all export policy to prevent this peer from receiving routes
                client
                    .set_policy_assignment(bgpgg::grpc::proto::SetPolicyAssignmentRequest {
                        peer_address: bind_addr.ip().to_string(),
                        direction: "export".to_string(),
                        policy_names: vec!["reject-all".to_string()],
                        default_action: None,
                    })
                    .await
                    .expect("Failed to set export policy");

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

    // PHASE 4: Wait for bgpgg to process all routes and verify best paths
    tracing::info!("Phase 4: Waiting for bgpgg to process routes...");
    let processing_start = Instant::now();
    let mut last_count = 0;
    let mut processing_complete = false;
    let mut processing_end = processing_start;
    while processing_start.elapsed().as_secs() < ROUTE_PROCESSING_TIMEOUT_SECS {
        match client
            .get_server_info(bgpgg::grpc::proto::GetServerInfoRequest {})
            .await
        {
            Ok(response) => {
                let info = response.into_inner();
                let count = info.num_routes;
                tracing::info!("Current route count in RIB: {}", count);

                // We expect the number of unique prefixes (best paths selected)
                if count == expected_best_paths.len() as u64 {
                    processing_end = Instant::now(); // Capture end time immediately
                    tracing::info!("RIB has expected number of routes, verifying best paths...");
                    last_count = count;
                    processing_complete = true;
                    break;
                }
                if count < last_count {
                    tracing::warn!("Route count decreased from {} to {}", last_count, count);
                } else if count == last_count && last_count > 0 {
                    tracing::info!("Route count stable at {}, waiting...", count);
                }
                last_count = count;
            }
            Err(e) => {
                tracing::warn!("Failed to get server info: {:?}", e);
            }
        }
        sleep(Duration::from_secs(2)).await;
    }

    if !processing_complete {
        tracing::error!(
            "Route count mismatch: expected {} unique prefixes, got {}",
            expected_best_paths.len(),
            last_count
        );
        bgpgg.kill();
        panic!(
            "Expected {} routes in loc-rib, got {}",
            expected_best_paths.len(),
            last_count
        );
    }

    // Query GLOBAL RIB (loc-rib) to verify best paths using streaming API
    tracing::info!("Querying GLOBAL RIB to verify best paths...");
    use tokio_stream::StreamExt;

    let mut stream = client
        .list_routes_stream(bgpgg::grpc::proto::ListRoutesRequest {
            rib_type: Some(bgpgg::grpc::proto::RibType::Global as i32),
            peer_address: None,
        })
        .await
        .expect("Failed to start route stream")
        .into_inner();

    // Collect all routes from the stream
    let mut routes = Vec::new();
    while let Some(route) = stream.next().await {
        routes.push(route.expect("Failed to read route from stream"));
    }
    tracing::info!("Retrieved {} routes from GLOBAL RIB", routes.len());

    // Verify each route matches our expected best path
    let mut mismatches = Vec::new();
    for route in &routes {
        let prefix: bgpgg::net::IpNetwork = route.prefix.parse().expect("Failed to parse prefix");

        if let Some(expected_path) = expected_best_paths.get(&prefix) {
            // GLOBAL RIB may have multiple paths per prefix (sorted, best first)
            // We only care about the first path (the best path)
            if route.paths.is_empty() {
                mismatches.push(format!("Prefix {} has no paths in GLOBAL RIB", prefix));
                continue;
            }

            let proto_path = &route.paths[0];

            // Convert proto::Path to rib::Path and use Path's equality for comparison
            let actual_path = match proto_path_to_rib_path(proto_path) {
                Ok(p) => p,
                Err(e) => {
                    mismatches.push(format!("Prefix {}: failed to convert path: {}", prefix, e));
                    continue;
                }
            };

            // Use Path::eq to compare paths (reusing core logic!)
            if &actual_path != expected_path {
                mismatches.push(format!(
                    "Prefix {}: best path mismatch\n  Expected: {:?}\n  Got: {:?}",
                    prefix, expected_path, actual_path
                ));
            }
        } else {
            mismatches.push(format!(
                "Prefix {} found in GLOBAL RIB but not in expected best paths",
                prefix
            ));
        }
    }

    if !mismatches.is_empty() {
        tracing::error!(
            "Found {} mismatches in best path selection:",
            mismatches.len()
        );
        for (i, mismatch) in mismatches.iter().take(10).enumerate() {
            tracing::error!("  {}: {}", i + 1, mismatch);
        }
        if mismatches.len() > 10 {
            tracing::error!("  ... and {} more", mismatches.len() - 10);
        }
        bgpgg.kill();
        panic!(
            "Best path verification failed with {} mismatches",
            mismatches.len()
        );
    }

    tracing::info!("✓ All {} best paths verified correctly!", routes.len());

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
    let processing_time = processing_end - processing_start;
    tracing::info!("\n=== Test Results ===");
    tracing::info!("Route send time: {:?}", ingestion_time);
    tracing::info!("Route processing time: {:?}", processing_time);
    tracing::info!("Total test time: {:?}", ingestion_time + processing_time);

    bgpgg.kill();
}

#[tokio::test]
async fn test_route_convergence_load() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init()
        .ok();

    const TEST_ROUTES: usize = 1_000_000;
    const NUM_DOWNSTREAM: usize = 10; // Start small for debugging

    tracing::info!(
        "Starting convergence test: {} upstream peers, {} routes, {} downstream peers",
        NUM_PEERS,
        TEST_ROUTES,
        NUM_DOWNSTREAM
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

    // Create reject-all export policy to prevent route redistribution to upstream peers
    tracing::info!("Creating reject-all export policy...");
    client
        .add_policy(bgpgg::grpc::proto::AddPolicyRequest {
            name: "reject-all".to_string(),
            statements: vec![bgpgg::grpc::proto::StatementConfig {
                conditions: None,
                actions: Some(bgpgg::grpc::proto::ActionsConfig {
                    accept: None,
                    reject: Some(true),
                    local_pref: None,
                    med: None,
                    add_communities: vec![],
                    remove_communities: vec![],
                }),
            }],
        })
        .await
        .expect("Failed to create reject-all policy");

    // Generate routes (same as ingestion test but with TEST_ROUTES)
    let config = RouteGenConfig {
        total_routes: TEST_ROUTES,
        num_peers: NUM_PEERS,
        seed: ROUTE_GEN_SEED,
        prefix_len_dist: PrefixLengthDistribution::default(),
        overlap_config: OverlapConfig::default(),
        attr_config: AttributeConfig::default(),
    };

    tracing::info!("Generating {} routes with overlap...", TEST_ROUTES);
    let peer_route_sets = generate_peer_routes(config);

    // Calculate expected best paths
    let expected_best_paths = calculate_expected_best_paths(&peer_route_sets);
    tracing::info!(
        "Expected {} unique prefixes with best paths",
        expected_best_paths.len()
    );

    // PHASE 1: Establish downstream peer connections (will receive routes)
    tracing::info!(
        "Phase 1: Establishing {} downstream peer connections...",
        NUM_DOWNSTREAM
    );
    let mut downstream_connections = Vec::new();

    for i in 0..NUM_DOWNSTREAM {
        let target: SocketAddr = bgp_addr.parse().unwrap();
        let downstream_asn = 65100 + i as u16;
        let downstream_router_id = Ipv4Addr::new(3, 0, 0, 1 + i as u8);
        let bind_addr: SocketAddr = format!("127.0.0.{}:0", 21 + i).parse().unwrap();

        match crate::sender::establish_connection(
            target,
            downstream_asn,
            downstream_router_id,
            65000,
            downstream_router_id,
            Some(bind_addr),
        )
        .await
        {
            Ok(conn) => {
                tracing::info!("Downstream peer {} connected from {}", i, bind_addr.ip());
                // NO reject-all export policy for downstream - they should receive routes
                downstream_connections.push(conn);
            }
            Err(e) => {
                tracing::error!("Failed to connect downstream peer {}: {:?}", i, e);
            }
        }
    }

    tracing::info!(
        "{} downstream peers connected",
        downstream_connections.len()
    );

    // PHASE 2: Verify downstream peers are established
    tracing::info!("Phase 2: Verifying downstream peers are established...");
    sleep(Duration::from_secs(1)).await;

    let peers_response = client
        .list_peers(bgpgg::grpc::proto::ListPeersRequest {})
        .await
        .unwrap();
    let peers = peers_response.into_inner().peers;
    tracing::info!("bgpgg reports {} peers after downstream connect", peers.len());
    for peer in &peers {
        tracing::info!(
            "  Peer: {} (AS{}, state={})",
            peer.address,
            peer.asn,
            peer.state
        );
    }

    // PHASE 3: Establish upstream peer connections
    tracing::info!(
        "Phase 3: Establishing {} upstream peer connections...",
        NUM_PEERS
    );
    let mut connections = Vec::new();

    for i in 0..NUM_PEERS {
        let target: SocketAddr = bgp_addr.parse().unwrap();
        let sender_asn = 65001 + i as u16;
        let sender_router_id = Ipv4Addr::new(2, 0, 0, 1 + i as u8);
        let bind_addr: SocketAddr = format!("127.0.0.{}:0", 1 + i).parse().unwrap();

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
                tracing::info!("Upstream peer {} connected", i);

                // Apply reject-all export policy to prevent routes going back to upstream
                client
                    .set_policy_assignment(bgpgg::grpc::proto::SetPolicyAssignmentRequest {
                        peer_address: bind_addr.ip().to_string(),
                        direction: "export".to_string(),
                        policy_names: vec!["reject-all".to_string()],
                        default_action: None,
                    })
                    .await
                    .expect("Failed to set export policy");

                connections.push(conn);
            }
            Err(e) => {
                tracing::error!("Failed to connect upstream peer {}: {:?}", i, e);
            }
        }
    }

    tracing::info!("{} upstream peers connected", connections.len());

    // Verify all peers are established
    tracing::info!("Verifying all peers are established...");
    sleep(Duration::from_secs(1)).await;

    let peers_response = client
        .list_peers(bgpgg::grpc::proto::ListPeersRequest {})
        .await
        .unwrap();
    let peers = peers_response.into_inner().peers;
    tracing::info!(
        "bgpgg reports {} total peers ({} upstream + {} downstream)",
        peers.len(),
        NUM_PEERS,
        NUM_DOWNSTREAM
    );
    for peer in &peers {
        tracing::info!(
            "  Peer: {} (AS{}, state={})",
            peer.address,
            peer.asn,
            peer.state
        );
    }

    // PHASE 4: Start convergence timer and send routes
    tracing::info!("Phase 4: Sending routes from upstream peers...");
    let convergence_start = Instant::now();

    let (result_tx, mut result_rx) = tokio::sync::mpsc::channel::<(
        usize,
        Result<crate::sender::SenderStats, std::io::Error>,
        Option<crate::sender::SenderConnection>,
    )>(NUM_PEERS);

    // Keep downstream connections alive throughout the test
    let mut _live_downstream_connections = downstream_connections;

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
    drop(result_tx);

    let mut _live_connections = Vec::new();
    while let Some((i, result, conn_opt)) = result_rx.recv().await {
        match result {
            Ok(stats) => {
                tracing::info!(
                    "Upstream peer {} sent {} routes in {:?}",
                    i,
                    stats.routes_sent,
                    stats.duration
                );
                if let Some(conn) = conn_opt {
                    _live_connections.push(conn);
                }
            }
            Err(e) => {
                tracing::error!("Upstream peer {} failed: {:?}", i, e);
            }
        }
    }

    // PHASE 5: Wait for bgpgg to process routes (loc-rib populated)
    tracing::info!("Phase 5: Waiting for bgpgg to process routes...");
    let phase5_start = Instant::now();
    let mut last_count = 0;
    let mut phase5_complete = false;
    while phase5_start.elapsed().as_secs() < ROUTE_PROCESSING_TIMEOUT_SECS {
        let info = client
            .get_server_info(bgpgg::grpc::proto::GetServerInfoRequest {})
            .await
            .expect("Failed to get server info")
            .into_inner();

        tracing::info!("Current route count in loc-rib: {}", info.num_routes);

        if info.num_routes == expected_best_paths.len() as u64 {
            tracing::info!("Loc-rib fully populated with {} routes", info.num_routes);
            phase5_complete = true;
            break;
        }

        last_count = info.num_routes;
        sleep(Duration::from_secs(30)).await;
    }

    if !phase5_complete {
        tracing::error!(
            "Phase 5 timeout: expected {} routes, got {}",
            expected_best_paths.len(),
            last_count
        );
        bgpgg.kill();
        panic!(
            "Phase 5 timeout after {} seconds: expected {} routes, got {}",
            ROUTE_PROCESSING_TIMEOUT_SECS,
            expected_best_paths.len(),
            last_count
        );
    }

    // PHASE 6: Poll downstream peers' adj-rib-out until all routes received
    tracing::info!("Phase 6: Waiting for downstream peers to receive all routes...");
    let expected_route_count = expected_best_paths.len();
    let mut converged_peers = vec![false; NUM_DOWNSTREAM];
    let phase6_start = Instant::now();

    while phase6_start.elapsed().as_secs() < ROUTE_PROCESSING_TIMEOUT_SECS
        && !converged_peers.iter().all(|&x| x)
    {
        for i in 0..NUM_DOWNSTREAM {
            // Skip peers that have already converged
            if converged_peers[i] {
                continue;
            }

            let peer_addr = format!("127.0.0.{}", 21 + i);

            // Use streaming API to avoid message size limits
            use tokio_stream::StreamExt;
            let mut stream = client
                .list_routes_stream(bgpgg::grpc::proto::ListRoutesRequest {
                    rib_type: Some(bgpgg::grpc::proto::RibType::AdjOut as i32),
                    peer_address: Some(peer_addr.clone()),
                })
                .await
                .expect("Failed to start adj-rib-out stream")
                .into_inner();

            let mut route_count = 0;
            while let Some(_route) = stream.next().await {
                route_count += 1;
            }

            if route_count >= expected_route_count {
                tracing::info!(
                    "Downstream peer {} converged: {}/{} routes",
                    i,
                    route_count,
                    expected_route_count
                );
                converged_peers[i] = true;
            } else {
                tracing::info!(
                    "Downstream peer {} adj-rib-out: {}/{} routes (not converged, skipping remaining peers)",
                    i,
                    route_count,
                    expected_route_count
                );
                // No need to check other peers if this one hasn't converged yet
                break;
            }
        }

        if !converged_peers.iter().all(|&x| x) {
            sleep(Duration::from_secs(10)).await;
        }
    }

    if !converged_peers.iter().all(|&x| x) {
        tracing::error!("Phase 6 timeout: not all peers converged");
        for (i, &converged) in converged_peers.iter().enumerate() {
            if !converged {
                tracing::error!("  Downstream peer {} did not converge", i);
            }
        }
        bgpgg.kill();
        panic!("Phase 6 timeout after {} seconds", ROUTE_PROCESSING_TIMEOUT_SECS);
    }

    let convergence_end = Instant::now();
    let convergence_time = convergence_end - convergence_start;

    tracing::info!("All downstream peers converged!");

    // PHASE 7: Verify adj-rib-out contents for each downstream peer
    tracing::info!("Phase 7: Verifying adj-rib-out contents...");

    for i in 0..NUM_DOWNSTREAM {
        let peer_addr = format!("127.0.0.{}", 21 + i);

        use tokio_stream::StreamExt;
        let mut stream = client
            .list_routes_stream(bgpgg::grpc::proto::ListRoutesRequest {
                rib_type: Some(bgpgg::grpc::proto::RibType::AdjOut as i32),
                peer_address: Some(peer_addr.clone()),
            })
            .await
            .expect("Failed to start adj-rib-out stream")
            .into_inner();

        let mut routes = Vec::new();
        while let Some(route) = stream.next().await {
            routes.push(route.expect("Failed to read route"));
        }

        tracing::info!(
            "Verifying {} routes for downstream peer {}",
            routes.len(),
            i
        );

        let mut mismatches = Vec::new();
        for route in &routes {
            let prefix: bgpgg::net::IpNetwork =
                route.prefix.parse().expect("Failed to parse prefix");

            if let Some(expected_path) = expected_best_paths.get(&prefix) {
                if route.paths.is_empty() {
                    mismatches.push(format!("Prefix {} has no paths", prefix));
                    continue;
                }

                let proto_path = &route.paths[0];
                let actual_path = match proto_path_to_rib_path(proto_path) {
                    Ok(p) => p,
                    Err(e) => {
                        mismatches.push(format!("Prefix {}: {}", prefix, e));
                        continue;
                    }
                };

                // Transform expected path to match eBGP export transformation
                let expected_exported =
                    transform_path_for_ebgp_export(expected_path, 65000, Ipv4Addr::new(1, 1, 1, 1));

                if &actual_path != &expected_exported {
                    mismatches.push(format!(
                        "Prefix {}: path mismatch\n  Expected: {:?}\n  Got: {:?}",
                        prefix, expected_exported, actual_path
                    ));
                }
            } else {
                mismatches.push(format!("Prefix {} not in expected best paths", prefix));
            }
        }

        if !mismatches.is_empty() {
            tracing::error!("Downstream peer {} has {} mismatches:", i, mismatches.len());
            for mismatch in mismatches.iter().take(5) {
                tracing::error!("  {}", mismatch);
            }
            bgpgg.kill();
            panic!("Verification failed for downstream peer {}", i);
        }

        tracing::info!("✓ Downstream peer {} verified correctly", i);
    }

    tracing::info!("\n=== Convergence Test Results ===");
    tracing::info!("Total routes: {}", TEST_ROUTES);
    tracing::info!("Unique prefixes: {}", expected_best_paths.len());
    tracing::info!("Upstream peers: {}", NUM_PEERS);
    tracing::info!("Downstream peers: {}", NUM_DOWNSTREAM);
    tracing::info!("Convergence time (end-to-end): {:?}", convergence_time);
    tracing::info!(
        "✓ All {} downstream peers received correct routes!",
        NUM_DOWNSTREAM
    );

    bgpgg.kill();
}
