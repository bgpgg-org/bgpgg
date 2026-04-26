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

mod common;

use std::io::Write;
use std::time::Duration;

use bgpgg::grpc::proto::SessionConfig;
use common::{poll_until_ok, Rogg};

/// Seed for read-only/show tests: includes a configured peer so
/// `show bgp peers` etc. have something to report.
const SEED_WITH_PEER: &str = "service bgp {
  asn 65042
  router-id 4.4.4.4
  listen-addr 127.0.0.1:0
  grpc-listen-addr 127.0.0.1:0

  peer 192.0.2.1 {
    remote-as 65043
  }
}
";

/// Seed for configure-mode tests: peer-free so each test starts from a
/// clean slate and can add/remove peers without colliding.
const SEED_EMPTY: &str = "service bgp {
  asn 65000
  router-id 5.5.5.5
  listen-addr 127.0.0.1:0
  grpc-listen-addr 127.0.0.1:0
}
";

/// Run `cmd` through all three invocation modes and assert each output
/// contains every expected substring. Modes: one-shot (`ggsh show ...`),
/// piped (`echo ... | ggsh`), interactive (PTY-attached prompt).
fn assert_all_modes(rogg: &Rogg, cmd: &str, expected: &[&str]) {
    let args: Vec<&str> = cmd.split_whitespace().collect();
    let outs = [
        ("one-shot", rogg.ggsh_cmd(&args)),
        ("piped", rogg.ggsh(&format!("{}\n", cmd))),
        ("interactive", rogg.ggsh_pty_run(cmd)),
    ];
    for (mode, out) in &outs {
        for substr in expected {
            assert!(
                out.contains(substr),
                "{:?} in {} mode missing {:?}: {}",
                cmd,
                mode,
                substr,
                out
            );
        }
    }
}

#[tokio::test]
async fn show_version() {
    let rogg = Rogg::new(SEED_WITH_PEER).await;
    assert_all_modes(&rogg, "show version", &["ggsh"]);
}

#[tokio::test]
async fn show_bgp_summary() {
    let rogg = Rogg::new(SEED_WITH_PEER).await;
    assert_all_modes(&rogg, "show bgp summary", &["BGP router listening"]);
}

#[tokio::test]
async fn show_bgp_peers() {
    let rogg = Rogg::new(SEED_WITH_PEER).await;
    assert_all_modes(&rogg, "show bgp peers", &["192.0.2.1"]);
}

#[tokio::test]
async fn show_bgp_peer() {
    let rogg = Rogg::new(SEED_WITH_PEER).await;
    assert_all_modes(&rogg, "show bgp peers 192.0.2.1", &["65043"]);
}

#[tokio::test]
async fn show_bgp_routes() {
    let rogg = Rogg::new(SEED_WITH_PEER).await;
    // No assertion on content -- empty RIB, just verify the command runs
    // cleanly in every mode (the harness asserts exit 0).
    assert_all_modes(&rogg, "show bgp routes", &[]);
}

#[tokio::test]
async fn show_config_history() {
    let rogg = Rogg::new(SEED_WITH_PEER).await;
    assert_all_modes(&rogg, "show config history", &[]);
}

#[tokio::test]
async fn running_config_round_trips() {
    let rogg = Rogg::new(SEED_WITH_PEER).await;
    let cfg = rogg.running_config().await;
    assert_eq!(cfg.asn, 65042);
}

/// Type `exit` at the interactive prompt and the ggsh process exits cleanly.
#[tokio::test]
async fn test_interactive_exit() {
    let rogg = Rogg::new(SEED_EMPTY).await;
    let (mut pty, mut child) = rogg.ggsh_pty();
    pty.write_all(b"exit\n").unwrap();
    drop(pty);

    let status = poll_until_ok::<_, _, _, ()>(Duration::from_secs(5), || {
        let polled = child.try_wait().ok().flatten().ok_or(());
        async move { polled }
    })
    .await
    .expect("ggsh did not exit after `exit` command");
    assert!(status.success(), "ggsh exit -> non-zero status: {}", status);
}

#[tokio::test]
async fn configure_peer_lifecycle() {
    let rogg = Rogg::new(SEED_EMPTY).await;

    rogg.ggsh(
        "configure
service bgp
peer 192.0.2.10 remote-as 65099
commit
",
    );

    let cfg = rogg.read_rogg_conf();
    assert!(
        cfg.peers.iter().any(|p| p.address == "192.0.2.10"),
        "peer not in rogg.conf: {:?}",
        cfg.peers
    );
    let peers = rogg.client.get_peers().await.unwrap();
    assert!(
        peers.iter().any(|p| p.address == "192.0.2.10"),
        "peer not in running: {:?}",
        peers
    );

    rogg.ggsh(
        "configure
service bgp
peer 192.0.2.10 remote-as 65100
commit
",
    );
    let cfg = rogg.read_rogg_conf();
    let peer = cfg
        .peers
        .iter()
        .find(|p| p.address == "192.0.2.10")
        .expect("peer present");
    assert_eq!(peer.asn, Some(65100));

    rogg.ggsh(
        "configure
service bgp
unset peer 192.0.2.10
commit
",
    );
    let cfg = rogg.read_rogg_conf();
    assert!(cfg.peers.is_empty(), "peer still present: {:?}", cfg.peers);
    let peers = rogg.client.get_peers().await.unwrap();
    assert!(
        !peers.iter().any(|p| p.address == "192.0.2.10"),
        "peer still running: {:?}",
        peers
    );
}

#[tokio::test]
async fn configure_exit_discards() {
    let rogg = Rogg::new(SEED_EMPTY).await;
    let before = std::fs::read_to_string(rogg.config_path()).unwrap();

    rogg.ggsh(
        "configure
service bgp
peer 192.0.2.20 remote-as 65043
exit
exit
",
    );

    let after = std::fs::read_to_string(rogg.config_path()).unwrap();
    assert_eq!(before, after, "exit must not touch rogg.conf");
    assert!(rogg.client.get_peers().await.unwrap().is_empty());
    assert!(
        !conf::fs::lock_path_for(rogg.config_path()).exists(),
        "lock file should be cleaned"
    );
}

#[tokio::test]
async fn configure_rejects_invalid() {
    let rogg = Rogg::new(SEED_EMPTY).await;

    // Bad value -> grammar rejects it -> candidate untouched. We then
    // `exit` instead of `commit` so the candidate is discarded.
    let out = rogg.ggsh(
        "configure
service bgp
peer 192.0.2.30 remote-as not-a-number
exit
exit
",
    );
    let lower = out.to_lowercase();
    assert!(
        lower.contains("error") || lower.contains("unknown"),
        "expected rejection message, got: {}",
        out
    );

    // The bogus peer was never parsed, so the on-disk and running configs
    // both stay peer-free.
    assert!(rogg.read_rogg_conf().peers.is_empty());
    assert!(rogg.client.get_peers().await.unwrap().is_empty());
}

#[tokio::test]
async fn imperative_save() {
    let rogg = Rogg::new(SEED_EMPTY).await;

    rogg.client
        .add_peer(
            "192.0.2.40".into(),
            Some(SessionConfig {
                asn: Some(65055),
                ..Default::default()
            }),
        )
        .await
        .expect("add_peer");

    let session = rogg.session();
    rogg.client
        .save_config(session.uuid)
        .await
        .expect("save_config");
    drop(session);

    let cfg = rogg.read_rogg_conf();
    assert!(
        cfg.peers.iter().any(|p| p.address == "192.0.2.40"),
        "peer not persisted: {:?}",
        cfg.peers
    );
}

#[tokio::test]
async fn commit_rollback_lifecycle() {
    let rogg = Rogg::new(SEED_EMPTY).await;

    let trunk = SEED_EMPTY.trim_end_matches("}\n");
    let text_a = format!("{}  peer 192.0.2.50 {{ remote-as 65060 }}\n}}\n", trunk);
    let text_b = format!("{}  peer 192.0.2.51 {{ remote-as 65061 }}\n}}\n", trunk);

    {
        let session = rogg.session();
        rogg.client
            .commit_config(text_a, session.uuid)
            .await
            .unwrap();
    }
    {
        let session = rogg.session();
        rogg.client
            .commit_config(text_b, session.uuid)
            .await
            .unwrap();
    }

    let snapshots = rogg.client.list_config_snapshots().await.unwrap();
    assert!(!snapshots.is_empty(), "expected snapshots after commits");

    {
        let session = rogg.session();
        rogg.client.rollback_config(1, session.uuid).await.unwrap();
    }
    let cfg = rogg.running_config().await;
    assert!(
        cfg.peers.iter().any(|p| p.address == "192.0.2.50"),
        "rollback A failed: {:?}",
        cfg.peers
    );

    {
        let session = rogg.session();
        rogg.client.rollback_config(1, session.uuid).await.unwrap();
    }
    let cfg = rogg.running_config().await;
    assert!(
        cfg.peers.iter().any(|p| p.address == "192.0.2.51"),
        "rollback B failed: {:?}",
        cfg.peers
    );

    let bad = {
        let session = rogg.session();
        rogg.client.rollback_config(99, session.uuid).await
    };
    assert!(bad.is_err(), "expected rollback(99) to fail");
}

/// While one ggsh holds the EX configure lock, a second ggsh's
/// `configure` is rejected fast and writes nothing.
#[tokio::test]
async fn test_multiple_configure_sessions() {
    let rogg = Rogg::new(SEED_EMPTY).await;

    let mut first = rogg.ggsh_spawn("configure\n");
    let lock_path = conf::fs::lock_path_for(rogg.config_path());
    poll_until_ok::<_, _, _, ()>(Duration::from_secs(5), || async {
        if lock_path.exists() {
            Ok(())
        } else {
            Err(())
        }
    })
    .await
    .expect("first ggsh never created lock file");

    let second = rogg.ggsh(
        "configure
service bgp
peer 192.0.2.60 remote-as 65043
exit
",
    );
    assert!(
        second.to_lowercase().contains("configure session"),
        "expected lock-busy message, got: {}",
        second
    );
    assert!(rogg.read_rogg_conf().peers.is_empty());

    drop(first.stdin.take());
    assert!(first.wait().expect("first ggsh wait").success());
}

/// While a configure session holds the EX lock, imperative gRPC writes
/// fail with the lock-busy error -- handlers take an SH lock that's
/// incompatible with the live EX.
#[tokio::test]
async fn test_add_peer_during_configure() {
    let rogg = Rogg::new(SEED_EMPTY).await;

    let mut holder = rogg.ggsh_spawn("configure\n");
    let lock_path = conf::fs::lock_path_for(rogg.config_path());
    poll_until_ok::<_, _, _, ()>(Duration::from_secs(5), || async {
        if lock_path.exists() {
            Ok(())
        } else {
            Err(())
        }
    })
    .await
    .expect("holder never created lock file");

    let err = rogg
        .client
        .add_peer(
            "192.0.2.70".into(),
            Some(SessionConfig {
                asn: Some(65077),
                ..Default::default()
            }),
        )
        .await
        .expect_err("add_peer should fail while EX lock is held");
    assert!(
        err.message().to_lowercase().contains("config locked"),
        "expected lock-busy status, got: {}",
        err.message()
    );
    assert!(rogg.client.get_peers().await.unwrap().is_empty());

    drop(holder.stdin.take());
    let _ = holder.wait();
}

/// SIGKILL on a configure-holding ggsh leaves the lock file behind, but
/// the kernel-level flock dies with the process; the next ggsh reclaims
/// the lock and commits.
#[tokio::test]
async fn configure_recovers_after_holder_sigkilled() {
    let rogg = Rogg::new(SEED_EMPTY).await;

    let mut holder = rogg.ggsh_spawn("configure\n");
    poll_until_ok::<_, _, _, ()>(Duration::from_secs(5), || async {
        match conf::fs::read_session_uuid(rogg.config_path()) {
            Ok(Some(_)) => Ok(()),
            _ => Err(()),
        }
    })
    .await
    .expect("holder never wrote a session UUID");
    // SAFETY: kill(2) with SIGKILL has no preconditions.
    unsafe {
        libc::kill(holder.id() as i32, libc::SIGKILL);
    }
    let _ = holder.wait();

    rogg.ggsh(
        "configure
service bgp
peer 192.0.2.61 remote-as 65043
commit
",
    );
    let cfg = rogg.read_rogg_conf();
    assert!(
        cfg.peers.iter().any(|p| p.address == "192.0.2.61"),
        "recovery peer absent: {:?}",
        cfg.peers
    );
}
