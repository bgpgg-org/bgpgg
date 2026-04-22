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

//! Single entry point for state mutation. All mutators call `commit_config`,
//! which applies the delta, persists `rogg.conf` (rotating the prior version
//! into `rogg.1.conf` and shifting older snapshots down), and on apply
//! failure returns `Err` without reverting — operators recover via
//! `RollbackConfig`.

use super::BgpServer;
use crate::log::error;
use conf::bgp::BgpConfig;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Number of historical config snapshots kept on disk.
pub(crate) const SNAPSHOT_COUNT: u32 = 10;

/// Metadata about a stored snapshot.
pub struct SnapshotInfo {
    pub index: u32,
    pub mtime_unix: u64,
    pub size_bytes: u64,
}

/// Validate, apply, persist. On apply failure, returns `Err` without
/// reverting — operator uses `RollbackConfig` to recover.
pub(crate) async fn commit_config(
    server: &mut BgpServer,
    new_config: BgpConfig,
    bind_addr: SocketAddr,
) -> Result<(), String> {
    for peer in &new_config.peers {
        peer.validate()?;
    }
    reject_unsupported_changes(&server.config, &new_config)?;

    let old_config = server.config.clone();
    reconfigure_all(server, &old_config, &new_config, bind_addr).await?;

    if let Err(e) = persist_config(&server.config_path, &new_config) {
        error!(error = %e, "failed to persist rogg.conf after in-memory commit");
        return Err(format!("applied but failed to persist: {}", e));
    }

    server.config = new_config;
    Ok(())
}

/// Apply the new config to runtime, one subsystem at a time. First failure
/// aborts the rest and bubbles up; runtime is left in whatever partial state
/// the failure produced.
async fn reconfigure_all(
    server: &mut BgpServer,
    old: &BgpConfig,
    new: &BgpConfig,
    bind_addr: SocketAddr,
) -> Result<(), String> {
    server.reconfigure_peers(old, new, bind_addr).await;
    server.reconfigure_bmp_servers(old, new).await?;
    server.reconfigure_rpki_caches(old, new).await?;
    Ok(())
}

/// Reject commits that touch fields we don't reconfigure yet.
fn reject_unsupported_changes(old: &BgpConfig, new: &BgpConfig) -> Result<(), String> {
    if old.asn != new.asn {
        return Err("changing 'asn' requires daemon restart".into());
    }
    if old.router_id != new.router_id {
        return Err("changing 'router-id' requires daemon restart".into());
    }
    if old.listen_addr != new.listen_addr {
        return Err("changing 'listen-addr' requires daemon restart".into());
    }
    if old.grpc_listen_addr != new.grpc_listen_addr {
        return Err("changing 'grpc-listen-addr' requires daemon restart".into());
    }
    if !json_eq(&old.policy_definitions, &new.policy_definitions) {
        return Err("policy-definitions cannot yet be changed via commit".into());
    }
    if !json_eq(&old.defined_sets, &new.defined_sets) {
        return Err("defined-sets cannot yet be changed via commit".into());
    }
    Ok(())
}

/// Structural equality without requiring `PartialEq`.
fn json_eq<T: serde::Serialize>(a: &T, b: &T) -> bool {
    match (serde_json::to_string(a), serde_json::to_string(b)) {
        (Ok(aa), Ok(bb)) => aa == bb,
        _ => false,
    }
}

/// Persist `config` to `path`, rotating the prior version into `.1` (and
/// older snapshots down by one, oldest dropped). Atomic replace via rename.
fn persist_config(path: &Path, config: &BgpConfig) -> io::Result<()> {
    rotate_snapshots(path, SNAPSHOT_COUNT)?;
    match fs::copy(path, snapshot_path_for(path, 1)) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let candidate = candidate_path_for(path);
    fs::write(&candidate, config.to_conf_str())?;
    fs::rename(&candidate, path)?;
    Ok(())
}

/// Slide existing snapshots up one slot: drop `.n`, rename `.(n-1)` → `.n`,
/// ..., `.1` → `.2`. Missing entries are skipped.
fn rotate_snapshots(path: &Path, n: u32) -> io::Result<()> {
    if n == 0 {
        return Ok(());
    }
    let oldest = snapshot_path_for(path, n);
    match fs::remove_file(&oldest) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    for i in (1..n).rev() {
        let src = snapshot_path_for(path, i);
        let dst = snapshot_path_for(path, i + 1);
        match fs::rename(&src, &dst) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read the snapshot at `index` as a UTF-8 string.
pub(crate) fn load_snapshot(path: &Path, index: u32) -> io::Result<String> {
    fs::read_to_string(snapshot_path_for(path, index))
}

/// Enumerate existing snapshots 1..=max. Returns only indices whose files
/// are readable; silently skips missing ones.
pub(crate) fn list_snapshots(path: &Path, max: u32) -> Vec<SnapshotInfo> {
    let mut out = Vec::new();
    for i in 1..=max {
        let snap = snapshot_path_for(path, i);
        let Ok(meta) = fs::metadata(&snap) else {
            continue;
        };
        let mtime_unix = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        out.push(SnapshotInfo {
            index: i,
            mtime_unix,
            size_bytes: meta.len(),
        });
    }
    out
}

/// Path where ggsh stages its candidate config. Appends `.candidate`.
pub(crate) fn candidate_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".candidate");
    PathBuf::from(s)
}

/// Snapshot path for `path` at `index`. Inserts `.<index>` before the file
/// extension: `/etc/rogg.conf` at index 3 → `/etc/rogg.3.conf`. Paths with
/// no extension (or dotfiles like `.rogg`) get `.<index>` appended.
pub(crate) fn snapshot_path_for(path: &Path, index: u32) -> PathBuf {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        let mut s = path.as_os_str().to_owned();
        s.push(format!(".{}", index));
        return PathBuf::from(s);
    };
    let new_name = match file_name.rfind('.') {
        Some(dot_pos) if dot_pos > 0 => {
            format!(
                "{}.{}{}",
                &file_name[..dot_pos],
                index,
                &file_name[dot_pos..]
            )
        }
        _ => format!("{}.{}", file_name, index),
    };
    path.parent()
        .map(|p| p.join(&new_name))
        .unwrap_or_else(|| PathBuf::from(new_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Scoped tempdir for tests: creates a unique directory, removes it on drop.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "bgpgg-config-test-{}-{}",
                std::process::id(),
                n
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn conf_path(&self) -> PathBuf {
            self.0.join("rogg.conf")
        }

        fn touch(&self, name: &str, contents: &str) {
            fs::write(self.0.join(name), contents).unwrap();
        }

        fn exists(&self, name: &str) -> bool {
            self.0.join(name).exists()
        }

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.0.join(name)).unwrap()
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_snapshot_path_for() {
        // Realistic inputs only -- the daemon's config_path is something like
        // rogg.conf (absolute or relative). Extension-less paths exist for
        // test/demo configs. Dotfiles and other exotic shapes don't.
        let cases = [
            ("/etc/rogg.conf", 3, "/etc/rogg.3.conf"),
            ("rogg.conf", 5, "rogg.5.conf"),
            ("/etc/config", 2, "/etc/config.2"),
            ("/var/rogg.conf.bak", 1, "/var/rogg.conf.1.bak"),
        ];
        for (input, n, expected) in cases {
            assert_eq!(
                snapshot_path_for(Path::new(input), n),
                PathBuf::from(expected),
                "input {:?} n={}",
                input,
                n
            );
        }
    }

    #[test]
    fn test_rotate_snapshots_shifts() {
        let dir = TestDir::new();
        // Pre-populate .1 through .10.
        for i in 1..=10 {
            dir.touch(&format!("rogg.{}.conf", i), &format!("v{}", i));
        }
        rotate_snapshots(&dir.conf_path(), 10).unwrap();

        // .1 is gone (moved to .2).
        assert!(!dir.exists("rogg.1.conf"));
        // .2 through .10 hold the prior .1 through .9.
        for i in 2..=10 {
            assert_eq!(dir.read(&format!("rogg.{}.conf", i)), format!("v{}", i - 1));
        }
        // Oldest (was .10) is dropped.
        assert!(!dir.exists("rogg.11.conf"));
    }

    #[test]
    fn test_rotate_snapshots_missing_entries() {
        let dir = TestDir::new();
        // Only .3 and .5 exist -- other indices missing.
        dir.touch("rogg.3.conf", "three");
        dir.touch("rogg.5.conf", "five");
        rotate_snapshots(&dir.conf_path(), 10).unwrap();

        // .3 -> .4, .5 -> .6; everything else stays missing.
        assert!(!dir.exists("rogg.3.conf"));
        assert_eq!(dir.read("rogg.4.conf"), "three");
        assert!(!dir.exists("rogg.5.conf"));
        assert_eq!(dir.read("rogg.6.conf"), "five");
    }

    #[test]
    fn test_list_snapshots() {
        let dir = TestDir::new();
        dir.touch("rogg.1.conf", "a");
        dir.touch("rogg.3.conf", "ccc");
        dir.touch("rogg.4.conf", "dddd");

        let got = list_snapshots(&dir.conf_path(), 10);
        let indices: Vec<u32> = got.iter().map(|s| s.index).collect();
        assert_eq!(indices, vec![1, 3, 4]);

        let sizes: Vec<u64> = got.iter().map(|s| s.size_bytes).collect();
        assert_eq!(sizes, vec![1, 3, 4]);

        assert!(got.iter().all(|s| s.mtime_unix > 0));
    }

    #[test]
    fn test_load_snapshot() {
        let dir = TestDir::new();
        dir.touch("rogg.2.conf", "hello");
        let text = load_snapshot(&dir.conf_path(), 2).unwrap();
        assert_eq!(text, "hello");
    }

    #[test]
    fn test_load_snapshot_not_found() {
        let dir = TestDir::new();
        let err = load_snapshot(&dir.conf_path(), 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
