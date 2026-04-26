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

//! Filesystem primitives shared across rogg daemons: atomic config write
//! with snapshot rotation, snapshot enumeration, sibling-lockfile
//! coordination.
//!
//! The sibling `<path>.lock` file is the rogg-wide config-mode lock.
//! ggsh holds an exclusive flock during configure mode and writes a
//! per-session UUID into the file. Imperative handlers take a shared
//! flock to refuse mutations during a session. Write RPCs verify the
//! caller's session_uuid against the file content.

use crate::language::{self, Root, Service};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use uuid::Uuid;

/// Number of historical config snapshots kept on disk.
pub const SNAPSHOT_COUNT: u32 = 10;

/// Metadata about a stored snapshot.
pub struct SnapshotInfo {
    pub index: u32,
    pub mtime_unix: u64,
    pub size_bytes: u64,
}

/// Open (create if missing) the sibling `.lock` file for `config_path`.
/// Creates parent directories as needed (e.g. on first ggsh run when
/// `~/.config/rogg/` doesn't exist yet).
pub fn open_lock_file(config_path: &Path) -> io::Result<File> {
    let lock_path = lock_path_for(config_path);
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
}

/// Caller holds SH for as long as the returned `File` is alive.
/// `Err("config locked")` when an EX holder exists.
pub fn acquire_shared_lock(config_path: &Path) -> Result<File, String> {
    let file = open_lock_file(config_path).map_err(|e| format!("lock error: {}", e))?;
    match file.try_lock_shared() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err("config locked".into()),
        Err(TryLockError::Error(e)) => Err(format!("lock error: {}", e)),
    }
}

/// Take EX on the lock file and write `session_uuid` into it. Caller
/// holds EX for as long as the returned `File` is alive. Used by ggsh
/// on `configure`. Truncates only after the flock is ours (a rejected
/// attempt must not clobber a held session's UUID).
pub fn acquire_exclusive_lock(config_path: &Path, session_uuid: Uuid) -> Result<File, String> {
    use std::io::Write;
    let mut file = open_lock_file(config_path).map_err(|e| format!("lock error: {}", e))?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err("another configure session is active".into()),
        Err(TryLockError::Error(e)) => return Err(format!("lock error: {}", e)),
    }
    file.set_len(0)
        .map_err(|e| format!("truncate failed: {}", e))?;
    write!(file, "{}", session_uuid).map_err(|e| format!("write failed: {}", e))?;
    file.flush().map_err(|e| format!("flush failed: {}", e))?;
    Ok(file)
}

/// Fresh v4 UUID. Coordination identity for a configure session;
/// not a security boundary.
pub fn make_session_uuid() -> Uuid {
    Uuid::new_v4()
}

/// `Ok(None)` if the lock file is missing or empty.
pub fn read_session_uuid(config_path: &Path) -> io::Result<Option<Uuid>> {
    let lock_path = lock_path_for(config_path);
    match fs::read_to_string(&lock_path) {
        Ok(content) => {
            let trimmed = content.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            Uuid::parse_str(trimmed).map(Some).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "lock file content is not a UUID",
                )
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Replace `service`'s slot in rogg.conf, rotate prior version into
/// `.1`, atomically write the merged result.
///
/// Caller must serialize concurrent writers (operator's EX flock or
/// ggsh's serial commit fan-out).
pub fn persist_service_config(path: &Path, service: Service) -> io::Result<()> {
    let existing = match fs::read_to_string(path) {
        Ok(text) => language::parse(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Root::default(),
        Err(e) => return Err(e),
    };
    let merged = existing.with_service(service).to_string();
    rotate_snapshots(path, SNAPSHOT_COUNT)?;
    match fs::copy(path, snapshot_path_for(path, 1)) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let tmp = tmp_write_path_for(path);
    fs::write(&tmp, &merged)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Slide existing snapshots up one slot: drop `.n`, rename `.(n-1)` -> `.n`,
/// ..., `.1` -> `.2`. Missing entries are skipped.
pub fn rotate_snapshots(path: &Path, n: u32) -> io::Result<()> {
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
pub fn load_snapshot(path: &Path, index: u32) -> io::Result<String> {
    fs::read_to_string(snapshot_path_for(path, index))
}

/// Enumerate existing snapshots 1..=max. Returns only indices whose files
/// are readable; silently skips missing ones.
pub fn list_snapshots(path: &Path, max: u32) -> Vec<SnapshotInfo> {
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

/// Snapshot path for `path` at `index`. Inserts `.<index>` before the file
/// extension: `/etc/rogg.conf` at index 3 -> `/etc/rogg.3.conf`. Paths with
/// no extension (or dotfiles like `.rogg`) get `.<index>` appended.
pub fn snapshot_path_for(path: &Path, index: u32) -> PathBuf {
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

/// Temp sibling used by `persist_service_config` for atomic rename.
fn tmp_write_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Sibling lockfile path: `<path>.lock`.
pub fn lock_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

/// XDG-compliant default path for `rogg.conf`:
/// `${XDG_CONFIG_HOME:-$HOME/.config}/rogg/rogg.conf`.
pub fn default_config_path() -> PathBuf {
    xdg_dir("XDG_CONFIG_HOME", ".config")
        .join("rogg")
        .join("rogg.conf")
}

/// XDG-compliant per-user state directory for rogg:
/// `${XDG_STATE_HOME:-$HOME/.local/state}/rogg`. Callers append a
/// tool-prefixed filename (e.g. `ggsh_history`).
pub fn user_state_dir() -> PathBuf {
    xdg_dir("XDG_STATE_HOME", ".local/state").join("rogg")
}

/// Per-user runtime directory for rogg state files (e.g. the daemon's
/// `bgpggd.json`). `${XDG_RUNTIME_DIR:-$HOME/.local/state}/rogg`. The
/// chosen directory is created with mode 0700 by `write_status`.
pub fn rogg_runtime_dir() -> PathBuf {
    xdg_dir("XDG_RUNTIME_DIR", ".local/state").join("rogg")
}

/// Which rogg daemon a status file belongs to. Each daemon publishes
/// its own runtime file under `rogg_runtime_dir()` so a single host
/// can run any combination without filename collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonKind {
    Bgp,
}

impl DaemonKind {
    pub fn filename(self) -> &'static str {
        match self {
            DaemonKind::Bgp => "bgpggd.json",
        }
    }
}

/// Daemon-published runtime info: written by the daemon after listeners
/// bind; read by ggsh and tooling for endpoint discovery. JSON schema is
/// intentionally minimal so additive fields don't break existing readers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusFile {
    pub grpc_addr: String,
}

/// Atomically write the status file under `dir`. Directory mode 0700,
/// file mode 0600 -- the file may name an internal management endpoint,
/// so it stays user-private. Callers pass `rogg_runtime_dir()` in
/// production; tests pass a tempdir.
pub fn write_status(dir: &Path, daemon: DaemonKind, status: &StatusFile) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

    let final_path = dir.join(daemon.filename());
    let tmp_path = dir.join(format!("{}.tmp", daemon.filename()));

    let json = serde_json::to_vec_pretty(status)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)?;
    file.write_all(&json)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

pub fn read_status(dir: &Path, daemon: DaemonKind) -> io::Result<StatusFile> {
    let bytes = fs::read(dir.join(daemon.filename()))?;
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Best-effort delete on graceful shutdown. Missing file is not an error.
pub fn remove_status(dir: &Path, daemon: DaemonKind) {
    let path = dir.join(daemon.filename());
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => tracing::debug!(path = %path.display(), error = %e, "remove_status failed"),
    }
}

fn xdg_dir(var: &str, fallback: &str) -> PathBuf {
    if let Some(v) = std::env::var_os(var) {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::BgpConfig;
    use crate::testutil::TempDir;
    use std::net::Ipv4Addr;

    #[test]
    fn status_file_round_trip() {
        let dir = TempDir::new().unwrap();
        let written = StatusFile {
            grpc_addr: "127.0.0.1:50123".into(),
        };
        write_status(dir.path(), DaemonKind::Bgp, &written).unwrap();
        assert_eq!(
            read_status(dir.path(), DaemonKind::Bgp).unwrap().grpc_addr,
            written.grpc_addr,
        );
    }

    /// Wraps `TempDir` with conveniences for the fs tests.
    struct TestDir(TempDir);

    impl TestDir {
        fn new() -> Self {
            Self(TempDir::new().unwrap())
        }

        fn conf_path(&self) -> PathBuf {
            self.0.path().join("rogg.conf")
        }

        fn touch(&self, name: &str, contents: &str) {
            fs::write(self.0.path().join(name), contents).unwrap();
        }

        fn exists(&self, name: &str) -> bool {
            self.0.path().join(name).exists()
        }

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.0.path().join(name)).unwrap()
        }
    }

    #[test]
    fn test_snapshot_path_for() {
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
        for i in 1..=10 {
            dir.touch(&format!("rogg.{}.conf", i), &format!("v{}", i));
        }
        rotate_snapshots(&dir.conf_path(), 10).unwrap();

        assert!(!dir.exists("rogg.1.conf"));
        for i in 2..=10 {
            assert_eq!(dir.read(&format!("rogg.{}.conf", i)), format!("v{}", i - 1));
        }
        assert!(!dir.exists("rogg.11.conf"));
    }

    #[test]
    fn test_rotate_snapshots_missing_entries() {
        let dir = TestDir::new();
        dir.touch("rogg.3.conf", "three");
        dir.touch("rogg.5.conf", "five");
        rotate_snapshots(&dir.conf_path(), 10).unwrap();

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

    #[test]
    fn test_persist_service_config_writes_and_rotates() {
        let dir = TestDir::new();
        let path = dir.conf_path();

        let cfg_v1 = BgpConfig::new(65001, "127.0.0.1:179", Ipv4Addr::new(1, 1, 1, 1), 90);
        let cfg_v2 = BgpConfig::new(65002, "127.0.0.1:179", Ipv4Addr::new(2, 2, 2, 2), 90);

        // First persist: no prior file, no rotation.
        persist_service_config(&path, Service::Bgp(cfg_v1.to_bgp_service_body())).unwrap();
        assert!(dir.read("rogg.conf").contains("65001"));
        assert!(!dir.exists("rogg.1.conf"));

        // Second persist: prior becomes .1.
        persist_service_config(&path, Service::Bgp(cfg_v2.to_bgp_service_body())).unwrap();
        assert!(dir.read("rogg.conf").contains("65002"));
        assert!(dir.read("rogg.1.conf").contains("65001"));
    }

    #[test]
    fn test_acquire_shared_lock_blocked_by_exclusive() {
        let dir = TestDir::new();
        let path = dir.conf_path();
        let exclusive = open_lock_file(&path).unwrap();
        exclusive.lock().unwrap();
        let err = acquire_shared_lock(&path).unwrap_err();
        assert!(err.contains("config locked"), "got: {}", err);
    }

    #[test]
    fn test_acquire_shared_lock_compatible_with_other_shared() {
        let dir = TestDir::new();
        let path = dir.conf_path();
        let _first = acquire_shared_lock(&path).expect("first SH");
        let _second = acquire_shared_lock(&path).expect("second SH (compatible)");
    }

    #[test]
    fn test_read_session_uuid() {
        type Expected = Result<Option<Uuid>, io::ErrorKind>;
        let written = Uuid::new_v4();
        let cases: [(&str, Option<&str>, Expected); 4] = [
            ("missing file", None, Ok(None)),
            ("empty file", Some(""), Ok(None)),
            ("valid uuid", Some(&written.to_string()), Ok(Some(written))),
            (
                "invalid content",
                Some("not-a-uuid"),
                Err(io::ErrorKind::InvalidData),
            ),
        ];
        for (name, content, expected) in cases {
            let dir = TestDir::new();
            if let Some(c) = content {
                dir.touch("rogg.conf.lock", c);
            }
            let result = read_session_uuid(&dir.conf_path());
            match (result, expected) {
                (Ok(got), Ok(want)) => assert_eq!(got, want, "{}", name),
                (Err(e), Err(want)) => assert_eq!(e.kind(), want, "{}", name),
                (got, want) => panic!("{}: got {:?}, want {:?}", name, got, want),
            }
        }
    }
}
