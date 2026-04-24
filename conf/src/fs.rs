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
//! with snapshot rotation, sibling-lockfile coordination, snapshot
//! enumeration, snapshot loading.
//!
//! `persist_config` is the single write entry point. It locks the file
//! against concurrent writers (multi-daemon: bgpgg vs ospfgg etc.), reads
//! the existing rogg.conf, replaces the caller-supplied service slice,
//! and atomically writes the merged result.

use crate::language::{self, Root, Service};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Number of historical config snapshots kept on disk.
pub const SNAPSHOT_COUNT: u32 = 10;

/// Metadata about a stored snapshot.
pub struct SnapshotInfo {
    pub index: u32,
    pub mtime_unix: u64,
    pub size_bytes: u64,
}

/// Exclusive advisory lock on rogg.conf's sibling `.lock` file. Held for
/// the duration of a daemon's read-modify-write so multi-daemon writes
/// don't clobber each other's slices. Released on Drop.
pub struct FileLock {
    _file: File,
}

impl FileLock {
    pub fn acquire(path: &Path) -> io::Result<Self> {
        let lock_path = lock_path_for(path);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        file.lock()?;
        Ok(Self { _file: file })
    }
}

/// Persist `service` into `path` as the new value for its slot. Reads
/// the existing rogg.conf under an exclusive lock, replaces the
/// matching service block (or appends if absent), rotates the prior
/// version into `.1`, and atomically writes the merged result.
pub fn persist_service_config(path: &Path, service: Service) -> io::Result<()> {
    let _lock = FileLock::acquire(path)?;
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

/// Sibling lockfile used by `FileLock`.
fn lock_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::BgpConfig;
    use crate::testutil::TempDir;
    use std::net::Ipv4Addr;

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
}
