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

//! Subprocess harness for end-to-end ggsh tests. Spawns a real `bgpggd`
//! and shells out to a real `ggsh`, both pointed at an isolated tempdir.
//! State is verified via `bgpgg::grpc::BgpClient` and by re-parsing
//! `rogg.conf` from disk.

#![allow(dead_code)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bgpgg::grpc::BgpClient;
use conf::bgp::BgpConfig;
use conf::fs::{DaemonKind, StatusFile};
use conf::testutil::TempDir;
use uuid::Uuid;

/// Subprocess-based ggsh harness. Each `Rogg` owns one `bgpggd` child
/// plus a tempdir scoped to it: rogg.conf, runtime status file, history --
/// all live under the tempdir so parallel tests cannot trample each other.
pub struct Rogg {
    daemon: Child,
    _tempdir: TempDir,
    config_path: PathBuf,
    runtime_dir: PathBuf,
    state_dir: PathBuf,
    pub client: BgpClient,
}

/// EX-lock guard for imperative gRPC writes (commit/save/rollback).
/// The daemon verifies caller-supplied `uuid` against the lock file's
/// content; the guard's `Drop` releases the flock and removes the file
/// so the next test or session starts clean.
pub struct Session {
    pub uuid: Uuid,
    _lock: File,
    config_path: PathBuf,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(conf::fs::lock_path_for(&self.config_path));
    }
}

impl Rogg {
    /// Spawn `bgpggd` against a freshly seeded `rogg.conf`. The seed
    /// must contain `grpc-listen-addr 127.0.0.1:0` so the kernel picks
    /// a free port -- the harness reads the bound port from the
    /// daemon's runtime status file.
    pub async fn new(seed_conf: &str) -> Self {
        let tempdir = TempDir::new().expect("create harness tempdir");
        let config_path = tempdir.path().join("rogg.conf");
        std::fs::write(&config_path, seed_conf).expect("write seed rogg.conf");

        let runtime_dir = tempdir.path().join("runtime");
        let state_dir = tempdir.path().join("state");
        for dir in [&runtime_dir, &state_dir] {
            std::fs::create_dir_all(dir).expect("create harness scratch dir");
        }

        let bgpggd_bin = bgpggd_bin_path();
        let mut daemon = Command::new(&bgpggd_bin)
            .arg("--config")
            .arg(&config_path)
            .arg("--runtime-dir")
            .arg(&runtime_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {}", bgpggd_bin.display(), e));

        let url = match wait_for_status(&runtime_dir, &mut daemon, Duration::from_secs(10)) {
            Ok(s) => format!("http://{}", s.grpc_addr),
            Err(e) => {
                let _ = daemon.kill();
                panic!(
                    "daemon never published status under {}: {}",
                    runtime_dir.display(),
                    e
                );
            }
        };

        let client = match wait_for_grpc(&url, Duration::from_secs(10)).await {
            Ok(c) => c,
            Err(e) => {
                let _ = daemon.kill();
                panic!("gRPC at {} never accepted: {}", url, e);
            }
        };

        Rogg {
            daemon,
            _tempdir: tempdir,
            config_path,
            runtime_dir,
            state_dir,
            client,
        }
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Acquire the EX session lock for an imperative gRPC mutation. The
    /// returned guard cleans up on drop.
    pub fn session(&self) -> Session {
        let uuid = conf::fs::make_session_uuid();
        let lock =
            conf::fs::acquire_exclusive_lock(&self.config_path, uuid).expect("acquire EX lock");
        Session {
            uuid,
            _lock: lock,
            config_path: self.config_path.clone(),
        }
    }

    /// Pre-built `Command` with `--config` and `--runtime-dir` set.
    /// `--bgpgg-addr` is intentionally omitted so the run exercises the
    /// runtime-status autodiscovery path. `XDG_STATE_HOME` is scoped to
    /// the tempdir so each test gets its own ggsh history file.
    fn ggsh_command(&self) -> Command {
        let mut cmd = Command::new(ggsh_bin_path());
        cmd.arg("--config")
            .arg(&self.config_path)
            .arg("--runtime-dir")
            .arg(&self.runtime_dir)
            .env("XDG_STATE_HOME", &self.state_dir);
        cmd
    }

    /// Run `ggsh` with `stdin` text, close stdin, wait for exit. Asserts
    /// the process exited 0 and returns combined stdout+stderr -- per-line
    /// errors from the shell go to stderr but the process itself stays
    /// on the success exit code in piped mode.
    pub fn ggsh(&self, stdin: &str) -> String {
        let mut child = self
            .ggsh_command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ggsh");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(stdin.as_bytes())
            .expect("write ggsh stdin");
        drop(child.stdin.take());
        let out = child.wait_with_output().expect("wait ggsh");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        assert!(
            out.status.success(),
            "ggsh exited {}: {}",
            out.status,
            combined
        );
        combined
    }

    /// Run `ggsh` with one-shot subcommand args (e.g. `ggsh show bgp summary`).
    /// Asserts success; returns combined stdout+stderr.
    pub fn ggsh_cmd(&self, args: &[&str]) -> String {
        let out = self
            .ggsh_command()
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run ggsh subcommand");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        assert!(
            out.status.success(),
            "ggsh {:?} exited {}: {}",
            args,
            out.status,
            combined
        );
        combined
    }

    /// Spawn `ggsh` under a PTY for real interactive-mode testing.
    pub fn ggsh_pty(&self) -> (File, Child) {
        // `pty_fd` is what the test reads/writes; `tty_fd` is what the
        // child sees as its controlling terminal.
        let mut pty_fd: i32 = -1;
        let mut tty_fd: i32 = -1;
        // SAFETY: openpty writes the two fds out-params; nullable args
        // are passed as null per libc docs.
        let rc = unsafe {
            libc::openpty(
                &mut pty_fd,
                &mut tty_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());

        let pty = unsafe { File::from_raw_fd(pty_fd) };
        let tty = unsafe { OwnedFd::from_raw_fd(tty_fd) };
        let stdin = tty.try_clone().expect("dup tty for stdin");
        let stdout = tty.try_clone().expect("dup tty for stdout");
        let stderr = tty;

        let mut cmd = self.ggsh_command();
        cmd.stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // SAFETY: setsid/TIOCSCTTY are async-signal-safe and required
        // to make the slave the controlling terminal of the child.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = cmd.spawn().expect("spawn ggsh under pty");
        (pty, child)
    }

    /// Run a single command at the real interactive prompt and return the
    /// captured PTY output (rustyline echo + prompt + command output).
    pub fn ggsh_pty_run(&self, cmd: &str) -> String {
        let (mut pty, mut child) = self.ggsh_pty();
        let mut reader = pty.try_clone().expect("dup pty");
        let drain = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(n) = reader.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            buf
        });

        pty.write_all(cmd.as_bytes()).expect("write pty");
        pty.write_all(b"\n").expect("write newline");
        std::thread::sleep(Duration::from_millis(300));
        // Ctrl-D: rustyline returns Eof, run_interactive breaks the loop.
        pty.write_all(&[0x04]).expect("write EOF");
        drop(pty);

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();

        String::from_utf8_lossy(&drain.join().expect("drain thread")).into_owned()
    }

    /// Spawn `ggsh` with `stdin_prefix` written but not closed. Caller
    /// drives the child's stdin to keep configure mode open across
    /// concurrency tests.
    pub fn ggsh_spawn(&self, stdin_prefix: &str) -> Child {
        let mut child = self
            .ggsh_command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ggsh");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(stdin_prefix.as_bytes())
            .expect("write ggsh stdin prefix");
        child
    }

    /// Daemon's view via `GetRunningConfig`, parsed back into `BgpConfig`.
    pub async fn running_config(&self) -> BgpConfig {
        let text = self
            .client
            .get_running_config()
            .await
            .expect("get_running_config");
        BgpConfig::from_conf_str(&text).expect("parse running config")
    }

    /// On-disk `rogg.conf`, parsed.
    pub fn read_rogg_conf(&self) -> BgpConfig {
        let text = std::fs::read_to_string(&self.config_path).expect("read rogg.conf");
        BgpConfig::from_conf_str(&text).expect("parse rogg.conf")
    }
}

impl Drop for Rogg {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

fn bgpggd_bin_path() -> PathBuf {
    bin_path("BGPGGD_BIN", "bgpggd")
}

fn ggsh_bin_path() -> PathBuf {
    bin_path("GGSH_BIN", "ggsh")
}

/// Resolve a binary location: explicit env var first, then
/// `<workspace-target>/debug/<name>`. Falls through to `release` when
/// debug isn't built so `cargo test --release` still works.
fn bin_path(env_var: &str, name: &str) -> PathBuf {
    if let Some(p) = std::env::var_os(env_var) {
        return PathBuf::from(p);
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().expect("workspace root");
    for profile in ["debug", "release"] {
        let candidate = workspace.join("target").join(profile).join(name);
        if candidate.exists() {
            return candidate;
        }
    }
    panic!(
        "no {} binary; build it or set {}=path/to/{}",
        name, env_var, name
    );
}

/// Poll for the daemon's runtime status file. Aborts early if the
/// process exited (so test failures point at the daemon's stderr
/// rather than a 10-second hang).
/// Poll the daemon's runtime dir for the bgpggd status file.
fn wait_for_status(
    dir: &Path,
    daemon: &mut Child,
    timeout: Duration,
) -> Result<StatusFile, String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = daemon.try_wait().ok().flatten() {
            return Err(format!("daemon exited early: {}", status));
        }
        if let Ok(parsed) = conf::fs::read_status(dir, DaemonKind::Bgp) {
            return Ok(parsed);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err("status file never appeared".into())
}

async fn wait_for_grpc(url: &str, timeout: Duration) -> Result<BgpClient, String> {
    let deadline = Instant::now() + timeout;
    let mut last_err = "no attempt".to_string();
    while Instant::now() < deadline {
        match BgpClient::connect(url.to_string()).await {
            Ok(client) => match client.get_server_info().await {
                Ok(_) => return Ok(client),
                Err(e) => last_err = e.to_string(),
            },
            Err(e) => last_err = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(last_err)
}

/// Helper: poll an async predicate until it returns Ok or `timeout` lapses.
pub async fn poll_until_ok<F, Fut, T, E>(timeout: Duration, mut f: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let deadline = Instant::now() + timeout;
    let mut last: Option<E> = None;
    while Instant::now() < deadline {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(last.expect("polled at least once"))
}
