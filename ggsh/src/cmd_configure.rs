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

use crate::shell::{Shell, ShellMode};

pub fn enter_configure(shell: &mut Shell) -> Result<(), String> {
    if shell.mode == ShellMode::Configure {
        return Err("already in configure mode".into());
    }

    let session_lock = conf::fs::acquire_exclusive_lock(&shell.config_path, shell.session_uuid)?;

    let text = match std::fs::read_to_string(&shell.config_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "failed to read {}: {}",
                shell.config_path.display(),
                e
            ));
        }
    };

    let root = match conf::language::parse(&text) {
        Ok(r) => r,
        Err(e) => {
            drop(session_lock);
            let _ = std::fs::remove_file(conf::fs::lock_path_for(&shell.config_path));
            return Err(format!(
                "failed to parse {}: {}",
                shell.config_path.display(),
                e
            ));
        }
    };

    shell.candidate = Some(root);
    shell.session_lock = Some(session_lock);
    shell.mode = ShellMode::Configure;
    Ok(())
}

pub fn abort_configure(shell: &mut Shell) -> Result<(), String> {
    if shell.mode != ShellMode::Configure {
        return Err("not in configure mode".into());
    }
    shell.session_lock = None;
    let _ = std::fs::remove_file(conf::fs::lock_path_for(&shell.config_path));
    shell.candidate = None;
    shell.mode = ShellMode::Operational;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    use conf::fs::lock_path_for;
    use conf::testutil::TempDir;

    fn test_shell(config_path: PathBuf) -> Shell {
        Shell::new(HashMap::new(), None, config_path)
    }

    #[test]
    fn test_configure_lifecycle() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("rogg.conf");
        let lock_path = lock_path_for(&config_path);
        let mut shell = test_shell(config_path.clone());
        let uuid = shell.session_uuid;

        // Enter: state set, UUID in lock file.
        enter_configure(&mut shell).expect("enter");
        assert_eq!(shell.mode, ShellMode::Configure);
        assert!(shell.candidate.is_some());
        assert!(shell.session_lock.is_some());
        assert_eq!(
            std::fs::read_to_string(&lock_path).unwrap(),
            uuid.to_string()
        );

        // Abort: state cleared, lock file gone.
        abort_configure(&mut shell).expect("abort");
        assert_eq!(shell.mode, ShellMode::Operational);
        assert!(shell.candidate.is_none());
        assert!(shell.session_lock.is_none());
        assert!(!lock_path.exists());

        // Re-enter: same UUID (process-level identity).
        enter_configure(&mut shell).expect("re-enter");
        assert_eq!(
            std::fs::read_to_string(&lock_path).unwrap(),
            uuid.to_string()
        );
    }

    #[test]
    fn test_enter_fails_when_locked() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("rogg.conf");
        let _holder = conf::fs::acquire_exclusive_lock(&config_path, uuid::Uuid::new_v4()).unwrap();

        let mut shell = test_shell(config_path);
        let err = enter_configure(&mut shell).expect_err("should fail when locked");
        assert!(
            err.contains("another configure session is active"),
            "got: {}",
            err
        );
        assert_eq!(shell.mode, ShellMode::Operational);
    }

    #[test]
    fn test_abort_when_not_in_config_mode_errors() {
        let dir = TempDir::new().unwrap();
        let mut shell = test_shell(dir.path().join("rogg.conf"));
        let err = abort_configure(&mut shell).expect_err("abort outside config mode");
        assert!(err.contains("not in configure mode"));
    }

    /// Regression: a rejected enter must not truncate the held session's
    /// UUID. acquire_exclusive_lock truncates only after taking the flock.
    #[test]
    fn test_failed_enter_does_not_clobber_holders_uuid() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("rogg.conf");
        let lock_path = lock_path_for(&config_path);
        let holder_uuid = uuid::Uuid::new_v4();
        let _holder = conf::fs::acquire_exclusive_lock(&config_path, holder_uuid).unwrap();

        let mut shell_b = test_shell(config_path);
        enter_configure(&mut shell_b).expect_err("ggsh-B enter rejected");

        let content = std::fs::read_to_string(&lock_path).unwrap();
        assert_eq!(content, holder_uuid.to_string());
    }
}
