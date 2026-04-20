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
//! which diffs against the running config, applies the delta, and persists.

use super::BgpServer;
use crate::log::error;
use conf::bgp::BgpConfig;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Validate, apply, persist. Reverts runtime on failure.
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

    if let Err(apply_err) = reconfigure_all(server, &old_config, &new_config, bind_addr).await {
        if let Err(revert_err) =
            reconfigure_all(server, &new_config, &old_config, bind_addr).await
        {
            error!(
                apply_err = %apply_err,
                revert_err = %revert_err,
                "commit failed AND revert failed -- runtime state is indeterminate"
            );
        }
        return Err(apply_err);
    }

    if let Err(e) = persist_config(&server.config_path, &new_config) {
        error!(error = %e, "failed to persist rogg.conf after in-memory commit");
        return Err(format!("applied but failed to persist: {}", e));
    }

    server.config = new_config;

    Ok(())
}

/// Apply the new config to runtime by calling each subsystem's reconfigure in
/// sequence. The first failure aborts the rest and bubbles up; commit_config's
/// revert loop runs this same function with (old, new) swapped.
async fn reconfigure_all(
    server: &mut BgpServer,
    old: &BgpConfig,
    new: &BgpConfig,
    bind_addr: SocketAddr,
) -> Result<(), String> {
    server.reconfigure_peers(old, new, bind_addr).await?;
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

fn persist_config(path: &Path, config: &BgpConfig) -> io::Result<()> {
    let candidate = candidate_path_for(path);
    fs::write(&candidate, config.to_conf_str())?;
    fs::rename(&candidate, path)?;
    Ok(())
}

/// Path where ggsh stages its candidate config.
pub(crate) fn candidate_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".candidate");
    PathBuf::from(s)
}
