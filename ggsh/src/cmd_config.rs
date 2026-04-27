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

use std::time::{SystemTime, UNIX_EPOCH};

use bgpgg::grpc::proto::ConfigSnapshot;
use bgpgg::grpc::BgpClient;

pub async fn show_history(client: &BgpClient) -> Result<(), Box<dyn std::error::Error>> {
    let snapshots = client.list_config_snapshots().await?;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    print!("{}", format_history(&snapshots, now_unix));
    Ok(())
}

fn format_history(snapshots: &[ConfigSnapshot], now_unix: u64) -> String {
    if snapshots.is_empty() {
        return "No config history yet.\n".to_string();
    }
    let mut out = String::new();
    out.push_str(&format!(
        "{:<8} {:>12} {:>12}\n",
        "Index", "Size", "Modified"
    ));
    for snap in snapshots {
        out.push_str(&format!(
            "{:<8} {:>12} {:>12}\n",
            snap.index,
            snap.size_bytes,
            format_relative(snap.mtime_unix, now_unix)
        ));
    }
    out
}

fn format_relative(mtime_unix: u64, now_unix: u64) -> String {
    if now_unix < mtime_unix {
        return "in future".to_string();
    }
    let delta = now_unix - mtime_unix;
    if delta < 60 {
        format!("{}s ago", delta)
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86400 {
        format!("{}h ago", delta / 3600)
    } else {
        format!("{}d ago", delta / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_relative_seconds() {
        assert_eq!(format_relative(100, 130), "30s ago");
    }

    #[test]
    fn format_relative_minutes() {
        assert_eq!(format_relative(0, 150), "2m ago");
    }

    #[test]
    fn format_relative_hours() {
        assert_eq!(format_relative(0, 7200), "2h ago");
    }

    #[test]
    fn format_relative_days() {
        assert_eq!(format_relative(0, 86400 * 3), "3d ago");
    }

    #[test]
    fn format_relative_future() {
        assert_eq!(format_relative(200, 100), "in future");
    }

    #[test]
    fn history_empty() {
        assert_eq!(format_history(&[], 1000), "No config history yet.\n");
    }

    #[test]
    fn history_populated() {
        let snapshots = vec![
            ConfigSnapshot {
                index: 1,
                mtime_unix: 970,
                size_bytes: 1234,
            },
            ConfigSnapshot {
                index: 2,
                mtime_unix: 600,
                size_bytes: 1100,
            },
        ];
        let out = format_history(&snapshots, 1000);
        assert!(out.contains("Index"));
        assert!(out.contains("1234"));
        assert!(out.contains("30s ago"));
        assert!(out.contains("6m ago"));
    }
}
