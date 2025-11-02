// Copyright 2025 bgpgg Authors
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

use std::time::SystemTime;

pub fn get_timestamp() -> String {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            let nanos = duration.subsec_nanos();
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                1970 + secs / 31557600,
                ((secs % 31557600) / 2629800) + 1,
                ((secs % 2629800) / 86400) + 1,
                (secs % 86400) / 3600,
                (secs % 3600) / 60,
                secs % 60,
                nanos / 1_000_000
            )
        }
        Err(_) => "unknown".to_string(),
    }
}

#[macro_export]
macro_rules! info {
    ($msg:expr) => {
        println!("{}", serde_json::json!({
            "timestamp": $crate::log::get_timestamp(),
            "level": "INFO",
            "message": $msg
        }));
    };
    ($msg:expr, $($key:tt => $val:expr),+ $(,)?) => {
        println!("{}", serde_json::json!({
            "timestamp": $crate::log::get_timestamp(),
            "level": "INFO",
            "message": $msg,
            $(
                $key: $val
            ),+
        }));
    };
}

#[macro_export]
macro_rules! warn {
    ($msg:expr) => {
        println!("{}", serde_json::json!({
            "timestamp": $crate::log::get_timestamp(),
            "level": "WARN",
            "message": $msg
        }));
    };
    ($msg:expr, $($key:tt => $val:expr),+ $(,)?) => {
        println!("{}", serde_json::json!({
            "timestamp": $crate::log::get_timestamp(),
            "level": "WARN",
            "message": $msg,
            $(
                $key: $val
            ),+
        }));
    };
}

#[macro_export]
macro_rules! error {
    ($msg:expr) => {
        eprintln!("{}", serde_json::json!({
            "timestamp": $crate::log::get_timestamp(),
            "level": "ERROR",
            "message": $msg
        }));
    };
    ($msg:expr, $($key:tt => $val:expr),+ $(,)?) => {
        eprintln!("{}", serde_json::json!({
            "timestamp": $crate::log::get_timestamp(),
            "level": "ERROR",
            "message": $msg,
            $(
                $key: $val
            ),+
        }));
    };
}

#[macro_export]
macro_rules! debug {
    ($msg:expr) => {
        println!("{}", serde_json::json!({
            "timestamp": $crate::log::get_timestamp(),
            "level": "DEBUG",
            "message": $msg
        }));
    };
    ($msg:expr, $($key:tt => $val:expr),+ $(,)?) => {
        println!("{}", serde_json::json!({
            "timestamp": $crate::log::get_timestamp(),
            "level": "DEBUG",
            "message": $msg,
            $(
                $key: $val
            ),+
        }));
    };
}
