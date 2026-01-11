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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl LogLevel {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "error" => Ok(LogLevel::Error),
            "warn" => Ok(LogLevel::Warn),
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            _ => Err(format!("Invalid log level: {}", s)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Logger {
    level: LogLevel,
}

impl Logger {
    pub fn new(level: LogLevel) -> Self {
        Logger { level }
    }

    #[inline]
    pub fn should_log(&self, level: LogLevel) -> bool {
        level <= self.level
    }
}

impl Default for Logger {
    fn default() -> Self {
        Logger::new(LogLevel::Info)
    }
}

#[macro_export]
macro_rules! info {
    ($logger:expr, $msg:expr) => {
        if $logger.should_log($crate::log::LogLevel::Info) {
            println!("{}", serde_json::json!({
                "timestamp": $crate::log::get_timestamp(),
                "level": "INFO",
                "message": $msg
            }));
        }
    };
    ($logger:expr, $msg:expr, $($key:tt => $val:expr),+ $(,)?) => {
        if $logger.should_log($crate::log::LogLevel::Info) {
            println!("{}", serde_json::json!({
                "timestamp": $crate::log::get_timestamp(),
                "level": "INFO",
                "message": $msg,
                $(
                    $key: $val
                ),+
            }));
        }
    };
}

#[macro_export]
macro_rules! warn {
    ($logger:expr, $msg:expr) => {
        if $logger.should_log($crate::log::LogLevel::Warn) {
            println!("{}", serde_json::json!({
                "timestamp": $crate::log::get_timestamp(),
                "level": "WARN",
                "message": $msg
            }));
        }
    };
    ($logger:expr, $msg:expr, $($key:tt => $val:expr),+ $(,)?) => {
        if $logger.should_log($crate::log::LogLevel::Warn) {
            println!("{}", serde_json::json!({
                "timestamp": $crate::log::get_timestamp(),
                "level": "WARN",
                "message": $msg,
                $(
                    $key: $val
                ),+
            }));
        }
    };
}

#[macro_export]
macro_rules! error {
    ($logger:expr, $msg:expr) => {
        if $logger.should_log($crate::log::LogLevel::Error) {
            eprintln!("{}", serde_json::json!({
                "timestamp": $crate::log::get_timestamp(),
                "level": "ERROR",
                "message": $msg
            }));
        }
    };
    ($logger:expr, $msg:expr, $($key:tt => $val:expr),+ $(,)?) => {
        if $logger.should_log($crate::log::LogLevel::Error) {
            eprintln!("{}", serde_json::json!({
                "timestamp": $crate::log::get_timestamp(),
                "level": "ERROR",
                "message": $msg,
                $(
                    $key: $val
                ),+
            }));
        }
    };
}

#[macro_export]
macro_rules! debug {
    ($logger:expr, $msg:expr) => {
        if $logger.should_log($crate::log::LogLevel::Debug) {
            println!("{}", serde_json::json!({
                "timestamp": $crate::log::get_timestamp(),
                "level": "DEBUG",
                "message": $msg
            }));
        }
    };
    ($logger:expr, $msg:expr, $($key:tt => $val:expr),+ $(,)?) => {
        if $logger.should_log($crate::log::LogLevel::Debug) {
            println!("{}", serde_json::json!({
                "timestamp": $crate::log::get_timestamp(),
                "level": "DEBUG",
                "message": $msg,
                $(
                    $key: $val
                ),+
            }));
        }
    };
}
