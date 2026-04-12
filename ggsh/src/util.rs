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

pub fn parse_afi(arg: Option<&String>) -> Option<u32> {
    arg.and_then(|s| match s.to_lowercase().as_str() {
        "ipv4" => Some(1),
        "ipv6" => Some(2),
        "ls" => Some(16388),
        _ => None,
    })
}

pub fn parse_safi(arg: Option<&String>) -> Option<u32> {
    arg.and_then(|s| match s.to_lowercase().as_str() {
        "unicast" => Some(1),
        "multicast" => Some(2),
        _ => None,
    })
}
