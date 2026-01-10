#!/bin/bash
# Copyright 2026 bgpgg Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

# Increase file descriptor limit for 1000+ connections
ulimit -n 10000

# Build all release binaries
cargo build --release

# Run benchmark, forward all arguments
exec cargo run --release --bin load_test -- "${@:-bgpgg}"
