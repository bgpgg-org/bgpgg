#!/usr/bin/env sh
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

# Setup FreeBSD for running tests.
# Run as root before running tests.

set -e

# Loopback aliases for tests (FreeBSD requires explicit aliases unlike Linux)
jot 19 2 | xargs -I{} ifconfig lo0 alias 127.0.0.{}

# TCP-MD5 support
kldload ipsec
kldload tcpmd5

# Disable IPv6 dual-stack binding issues
sysctl net.inet6.ip6.v6only=0

# Clear any stale security associations
setkey -F
