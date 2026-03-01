#!/usr/bin/env sh
# Setup FreeBSD for running tests.
# Run as root before running tests.
set -e

# Loopback aliases for tests (FreeBSD requires explicit aliases unlike Linux)
jot 19 2 | xargs -I{} ifconfig lo0 alias 127.0.0.{}

# TCP-MD5 support
kldload ipsec
kldload tcpmd5

# FreeBSD defaults to v6only=1, which prevents an IPv6 socket bound to ::
# from accepting IPv4 connections. Tests bind to :: and expect to accept
# IPv4 peers via v4-mapped addresses (e.g. ::ffff:127.0.0.1), so disable it.
sysctl net.inet6.ip6.v6only=0

# Clear any stale security associations
setkey -F
