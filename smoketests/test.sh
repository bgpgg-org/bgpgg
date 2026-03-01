#!/usr/bin/env bash
# Smoke test: start two bgpggd instances directly and verify basic BGP functionality.
# No Docker required; tests the native binary on the current platform.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BGPGGD="${BGPGGD:-$PROJECT_DIR/target/release/bgpggd}"
BGPGG="${BGPGG:-$PROJECT_DIR/target/release/bgpgg}"

PEER1_PID=
PEER2_PID=

cleanup() {
    [ -n "$PEER1_PID" ] && kill "$PEER1_PID" 2>/dev/null || true
    [ -n "$PEER2_PID" ] && kill "$PEER2_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

poll_until() {
    local desc=$1 timeout=$2
    shift 2
    for _ in $(seq 1 "$timeout"); do
        if eval "$*" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "Timed out: $desc"
    return 1
}

start_peers() {
    local p1_grpc=$1 p2_grpc=$2 p1_port=$3 p2_port=$4
    local p1_ip=127.0.0.1 p2_ip=127.0.0.2

    echo "Starting peer1 (ASN 65001, $p1_ip:$p1_port)..."
    "$BGPGGD" --asn 65001 --router-id 1.1.1.1 \
        --listen-addr "$p1_ip:$p1_port" \
        --grpc-listen-addr "${p1_grpc#http://}" &
    PEER1_PID=$!

    echo "Starting peer2 (ASN 65002, $p2_ip:$p2_port)..."
    "$BGPGGD" --asn 65002 --router-id 2.2.2.2 \
        --listen-addr "$p2_ip:$p2_port" \
        --grpc-listen-addr "${p2_grpc#http://}" &
    PEER2_PID=$!

    echo "Waiting for gRPC..."
    poll_until "peer1 gRPC not ready" 10 "$BGPGG --addr $p1_grpc peer list"
    poll_until "peer2 gRPC not ready" 10 "$BGPGG --addr $p2_grpc peer list"
}

stop_peers() {
    [ -n "$PEER1_PID" ] && kill "$PEER1_PID" 2>/dev/null || true
    [ -n "$PEER2_PID" ] && kill "$PEER2_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    PEER1_PID=
    PEER2_PID=
}

# --- Basic peering ---
echo "=== Basic peering ==="
P1_GRPC=http://127.0.0.1:50051
P2_GRPC=http://127.0.0.2:50052
start_peers "$P1_GRPC" "$P2_GRPC" 11179 11179

echo "Adding peers..."
"$BGPGG" --addr "$P1_GRPC" peer add 127.0.0.2 65002 --port 11179
"$BGPGG" --addr "$P2_GRPC" peer add 127.0.0.1 65001 --port 11179

echo "Waiting for BGP session to establish..."
poll_until "Peering failed to establish" 30 "$BGPGG --addr $P1_GRPC peer list | grep -q Established"
echo "  established"

echo "Announcing 10.99.0.0/24 from peer1..."
"$BGPGG" --addr "$P1_GRPC" global rib add 10.99.0.0/24 --nexthop 192.168.1.1

echo "Waiting for route to propagate to peer2..."
poll_until "Route did not propagate" 10 "$BGPGG --addr $P2_GRPC global rib show | grep -q 10.99.0.0/24"
echo "  propagated"

echo "Withdrawing 10.99.0.0/24 from peer1..."
"$BGPGG" --addr "$P1_GRPC" global rib del 10.99.0.0/24

echo "Waiting for route withdrawal on peer2..."
poll_until "Route withdrawal failed" 10 "! $BGPGG --addr $P2_GRPC global rib show | grep -q 10.99.0.0/24"
echo "  withdrawn"

stop_peers

# --- TCP MD5 ---
echo "=== TCP MD5 ==="
P1_GRPC=http://127.0.0.1:50061
P2_GRPC=http://127.0.0.2:50062
KEY_FILE=$(mktemp)
chmod 600 "$KEY_FILE"
echo -n "bgp-md5-smoke-key" > "$KEY_FILE"

start_peers "$P1_GRPC" "$P2_GRPC" 12179 12179

echo "Adding peers with MD5 key..."
"$BGPGG" --addr "$P1_GRPC" peer add 127.0.0.2 65002 --port 12179 --md5-key-file "$KEY_FILE"
"$BGPGG" --addr "$P2_GRPC" peer add 127.0.0.1 65001 --port 12179 --md5-key-file "$KEY_FILE"

echo "Waiting for BGP session to establish..."
poll_until "MD5 peering failed to establish" 30 "$BGPGG --addr $P1_GRPC peer list | grep -q Established"
echo "  established"

rm -f "$KEY_FILE"
stop_peers

echo "All smoke tests passed"
