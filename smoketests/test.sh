#!/usr/bin/env bash
# Smoke test: start two bgpggd instances directly and verify basic BGP functionality.
# No Docker required; tests the native binary on the current platform.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BGPGGD="${BGPGGD:-$PROJECT_DIR/target/release/bgpggd}"
BGPGG="${BGPGG:-$PROJECT_DIR/target/release/bgpgg}"

PEER1_IP=127.0.0.1
PEER2_IP=127.0.0.2
# Use high ports to avoid requiring root
PEER1_BGP_PORT=11179
PEER2_BGP_PORT=11179
PEER1_GRPC="http://$PEER1_IP:50051"
PEER2_GRPC="http://$PEER2_IP:50052"

PEER1_PID=
PEER2_PID=

peer1() { "$BGPGG" --addr "$PEER1_GRPC" "$@"; }
peer2() { "$BGPGG" --addr "$PEER2_GRPC" "$@"; }

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

echo "Starting peer1 (ASN 65001, $PEER1_IP:$PEER1_BGP_PORT)..."
"$BGPGGD" \
    --asn 65001 \
    --router-id 1.1.1.1 \
    --listen-addr "$PEER1_IP:$PEER1_BGP_PORT" \
    --grpc-listen-addr "$PEER1_IP:50051" &
PEER1_PID=$!

echo "Starting peer2 (ASN 65002, $PEER2_IP:$PEER2_BGP_PORT)..."
"$BGPGGD" \
    --asn 65002 \
    --router-id 2.2.2.2 \
    --listen-addr "$PEER2_IP:$PEER2_BGP_PORT" \
    --grpc-listen-addr "$PEER2_IP:50052" &
PEER2_PID=$!

echo "Waiting for gRPC..."
poll_until "peer1 gRPC not ready" 10 "peer1 peer list"
poll_until "peer2 gRPC not ready" 10 "peer2 peer list"

echo "Adding peers..."
peer1 peer add "$PEER2_IP" 65002 --port "$PEER2_BGP_PORT"
peer2 peer add "$PEER1_IP" 65001 --port "$PEER1_BGP_PORT"

echo "Waiting for BGP session to establish..."
poll_until "Peering failed to establish" 30 "peer1 peer list | grep -q Established"
echo "  established"

echo "Announcing 10.99.0.0/24 from peer1..."
peer1 global rib add 10.99.0.0/24 --nexthop 192.168.1.1

echo "Waiting for route to propagate to peer2..."
poll_until "Route did not propagate" 10 "peer2 global rib show | grep -q 10.99.0.0/24"
echo "  propagated"

echo "Withdrawing 10.99.0.0/24 from peer1..."
peer1 global rib del 10.99.0.0/24

echo "Waiting for route withdrawal on peer2..."
poll_until "Route withdrawal failed" 10 "! peer2 global rib show | grep -q 10.99.0.0/24"
echo "  withdrawn"

echo "Smoke tests passed"
