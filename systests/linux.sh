#!/usr/bin/env bash
# Linux-specific system tests. Requires root (uses network namespaces).

set -euo pipefail

if [ "$(uname)" != "Linux" ]; then
    echo "Error: Linux-only tests"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: requires root (run with sudo)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BGPGGD="${BGPGGD:-$PROJECT_DIR/target/release/bgpggd}"
BGPGG="${BGPGG:-$PROJECT_DIR/target/release/bgpgg}"

PEER1_PID=
PEER2_PID=
NS1=bgpgg-test-ns1
NS2=bgpgg-test-ns2
VETH1=bgpgg-v1
VETH2=bgpgg-v2

cleanup() {
    [ -n "$PEER1_PID" ] && kill "$PEER1_PID" 2>/dev/null || true
    [ -n "$PEER2_PID" ] && kill "$PEER2_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    PEER1_PID=
    PEER2_PID=
    ip netns del "$NS1" 2>/dev/null || true
    ip netns del "$NS2" 2>/dev/null || true
    ip link del "$VETH1" 2>/dev/null || true
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

test_link_local_peering() {
    echo "=== Link-local IPv6 peering ==="
    local p1_grpc=http://127.0.0.1:50071
    local p2_grpc=http://127.0.0.2:50072

    # Create namespaces and veth pair
    ip netns add "$NS1"
    ip netns add "$NS2"
    ip link add "$VETH1" type veth peer name "$VETH2"
    ip link set "$VETH1" netns "$NS1"
    ip link set "$VETH2" netns "$NS2"
    ip netns exec "$NS1" ip link set "$VETH1" up
    ip netns exec "$NS2" ip link set "$VETH2" up
    ip netns exec "$NS1" ip link set lo up
    ip netns exec "$NS2" ip link set lo up

    # Wait for link-local addresses to be assigned
    sleep 2
    local ll1 ll2
    ll1=$(ip netns exec "$NS1" ip -6 addr show dev "$VETH1" scope link | grep -oP 'fe80::\S+' | head -1 | cut -d/ -f1)
    ll2=$(ip netns exec "$NS2" ip -6 addr show dev "$VETH2" scope link | grep -oP 'fe80::\S+' | head -1 | cut -d/ -f1)

    echo "  NS1 link-local: $ll1 on $VETH1"
    echo "  NS2 link-local: $ll2 on $VETH2"

    # Start bgpggd in each namespace
    echo "Starting peer1 in $NS1..."
    ip netns exec "$NS1" "$BGPGGD" --asn 65001 --router-id 1.1.1.1 \
        --listen-addr "[::]:13179" \
        --grpc-listen-addr "127.0.0.1:50071" &
    PEER1_PID=$!

    echo "Starting peer2 in $NS2..."
    ip netns exec "$NS2" "$BGPGGD" --asn 65001 --router-id 2.2.2.2 \
        --listen-addr "[::]:13179" \
        --grpc-listen-addr "127.0.0.2:50072" &
    PEER2_PID=$!

    echo "Waiting for gRPC..."
    poll_until "peer1 gRPC not ready" 10 "ip netns exec $NS1 $BGPGG --addr $p1_grpc peer list"
    poll_until "peer2 gRPC not ready" 10 "ip netns exec $NS2 $BGPGG --addr $p2_grpc peer list"

    echo "Adding peers with link-local addresses..."
    ip netns exec "$NS1" "$BGPGG" --addr "$p1_grpc" peer add "$ll2" 65001 --port 13179 --interface "$VETH1"
    ip netns exec "$NS2" "$BGPGG" --addr "$p2_grpc" peer add "$ll1" 65001 --port 13179 --interface "$VETH2"

    echo "Waiting for BGP session to establish..."
    poll_until "Link-local peering failed to establish" 30 \
        "ip netns exec $NS1 $BGPGG --addr $p1_grpc peer list | grep -q Established"
    echo "  established"

    echo "Announcing route over link-local session..."
    ip netns exec "$NS1" "$BGPGG" --addr "$p1_grpc" global rib add 10.99.0.0/24 --nexthop 192.168.1.1
    poll_until "Route did not propagate over link-local" 10 \
        "ip netns exec $NS2 $BGPGG --addr $p2_grpc global rib show | grep -q 10.99.0.0/24"
    echo "  propagated"

    cleanup
}

test_link_local_peering

echo "All Linux system tests passed"
