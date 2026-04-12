#!/usr/bin/env bash
# ggsh system tests. No root required.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BGPGGD="${BGPGGD:-$PROJECT_DIR/target/release/bgpggd}"
BGPGG="${BGPGG:-$PROJECT_DIR/target/release/bgpgg}"
GGSH="${GGSH:-$PROJECT_DIR/target/release/ggsh}"

PEER1_PID=
PEER2_PID=
TMPDIR=$(mktemp -d)

cleanup() {
    [ -n "$PEER1_PID" ] && kill "$PEER1_PID" 2>/dev/null || true
    [ -n "$PEER2_PID" ] && kill "$PEER2_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    PEER1_PID=
    PEER2_PID=
    rm -rf "$TMPDIR"
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

P1_GRPC=http://127.0.0.1:50081
P2_GRPC=http://127.0.0.2:50082

cat > "$TMPDIR/peer1.conf" <<'EOF'
service bgp {
  asn 65001
  router-id 1.1.1.1
  listen-addr 127.0.0.1:14179
  grpc-listen-addr 127.0.0.1:50081
}
EOF

cat > "$TMPDIR/peer2.conf" <<'EOF'
service bgp {
  asn 65001
  router-id 2.2.2.2
  listen-addr 127.0.0.2:14179
  grpc-listen-addr 127.0.0.2:50082
}
EOF

echo "Starting peer1 (ASN 65001, 127.0.0.1:14179, router-id 1.1.1.1)..."
"$BGPGGD" --config "$TMPDIR/peer1.conf" &
PEER1_PID=$!

echo "Starting peer2 (ASN 65001, 127.0.0.2:14179, router-id 2.2.2.2)..."
"$BGPGGD" --config "$TMPDIR/peer2.conf" &
PEER2_PID=$!

echo "Waiting for gRPC..."
poll_until "peer1 gRPC not ready" 10 "$BGPGG --addr $P1_GRPC peer list"
poll_until "peer2 gRPC not ready" 10 "$BGPGG --addr $P2_GRPC peer list"

echo "Adding peers..."
"$BGPGG" --addr "$P1_GRPC" peer add 127.0.0.2 65001 --port 14179
"$BGPGG" --addr "$P2_GRPC" peer add 127.0.0.1 65001 --port 14179

echo "Waiting for session to establish..."
poll_until "Peering failed to establish" 30 "$BGPGG --addr $P1_GRPC peer list | grep -q Established"

echo "Announcing 10.99.0.0/24 from peer2..."
"$BGPGG" --addr "$P2_GRPC" global rib add 10.99.0.0/24 --nexthop 192.168.1.1

echo "Waiting for route to propagate..."
poll_until "Route did not propagate" 10 "$BGPGG --addr $P1_GRPC global rib show | grep -q 10.99.0.0/24"

# --- ggsh tests ---

echo ""
echo "=== ggsh one-shot: show bgp summary ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" show bgp summary)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "Established" || { echo "FAIL: expected Established in summary"; exit 1; }
echo "$OUTPUT" | grep -q "127.0.0.2" || { echo "FAIL: expected peer address in summary"; exit 1; }
echo "  ok"

echo "=== ggsh one-shot: show bgp routes ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" show bgp routes)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "10.99.0.0/24" || { echo "FAIL: expected route in routes"; exit 1; }
echo "  ok"

echo "=== ggsh one-shot: show bgp peers ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" show bgp peers)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "127.0.0.2" || { echo "FAIL: expected peer in peers list"; exit 1; }
echo "$OUTPUT" | grep -q "Established" || { echo "FAIL: expected Established in peers list"; exit 1; }
echo "  ok"

echo "=== ggsh one-shot: show bgp peers <addr> ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" show bgp peers 127.0.0.2)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "127.0.0.2" || { echo "FAIL: expected peer address in detail"; exit 1; }
echo "$OUTPUT" | grep -q "65001" || { echo "FAIL: expected ASN in peer detail"; exit 1; }
echo "  ok"

echo "=== ggsh one-shot: show version ==="
OUTPUT=$("$GGSH" show version)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "ggsh" || { echo "FAIL: expected ggsh in version"; exit 1; }
echo "  ok"

echo "=== ggsh piped mode ==="
OUTPUT=$(echo "show bgp summary" | "$GGSH" --bgpgg-addr "$P1_GRPC")
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "Established" || { echo "FAIL: expected Established in piped output"; exit 1; }
echo "  ok"

echo "=== ggsh stdin with multiple commands ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" <<'EOF'
show bgp summary
show bgp routes
exit
EOF
)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "Established" || { echo "FAIL: expected Established in stdin output"; exit 1; }
echo "$OUTPUT" | grep -q "10.99.0.0/24" || { echo "FAIL: expected route in stdin output"; exit 1; }
echo "  ok"

echo "=== ggsh incomplete command: show bgp ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" show bgp 2>&1 || true)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "summary" || { echo "FAIL: expected summary in subcommands"; exit 1; }
echo "$OUTPUT" | grep -q "peers" || { echo "FAIL: expected peers in subcommands"; exit 1; }
echo "$OUTPUT" | grep -q "routes" || { echo "FAIL: expected routes in subcommands"; exit 1; }
echo "  ok"

echo "=== ggsh interactive: error does not exit ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" <<'EOF'
show bogus
show bgp summary
exit
EOF
)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "Established" || { echo "FAIL: expected Established after error"; exit 1; }
echo "  ok"

echo "=== ggsh error: unknown command ==="
if "$GGSH" --bgpgg-addr "$P1_GRPC" show bogus 2>/dev/null; then
    echo "FAIL: expected non-zero exit for unknown command"
    exit 1
fi
echo "  ok"

cleanup
echo ""
echo "All ggsh system tests passed"
