#!/usr/bin/env bash
# Smoke test: Verify two bgpgg instances can peer

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

cleanup() {
    echo ""
    echo "Cleaning up..."
    docker compose -f basic.yml down -v 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "Starting containers..."
docker compose -f basic.yml up -d

echo "Waiting for containers to be healthy..."
timeout 30s bash -c 'until [ "$(docker inspect --format="{{.State.Health.Status}}" bgpgg-smoke-peer1)" = "healthy" ]; do sleep 1; done'
timeout 30s bash -c 'until [ "$(docker inspect --format="{{.State.Health.Status}}" bgpgg-smoke-peer2)" = "healthy" ]; do sleep 1; done'

echo "Polling for BGP peering (60 seconds)..."
for i in {1..60}; do
    if docker exec bgpgg-smoke-peer1 bgpgg --addr http://127.0.0.1:50051 peer list 2>/dev/null | grep -q "Established"; then
        echo "✓ Peering established!"
        exit 0
    fi
    sleep 1
done

echo "Peering failed to establish"
docker exec bgpgg-smoke-peer1 bgpgg --addr http://127.0.0.1:50051 peer list || true
exit 1
