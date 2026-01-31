#!/usr/bin/env bash
# Smoke test: verify basic functionality

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
for i in $(seq 1 60); do
    if docker exec bgpgg-smoke-peer1 bgpgg --addr http://127.0.0.1:50051 peer list 2>/dev/null | grep -q Established; then
        echo "Peering established"
        break
    fi
    sleep 1
done

if ! docker exec bgpgg-smoke-peer1 bgpgg --addr http://127.0.0.1:50051 peer list 2>/dev/null | grep -q Established; then
    echo "Peering failed to establish"
    docker exec bgpgg-smoke-peer1 bgpgg --addr http://127.0.0.1:50051 peer list || true
    exit 1
fi

echo "Announcing route 10.99.0.0/24 from peer1..."
docker exec bgpgg-smoke-peer1 bgpgg --addr http://127.0.0.1:50051 global rib add 10.99.0.0/24 --nexthop 192.168.1.1

echo "Polling for route propagation to peer2 (10 seconds)..."
for i in $(seq 1 10); do
    if docker exec bgpgg-smoke-peer2 bgpgg --addr http://127.0.0.1:50051 global rib show 2>/dev/null | grep -q 10.99.0.0/24; then
        echo "Route propagated"
        echo "Smoke tests passed"
        exit 0
    fi
    sleep 1
done

echo "Route did not propagate"
docker exec bgpgg-smoke-peer2 bgpgg --addr http://127.0.0.1:50051 global rib show || true
exit 1
