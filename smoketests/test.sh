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
sleep 2

echo "Adding peers..."
docker compose -f basic.yml exec -T peer1 bgpgg peer add 172.30.0.20 65002
docker compose -f basic.yml exec -T peer2 bgpgg peer add 172.30.0.10 65001

echo "Polling for BGP peering (60 seconds)..."
for i in $(seq 1 60); do
    if docker compose -f basic.yml exec -T peer1 bgpgg peer list 2>/dev/null | grep -q Established; then
        echo "Peering established"
        break
    fi
    sleep 1
done

if ! docker compose -f basic.yml exec -T peer1 bgpgg peer list 2>/dev/null | grep -q Established; then
    echo "Peering failed to establish"
    docker compose -f basic.yml exec -T peer1 bgpgg peer list || true
    exit 1
fi

echo "Announcing routes 10.99.0.0/24 and 10.99.1.0/24 from peer1..."
docker compose -f basic.yml exec -T peer1 bgpgg global rib add 10.99.0.0/24 --nexthop 192.168.1.1
docker compose -f basic.yml exec -T peer1 bgpgg global rib add 10.99.1.0/24 --nexthop 192.168.1.1

echo "Polling for route propagation to peer2 (10 seconds)..."
for i in $(seq 1 10); do
    if docker compose -f basic.yml exec -T peer2 bgpgg global rib show 2>/dev/null | grep -q 10.99.0.0/24; then
        echo "Routes propagated"
        break
    fi
    sleep 1
done

if ! docker compose -f basic.yml exec -T peer2 bgpgg global rib show 2>/dev/null | grep -q 10.99.0.0/24; then
    echo "Route did not propagate"
    docker compose -f basic.yml exec -T peer2 bgpgg global rib show || true
    exit 1
fi

echo "Withdrawing route 10.99.0.0/24 from peer1..."
docker compose -f basic.yml exec -T peer1 bgpgg global rib del 10.99.0.0/24

echo "Polling for route withdrawal on peer2 (10 seconds)..."
for i in $(seq 1 10); do
    if ! docker compose -f basic.yml exec -T peer2 bgpgg global rib show 2>/dev/null | grep -q 10.99.0.0/24; then
        echo "Route withdrawn"
        echo "Smoke tests passed"
        exit 0
    fi
    sleep 1
done

echo "Route withdrawal failed"
docker compose -f basic.yml exec -T peer2 bgpgg global rib show || true
exit 1
