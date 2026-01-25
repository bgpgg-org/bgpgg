# bgpgg

A BGP router written in Rust, designed for speed and observability.

Supports Linux (x86_64, aarch64, armv7, i686) and FreeBSD (x86_64).

## Get Started

```bash
# Linux x86_64
curl -LO https://github.com/bgpgg-org/bgpgg/releases/latest/download/bgpgg-latest-x86_64-linux.tar.gz
tar xzf bgpgg-latest-x86_64-linux.tar.gz

# Available: x86_64-linux, aarch64-linux, armv7-linux, i686-linux, x86_64-freebsd
```

Create a config file:

```yaml
# config.yaml
asn: 65000
router_id: 1.1.1.1
peers:
  - address: "192.168.1.1:179"
    asn: 65001
```

Run it:

```bash
./bgpggd -c config.yaml &
./bgpgg peer list
./bgpgg route add 10.0.0.0/24 --next-hop 192.168.1.1
```

## Build from Source

```bash
make
./target/release/bgpggd -c config.yaml &
./target/release/bgpgg peer list
```

## Try with Docker

Run two BGP speakers and watch them peer:

```bash
curl -sSL https://raw.githubusercontent.com/bgpgg-org/bgpgg/main/docker/docker-compose.yml | docker compose -f - up -d

# Check peering
docker exec bgpgg1 bgpgg peer list

# Add a route on speaker 1
docker exec bgpgg1 bgpgg route add 10.0.0.0/24 --next-hop 172.20.0.10

# See it on speaker 2
docker exec bgpgg2 bgpgg route list
```