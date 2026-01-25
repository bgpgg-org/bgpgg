# bgpgg

A BGP router written in Rust, designed for speed and observability.

## Get Started

Download the [latest release](https://github.com/bgpgg-org/bgpgg/releases/latest) for your platform.

```bash
# Example for v0.2.0 on Linux x86_64
curl -LO https://github.com/bgpgg-org/bgpgg/releases/download/v0.2.0/bgpgg-v0.2.0-x86_64-linux.tar.gz
tar xzf bgpgg-v0.2.0-x86_64-linux.tar.gz
```

Create a config file:

```yaml
# config.yaml
asn: 65000
router_id: 1.1.1.1
listen_addr: "0.0.0.0:17900"  # (Optional) Use high port to avoid needing root
peers:
  - address: "192.168.1.1:17900"
    asn: 65001
```

Run it:

```bash
./bgpgg-v0.2.0-x86_64-linux/bgpggd -c config.yaml
./bgpgg-v0.2.0-x86_64-linux/bgpgg peer list
./bgpgg-v0.2.0-x86_64-linux/bgpgg global rib add 10.0.0.0/24 --nexthop 192.168.1.1
```

## Build from Source

```bash
make
./target/release/bgpggd -c config.yaml
./target/release/bgpgg peer list
```

## Try with Docker

Run two BGP speakers and watch them peer:

```bash
curl -LO https://raw.githubusercontent.com/bgpgg-org/bgpgg/master/docker/docker-compose.yml
docker compose up -d

# Check peering
docker exec bgpgg1 bgpgg peer list

# Add a route on speaker 1
docker exec bgpgg1 bgpgg global rib add 10.0.0.0/24 --nexthop 172.20.0.10

# See it on speaker 2
docker exec bgpgg2 bgpgg global rib show
```