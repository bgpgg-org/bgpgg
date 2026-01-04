# bgpgg

A BGP router written in Rust, designed for speed and observability.

## Quick Start

```bash
# Build
make

# Run daemon
./target/release/bgpggd -c config.yaml

# Use CLI (in another terminal)
./target/release/bgpgg peer add 192.168.1.1:179
./target/release/bgpgg peer list
```

## Configuration

Edit `config.yaml`:

```yaml
asn: 65000                      # Your AS number
listen_addr: "127.0.0.1:1790"   # BGP listen address
router_id: "1.1.1.1"            # Router ID
grpc_listen_addr: "[::1]:50051" # gRPC API address
```

## Development

```bash
make        # Build
make test   # Run tests
make fmt    # Format code
```

## Structure

- `core` - Core BGP protocol implementation
- `daemon` - BGP daemon server
- `cli` - Command-line interface

## License

Apache-2.0
