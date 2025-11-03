#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v0.1.0"
    exit 1
fi

VERSION=$1
RELEASE_DIR="release/$VERSION"

echo "Building bgpgg $VERSION..."

# Build release binaries
cargo build --release

# Create release directory
mkdir -p "$RELEASE_DIR"

# Create tar.gz archive
tar czf "$RELEASE_DIR/bgpgg-$VERSION-x86_64-linux.tar.gz" \
    -C target/release bgpggd bgpgg \
    -C ../.. LICENSE

echo "Done! Release archive: $RELEASE_DIR/bgpgg-$VERSION-x86_64-linux.tar.gz"
