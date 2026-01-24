#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v0.1.0"
    exit 1
fi

# Install cross if not present
if ! command -v cross &> /dev/null; then
    echo "Installing cross..."
    cargo install cross --git https://github.com/cross-rs/cross
fi

# Clean to avoid glibc version conflicts between host and container
echo "Cleaning build artifacts..."
cargo clean

VERSION=$1
RELEASE_DIR="release/$VERSION"
mkdir -p "$RELEASE_DIR"

build_and_package() {
    local TARGET=$1
    local PLATFORM=$2

    echo "Building bgpgg $VERSION for $PLATFORM..."
    cross build --release --target "$TARGET"

    # Strip binaries (skip for FreeBSD)
    if [[ "$TARGET" != *"freebsd"* ]]; then
        strip "target/$TARGET/release/bgpggd" 2>/dev/null || true
        strip "target/$TARGET/release/bgpgg" 2>/dev/null || true
    fi

    # Package
    ARCHIVE_NAME="bgpgg-$VERSION-$PLATFORM"
    ARCHIVE_FILE="$RELEASE_DIR/$ARCHIVE_NAME.tar.gz"

    mkdir -p "$ARCHIVE_NAME"
    cp "target/$TARGET/release/bgpggd" "$ARCHIVE_NAME/"
    cp "target/$TARGET/release/bgpgg" "$ARCHIVE_NAME/"
    cp LICENSE "$ARCHIVE_NAME/" 2>/dev/null || true

    tar czf "$ARCHIVE_FILE" "$ARCHIVE_NAME"
    rm -rf "$ARCHIVE_NAME"

    echo "Created: $ARCHIVE_FILE"
}

# Build all platforms
build_and_package "x86_64-unknown-linux-musl" "x86_64-linux"
build_and_package "aarch64-unknown-linux-musl" "aarch64-linux"
build_and_package "x86_64-unknown-freebsd" "x86_64-freebsd"

echo ""
echo "All builds complete! Archives in release/$VERSION/"
