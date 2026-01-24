#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building with musl target..."
cd ..
cargo build --release --target x86_64-unknown-linux-musl
cd docker

echo "Creating local tarball for docker build..."
mkdir -p bgpgg-dev-x86_64-linux
cp ../target/x86_64-unknown-linux-musl/release/bgpggd bgpgg-dev-x86_64-linux/
cp ../target/x86_64-unknown-linux-musl/release/bgpgg bgpgg-dev-x86_64-linux/
tar czf bgpgg-dev-x86_64-linux.tar.gz bgpgg-dev-x86_64-linux
rm -rf bgpgg-dev-x86_64-linux
echo "Created bgpgg-dev-x86_64-linux.tar.gz"
