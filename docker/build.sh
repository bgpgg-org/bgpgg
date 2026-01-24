#!/usr/bin/env bash
# Build Docker image for bgpgg
#
# Usage:
# # builds for host platform (auto-detected)
# ./build.sh v0.1.0
#
# # builds arm64
# ./build.sh v0.1.0 linux/arm64
#
# # builds multiple platforms
# ./build.sh v0.1.0 "linux/amd64,linux/arm64"
set -eux

VERSION=$1

# Detect host platform if not specified
if [ -z "${2:-}" ]; then
  HOST_ARCH=$(uname -m)
  case "$HOST_ARCH" in
    x86_64)        PLATFORM="linux/amd64" ;;
    aarch64|arm64) PLATFORM="linux/arm64" ;;
    *)
      echo "Warning: Unsupported architecture: $HOST_ARCH, defaulting to linux/amd64"
      PLATFORM="linux/amd64"
      ;;
  esac
  echo "Auto-detected platform: $PLATFORM"
else
  PLATFORM=$2
fi

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
PROJECT_DIR="$SCRIPT_DIR/.."
RELEASE_DIR="$PROJECT_DIR/release/$VERSION"

# Verify release tarballs exist
if [ ! -f "$RELEASE_DIR/bgpgg-$VERSION-x86_64-linux.tar.gz" ] || \
   [ ! -f "$RELEASE_DIR/bgpgg-$VERSION-aarch64-linux.tar.gz" ] || \
   [ ! -f "$RELEASE_DIR/bgpgg-$VERSION-armv7-linux.tar.gz" ] || \
   [ ! -f "$RELEASE_DIR/bgpgg-$VERSION-i686-linux.tar.gz" ]; then
  echo "Error: Release tarballs not found in $RELEASE_DIR"
  echo "Run ./script/release.sh $VERSION first"
  exit 1
fi

# Create temporary build context
BUILD_CONTEXT=$(mktemp -d)
trap "rm -rf $BUILD_CONTEXT" EXIT

# Copy Dockerfile and Linux tarballs to build context
cp "$SCRIPT_DIR/Dockerfile" "$BUILD_CONTEXT/"
cp "$RELEASE_DIR/bgpgg-$VERSION-x86_64-linux.tar.gz" "$BUILD_CONTEXT/"
cp "$RELEASE_DIR/bgpgg-$VERSION-aarch64-linux.tar.gz" "$BUILD_CONTEXT/"
cp "$RELEASE_DIR/bgpgg-$VERSION-armv7-linux.tar.gz" "$BUILD_CONTEXT/"
cp "$RELEASE_DIR/bgpgg-$VERSION-i686-linux.tar.gz" "$BUILD_CONTEXT/"

# Count platforms (check for comma)
if [[ "$PLATFORM" == *","* ]]; then
  echo "Building for multiple platforms: $PLATFORM"

  # Check if multiarch builder exists, create if not
  if ! docker buildx ls | grep -q "multiarch"; then
    echo "Creating multiarch builder for multi-platform builds..."
    docker buildx create --name multiarch --use
    docker buildx inspect --bootstrap
  else
    echo "Using existing multiarch builder"
    docker buildx use multiarch
  fi
  echo ""

  docker buildx build \
    --platform "$PLATFORM" \
    -t bgpgg/bgpgg:"$VERSION" \
    -t bgpgg/bgpgg:latest \
    --build-arg VERSION="$VERSION" \
    "$BUILD_CONTEXT"

  # Switch back to default builder
  docker buildx use default
else
  echo "Building for single platform: $PLATFORM"
  echo "Image will be loaded to local Docker daemon"

  docker buildx build \
    --platform "$PLATFORM" \
    -t bgpgg/bgpgg:"$VERSION" \
    -t bgpgg/bgpgg:latest \
    --build-arg VERSION="$VERSION" \
    --load \
    "$BUILD_CONTEXT"
fi

echo ""
echo "Build complete!"
if [[ "$PLATFORM" != *","* ]]; then
  echo "Test with: docker run --rm bgpgg/bgpgg:$VERSION ./bgpggd --version"
fi
