#!/bin/bash
set -e

PROTOC_VERSION="25.1"
REQUIRED_VERSION="3.15.0"

# Check if protoc is installed and meets minimum version
if command -v protoc >/dev/null 2>&1; then
    CURRENT_VERSION=$(protoc --version | awk '{print $2}')

    # Compare versions (simplified: just check if >= 3.15)
    if printf '%s\n%s\n' "$REQUIRED_VERSION" "$CURRENT_VERSION" | sort -V -C; then
        exit 0
    else
        echo "protoc $CURRENT_VERSION found, but >= $REQUIRED_VERSION required"
    fi
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        PROTOC_ARCH="x86_64"
        ;;
    aarch64|arm64)
        PROTOC_ARCH="aarch_64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Detect OS
OS=$(uname -s)
case "$OS" in
    Linux)
        PROTOC_OS="linux"
        ;;
    Darwin)
        PROTOC_OS="osx"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

PROTOC_ZIP="protoc-${PROTOC_VERSION}-${PROTOC_OS}-${PROTOC_ARCH}.zip"
PROTOC_URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${PROTOC_ZIP}"

echo "Installing protoc ${PROTOC_VERSION}..."

# Create temporary directory
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

# Download and extract
cd "$TMP_DIR"
curl -LO "$PROTOC_URL"
unzip -q "$PROTOC_ZIP"

# Install to /usr/local (requires sudo on most systems)
NEED_SUDO=false
if [ ! -w /usr/local/bin ]; then
    NEED_SUDO=true
elif [ -e /usr/local/include ] && [ ! -w /usr/local/include ]; then
    NEED_SUDO=true
elif [ ! -e /usr/local/include ] && [ ! -w /usr/local ]; then
    NEED_SUDO=true
fi

if [ "$NEED_SUDO" = true ]; then
    sudo mkdir -p /usr/local/include
    sudo cp bin/protoc /usr/local/bin/
    sudo cp -r include/google /usr/local/include/
else
    mkdir -p /usr/local/include
    cp bin/protoc /usr/local/bin/
    cp -r include/google /usr/local/include/
fi

# Verify installation
protoc --version
echo "protoc ${PROTOC_VERSION} installed successfully"
