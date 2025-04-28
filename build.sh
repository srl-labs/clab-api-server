#!/bin/bash

set -o errexit
set -o pipefail
set -e

# -----------------------------------------------------------------------------
# Environment variables
# -----------------------------------------------------------------------------
# Use git tag if available, otherwise use 'dev'
VERSION=$(git describe --tags 2>/dev/null || echo "dev")
# Get short commit hash
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
# Get current date in ISO 8601 format
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Output directory
DIST_DIR="dist"

# -----------------------------------------------------------------------------
# Build functions
# -----------------------------------------------------------------------------
function build-builder-image {
    echo "Building builder image..."
    docker build -t ghcr.io/srl-labs/clab-api-server/clab-api-builder:latest -f docker/build.dockerfile .
}

function build-with-builder-image {
    echo "Building clab-api-server using the builder image..."
    docker run --rm -i -t -v $(pwd):/app ghcr.io/srl-labs/clab-api-server/clab-api-builder:latest
}

function setup-env {
    echo "Setting up build environment..."
    mkdir -p "${DIST_DIR}"
}

# Build for local architecture
function build-local {
    setup-env
    echo "Building clab-api-server for local architecture..."
    CGO_ENABLED=1 go build -trimpath -ldflags "-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.date=${DATE}" \
        -o "${DIST_DIR}/clab-api-server" ./cmd/server

    echo "Build complete: ${DIST_DIR}/clab-api-server"
}

# Build for linux/amd64
function build-amd64 {
    setup-env
    echo "Building clab-api-server for linux/amd64..."
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.date=${DATE}" \
        -o "${DIST_DIR}/clab-api-server-linux-amd64" ./cmd/server

    echo "Build complete: ${DIST_DIR}/clab-api-server-linux-amd64"
}

# Build for linux/arm64 (requires cross-compilation tools)
function build-arm64 {
    setup-env
    # Check if aarch64-linux-gnu-gcc is available
    if ! command -v aarch64-linux-gnu-gcc &> /dev/null; then
        echo "Error: aarch64-linux-gnu-gcc not found. Install with:"
        echo "sudo apt-get install gcc-aarch64-linux-gnu"
        exit 1
    fi

    echo "Building clab-api-server for linux/arm64..."
    CC=aarch64-linux-gnu-gcc \
    CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
    go build -trimpath -ldflags "-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.date=${DATE}" \
        -o "${DIST_DIR}/clab-api-server-linux-arm64" ./cmd/server

    echo "Build complete: ${DIST_DIR}/clab-api-server-linux-arm64"
}

# Build for all architectures
function build-all {
    build-amd64
    build-arm64

    # Make binaries executable
    chmod +x ${DIST_DIR}/clab-api-server-linux-*

    echo "All builds completed successfully!"
}

# Clean build artifacts
function clean {
    echo "Cleaning build artifacts..."
    rm -rf "${DIST_DIR}"
    echo "Cleaned!"
}

# -----------------------------------------------------------------------------
# Bash runner functions.
# -----------------------------------------------------------------------------
function help {
  printf "%s <task> [args]\n\nTasks:\n" "${0}"

  compgen -A function | grep -v "^_" | cat -n

  printf "\nExtended help:\n"
  echo "  build-builder-image  - Build the Docker builder image"
  echo "  build-with-builder-image - Build using the Docker builder image"
  echo "  build-local          - Build for local architecture"
  echo "  build-amd64          - Build for linux/amd64"
  echo "  build-arm64          - Build for linux/arm64 (requires cross-tools)"
  echo "  build-all            - Build for all architectures"
  echo "  clean                - Clean build artifacts"
}

TIMEFORMAT=$'\nTask completed in %3lR'
time "${@:-help}"