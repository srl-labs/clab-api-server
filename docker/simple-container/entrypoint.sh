#!/bin/sh
set -e

# Setup labs directory
SHARED_LABS_DIR=${CLAB_SHARED_LABS_DIR:-/opt/containerlab/labs}
echo "Setting up labs directory: $SHARED_LABS_DIR"
mkdir -p "$SHARED_LABS_DIR"
mkdir -p "$SHARED_LABS_DIR/users"

mkdir -p /var/run/netns

# Now execute the command passed to the container
echo "Executing command: $@"
exec "$@"