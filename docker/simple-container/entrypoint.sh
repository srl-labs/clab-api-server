#!/bin/sh
set -e

# Setup required user groups
API_GROUP=${API_USER_GROUP:-clab_api}
ADMIN_GROUP=${SUPERUSER_GROUP:-clab_admins}
REQUIRED_LOGIN_GROUP="clab_admins"

# Setup labs directory
SHARED_LABS_DIR=${CLAB_SHARED_LABS_DIR:-/opt/containerlab/labs}
echo "Setting up labs directory: $SHARED_LABS_DIR"
mkdir -p "$SHARED_LABS_DIR"
mkdir -p "$SHARED_LABS_DIR/users"

# Check Docker socket access
echo "Checking access to Docker socket..."
if [ ! -S /var/run/docker.sock ]; then
  echo "ERROR: Docker socket /var/run/docker.sock not found. Make sure you've mounted it correctly." >&2
  exit 1
fi

if ! docker info > /dev/null 2>&1; then
  echo "ERROR: Cannot connect to Docker daemon. Check if socket has correct permissions and the container is privileged." >&2
  exit 1
fi
echo "Docker socket access verified."

# Now execute the command passed to the container
echo "Executing command: $@"
exec "$@"