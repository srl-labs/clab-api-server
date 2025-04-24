#!/bin/sh
set -e

# Source common functions
. /usr/local/lib/user-persistence.sh

# Setup user persistence
setup_user_persistence

# Setup user groups
setup_user_groups

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

# Dynamically detect and fix docker group GID to match the host
DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)
echo "INFO: Detected Docker socket GID: ${DOCKER_GID}"

# Update docker group with correct GID from socket
if getent group docker >/dev/null; then
  groupmod -g ${DOCKER_GID} docker
else
  groupadd -g ${DOCKER_GID} docker
fi

# Ensure API user is in docker group
usermod -aG docker ${API_USER:-admin}

# Fix permissions on Docker socket if needed
if [ "$(stat -c '%a' /var/run/docker.sock)" != "660" ]; then
  chmod 660 /var/run/docker.sock
fi

# Now execute the command passed to the container (e.g., clab-api-server)
echo "Executing command: $@"
exec "$@"