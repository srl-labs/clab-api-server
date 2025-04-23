#!/bin/sh
set -e

# Optional: Explicitly disable ip6tables if needed, though less likely required
# when installing docker-ce directly compared to some DIND base images.
# Uncomment if you still see hangs related to IPv6.
# export DOCKER_DEFAULT_IP6_TABLES=--ip6tables=false
# if [ -n "$DOCKER_DEFAULT_IP6_TABLES" ]; then
#   echo "INFO: Will attempt to start dockerd with ip6tables disabled."
#   # Note: This env var isn't directly used by dockerd itself,
#   # but we could modify the dockerd start command below if needed.
# fi

# Start the Docker daemon in the background
echo "Starting Docker daemon (dockerd)..."
LOG_FILE="/var/log/dockerd.log"
dockerd > "$LOG_FILE" 2>&1 &
DOCKERD_PID=$!

# Wait for the Docker daemon socket to appear
echo "Waiting for Docker daemon socket (/var/run/docker.sock)..."
attempts=0
max_attempts=45 # Wait for max 45 seconds
while [ ! -S /var/run/docker.sock ]; do
  # Check if the background dockerd script exited prematurely
  if ! kill -0 $DOCKERD_PID > /dev/null 2>&1; then
     echo "ERROR: Docker daemon (PID: $DOCKERD_PID) exited prematurely. Check logs:" >&2
     cat "$LOG_FILE" >&2
     exit 1
  fi
  if [ $attempts -ge $max_attempts ]; then
    echo "ERROR: Timeout - Docker socket /var/run/docker.sock did not appear after ${max_attempts} seconds." >&2
    echo "--- Last logs from ${LOG_FILE} ---" >&2
    tail -n 50 "$LOG_FILE" >&2
    echo "--- End logs ---" >&2
    exit 1
  fi
  attempts=$((attempts + 1))
  sleep 1
done
# Set permissions on the socket (often needed)
chmod 666 /var/run/docker.sock
echo "Docker socket found."

# Wait for the Docker daemon API to respond
echo "Waiting for Docker daemon API to respond..."
attempts=0
while ! docker info > /dev/null 2>&1; do
  # Check if the background dockerd script exited prematurely
  if ! kill -0 $DOCKERD_PID > /dev/null 2>&1; then
     echo "ERROR: Docker daemon (PID: $DOCKERD_PID) exited prematurely after socket creation. Check logs:" >&2
     cat "$LOG_FILE" >&2
     exit 1
  fi
  if [ $attempts -ge $max_attempts ]; then
    echo "ERROR: Timeout - Docker daemon did not respond after ${max_attempts} seconds." >&2
    echo "--- Last logs from ${LOG_FILE} ---" >&2
    tail -n 50 "$LOG_FILE" >&2
    echo "--- End logs ---" >&2
    exit 1
  fi
  attempts=$((attempts + 1))
  echo "Still waiting for Docker daemon API..."
  sleep 1
done
echo "Docker daemon is ready."

# Ensure required groups exist (best effort, useradd/groupadd might handle this too)
# These should match your .env settings
API_GROUP=${API_USER_GROUP:-clab_api} # Default if not set in env
ADMIN_GROUP=${SUPERUSER_GROUP:-clab_admins} # Default if not set in env
REQUIRED_LOGIN_GROUP="clab_admins" # Hardcoded in auth/credentials.go

echo "Ensuring internal groups exist: $REQUIRED_LOGIN_GROUP, $API_GROUP, $ADMIN_GROUP"
if ! getent group "$REQUIRED_LOGIN_GROUP" > /dev/null; then addgroup "$REQUIRED_LOGIN_GROUP"; echo "INFO: Created group $REQUIRED_LOGIN_GROUP"; fi
if ! getent group "$API_GROUP" > /dev/null; then addgroup "$API_GROUP"; echo "INFO: Created group $API_GROUP"; fi
if ! getent group "$ADMIN_GROUP" > /dev/null; then addgroup "$ADMIN_GROUP"; echo "INFO: Created group $ADMIN_GROUP"; fi

# Now execute the command passed to the container (e.g., clab-api-server)
echo "Executing command: $@"
exec "$@"