#!/bin/sh
set -e

# Setup optional labs root. When CLAB_LABS_ROOT is unset, the API server
# stores managed lab files in each authenticated user's ~/.clab directory.
if [ -n "${CLAB_LABS_ROOT:-}" ]; then
  echo "Setting up labs root: $CLAB_LABS_ROOT"
  mkdir -p "$CLAB_LABS_ROOT"
fi

# With host PID mode, PID 1 exposes the lab host's filesystem. Keep host-side
# Containerlab name resolution in sync in addition to this container's own
# Docker-managed /etc/hosts file.
if [ -z "${CLAB_HOSTS_FILE:-}" ] && [ -f /proc/1/root/etc/hosts ] && \
  ! [ /etc/hosts -ef /proc/1/root/etc/hosts ]; then
  export CLAB_HOSTS_FILE=/proc/1/root/etc/hosts
  echo "Using host hosts file: $CLAB_HOSTS_FILE"
fi

mkdir -p /var/run/netns

# Now execute the command passed to the container
echo "Executing command: $@"
exec "$@"
