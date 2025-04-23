#!/bin/sh
set -e

# --- BEGIN User Persistence Logic ---
PERSISTENT_CONFIG_DIR="/persistent-config"
ETC_FILES_TO_PERSIST="passwd shadow group gshadow subuid subgid" # Added subuid/subgid often needed with rootless/userns

echo "Checking for persistent user/group configuration in ${PERSISTENT_CONFIG_DIR}..."

# Create the target directory if it doesn't exist (should exist due to volume mount)
mkdir -p "${PERSISTENT_CONFIG_DIR}"

# Flag to check if any restoration happened
restored_files=false

for file in ${ETC_FILES_TO_PERSIST}; do
  persistent_file="${PERSISTENT_CONFIG_DIR}/${file}"
  target_file="/etc/${file}"

  if [ -f "${persistent_file}" ]; then
    echo "Restoring ${target_file} from ${persistent_file}..."
    # Copy with permissions, overwrite if exists
    if cp -p "${persistent_file}" "${target_file}"; then
      echo "Successfully restored ${target_file}."
      restored_files=true
    else
      echo "WARNING: Failed to restore ${target_file} from ${persistent_file}. Check permissions or file integrity." >&2
      # exit 1
    fi
  else
    echo "No persistent file found for ${file} at ${persistent_file}. Using container default."
    if [ ! -f "${PERSISTENT_CONFIG_DIR}/passwd" ]; then
       echo "First run detected (or persistent config missing). Backing up initial ${target_file} to ${persistent_file}..."
       if [ -f "${target_file}" ]; then # Ensure the source file exists before copying
           cp -p "${target_file}" "${persistent_file}"
       else
           echo "WARNING: Initial ${target_file} not found in image, cannot back up default." >&2
       fi
    fi
  fi
done

if [ "$restored_files" = true ]; then
  echo "User/group configuration restored from persistent volume."
else
  echo "Using default user/group configuration from image (or first run)."
fi
echo "User/group configuration check complete."
# --- END User Persistence Logic ---

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

API_GROUP=${API_USER_GROUP:-clab_api} # Default if not set in env
ADMIN_GROUP=${SUPERUSER_GROUP:-clab_admins} # Default if not set in env
REQUIRED_LOGIN_GROUP="clab_admins" # Hardcoded in auth/credentials.go

echo "Ensuring internal groups exist: $REQUIRED_LOGIN_GROUP, $API_GROUP, $ADMIN_GROUP"
# Use addgroup -g <gid> <groupname> if you need specific GIDs, otherwise just ensure they exist
if ! getent group "$REQUIRED_LOGIN_GROUP" > /dev/null; then addgroup --system "$REQUIRED_LOGIN_GROUP" || addgroup "$REQUIRED_LOGIN_GROUP" ; echo "INFO: Ensured group $REQUIRED_LOGIN_GROUP exists"; fi
if ! getent group "$API_GROUP" > /dev/null; then addgroup --system "$API_GROUP" || addgroup "$API_GROUP"; echo "INFO: Ensured group $API_GROUP exists"; fi
if ! getent group "$ADMIN_GROUP" > /dev/null; then addgroup --system "$ADMIN_GROUP" || addgroup "$ADMIN_GROUP"; echo "INFO: Ensured group $ADMIN_GROUP exists"; fi

# Now execute the command passed to the container (e.g., clab-api-server)
echo "Executing command: $@"
exec "$@"