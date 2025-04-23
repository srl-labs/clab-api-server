#!/bin/sh
set -e

# --- BEGIN User Persistence with File Copy ---
PERSISTENT_CONFIG_DIR="/persistent-config"
ETC_FILES_TO_PERSIST="passwd shadow group gshadow subuid subgid"

echo "Setting up persistent user/group configuration in ${PERSISTENT_CONFIG_DIR}..."

# Create the target directory if it doesn't exist
mkdir -p "${PERSISTENT_CONFIG_DIR}"

# For each file we want to persist
for file in ${ETC_FILES_TO_PERSIST}; do
  persistent_file="${PERSISTENT_CONFIG_DIR}/${file}"
  etc_file="/etc/${file}"

  # If persistent file exists, restore it to /etc
  if [ -f "${persistent_file}" ]; then
    echo "Restoring ${etc_file} from ${persistent_file}..."
    cp -p "${persistent_file}" "${etc_file}"
    echo " -> Restored ${etc_file}"
  else
    # First run - back up the original to persistent storage
    echo "First run - backing up ${etc_file} to ${persistent_file}..."
    if [ -f "${etc_file}" ]; then
      cp -p "${etc_file}" "${persistent_file}"
      echo " -> Created initial ${persistent_file}"
    else
      echo " -> Warning: ${etc_file} doesn't exist, creating empty ${persistent_file}"
      touch "${persistent_file}"
    fi
  fi

  # Set correct permissions
  if [ "${file}" = "shadow" ] || [ "${file}" = "gshadow" ]; then
    chmod 600 "${persistent_file}"
    chmod 600 "${etc_file}"
  else
    chmod 644 "${persistent_file}"
    chmod 644 "${etc_file}"
  fi
done

# Set up background sync to periodically save changes
echo "Setting up background sync for user/group files..."
(
  while true; do
    sleep 5
    for file in ${ETC_FILES_TO_PERSIST}; do
      if [ -f "/etc/${file}" ]; then
        cp -p "/etc/${file}" "${PERSISTENT_CONFIG_DIR}/${file}" 2>/dev/null
      fi
    done
  done
) &
echo "Background sync started. Changes to /etc files will be saved to ${PERSISTENT_CONFIG_DIR}"

echo "User/group persistence setup complete."
# --- END User Persistence with File Copy ---

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

# Save the files again after group creation to make sure all changes are saved
echo "Backing up user/group files after group creation..."
for file in ${ETC_FILES_TO_PERSIST}; do
  if [ -f "/etc/${file}" ]; then
    cp -p "/etc/${file}" "${PERSISTENT_CONFIG_DIR}/${file}"
    echo " -> Backed up ${file}"
  fi
done

# Now execute the command passed to the container (e.g., clab-api-server)
echo "Executing command: $@"
exec "$@"