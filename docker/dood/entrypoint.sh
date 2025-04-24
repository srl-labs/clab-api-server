#!/bin/sh
set -e

# Source common functions
. /usr/local/lib/user-persistence.sh

# Setup user persistence
setup_user_persistence

# Setup user groups
setup_user_groups

# Create labs symbolic links in user home directories
SHARED_LABS_DIR=${CLAB_SHARED_LABS_DIR:-/opt/containerlab/labs}
SHARED_USERS_DIR="${SHARED_LABS_DIR}/users"

echo "Setting up labs symbolic links in user home directories..."
mkdir -p "${SHARED_USERS_DIR}"

# Process each user in /home
for user_home in /home/*; do
  if [ -d "$user_home" ]; then
    username=$(basename "$user_home")
    user_labs_dir="${user_home}/labs"
    target_dir="${SHARED_USERS_DIR}/${username}"
    
    # Create user directory in shared labs if it doesn't exist
    mkdir -p "${target_dir}"
    chown "${username}:${username}" "${target_dir}"
    
    # Create symbolic link in user's home to the shared directory
    if [ ! -e "$user_labs_dir" ] || [ -L "$user_labs_dir" ]; then
      # Remove existing symlink if it exists
      [ -L "$user_labs_dir" ] && rm -f "$user_labs_dir"
      
      # Create the new symlink
      ln -sf "${target_dir}" "$user_labs_dir"
      chown -h "${username}:${username}" "$user_labs_dir"
      echo "Created symbolic link: $user_labs_dir -> ${target_dir}"
    fi
  fi
done

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