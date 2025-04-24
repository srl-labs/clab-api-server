#!/bin/sh
# Common user persistence functionality for both DinD and DooD setups

setup_user_persistence() {
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
}

# Setup required user groups
setup_user_groups() {
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
  for file in passwd shadow group gshadow subuid subgid; do
    if [ -f "/etc/${file}" ]; then
      cp -p "/etc/${file}" "/persistent-config/${file}"
      echo " -> Backed up ${file}"
    fi
  done
}