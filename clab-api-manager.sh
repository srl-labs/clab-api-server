#!/bin/bash
#
# clab-api-manager.sh - Management script for Containerlab API service
#
# This script helps manage the Containerlab API service (both DinD and DooD),
# including starting/stopping the service, creating backups, and restoring from backups.

# --- Configuration ---
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="${BASE_DIR}/docker"
DIND_COMPOSE_FILE="${DOCKER_DIR}/dind/docker-compose.yml"
DOOD_COMPOSE_FILE="${DOCKER_DIR}/dood/docker-compose.yml"
TEMP_CONTAINER_IMAGE="debian:bookworm-slim"

# --- Default Implementation ---
DEFAULT_IMPL="dood"  # Set to "dind" if you prefer that as default

# --- Container and Volume Names ---
DIND_CONTAINER="clab-api-dind"
DOOD_CONTAINER="clab-api-dood"
DIND_CONFIG_VOLUME="clab-api-config-data"
DIND_HOME_VOLUME="clab-api-home-data"
DOOD_CONFIG_VOLUME="clab-api-config-data"
DOOD_HOME_VOLUME="clab-api-home-data"
BACKUP_FILENAME_PREFIX="clab-api-volumes-backup"

# --- Helper Functions ---
usage() {
  echo "Usage: $0 [dind|dood] <command> [arguments]"
  echo ""
  echo "Manages the Containerlab API Docker service (DinD or DooD implementation)."
  echo ""
  echo "Implementation (optional, defaults to $DEFAULT_IMPL):"
  echo "  dind           Use the Docker-in-Docker implementation"
  echo "  dood           Use the Docker-out-of-Docker implementation"
  echo ""
  echo "Commands:"
  echo "  start          Starts the service"
  echo "  stop           Stops the service"
  echo "  restart        Restarts the service"
  echo "  backup         Creates backup (.tar.gz) of config & home volumes"
  echo "  restore <file> Restores volumes from the specified backup file"
  echo "                 WARNING: Service must be stopped. Volume data will be ERASED."
  echo "  status         Shows service status"
  echo "  logs [-f]      Shows service logs"
  echo "  help, -h       Shows this help message"
}

is_container_running() {
  local container_name="$1"
  docker ps -f name="^/${container_name}$" --format '{{.Names}}' | grep -q "${container_name}"
}

# --- Determine Docker Compose Command ---
detect_compose_cmd() {
  if command -v docker compose &> /dev/null; then
    echo "docker compose"
  elif command -v docker-compose &> /dev/null; then
    echo "docker-compose"
  else
    echo "ERROR: Neither 'docker compose' nor 'docker-compose' command found." >&2
    exit 1
  fi
}

COMPOSE_CMD=$(detect_compose_cmd)
echo "INFO: Using compose command: '$COMPOSE_CMD'"

# --- Parse Arguments for Implementation ---
IMPL="$DEFAULT_IMPL"
if [[ "$1" == "dind" || "$1" == "dood" ]]; then
  IMPL="$1"
  shift
fi

# --- Set Variables Based on Implementation ---
if [ "$IMPL" == "dind" ]; then
  COMPOSE_FILE="$DIND_COMPOSE_FILE"
  CONTAINER_NAME="$DIND_CONTAINER"
  ACTUAL_CONFIG_VOLUME="dind_${DIND_CONFIG_VOLUME}"
  ACTUAL_HOME_VOLUME="dind_${DIND_HOME_VOLUME}"
  PROJECT_NAME="dind"
else  # dood is default
  COMPOSE_FILE="$DOOD_COMPOSE_FILE"
  CONTAINER_NAME="$DOOD_CONTAINER"
  ACTUAL_CONFIG_VOLUME="dood_${DOOD_CONFIG_VOLUME}"
  ACTUAL_HOME_VOLUME="dood_${DOOD_HOME_VOLUME}"
  PROJECT_NAME="dood"
fi

# --- Check if Compose File Exists ---
if [ ! -f "$COMPOSE_FILE" ]; then
  echo "ERROR: Docker Compose file not found at '$COMPOSE_FILE'."
  exit 1
fi

# --- Define Compose Arguments ---
COMPOSE_ARGS="-p ${PROJECT_NAME} -f ${COMPOSE_FILE}"

# --- Service Commands ---
start_service() {
  echo "INFO: Starting clab-api service ($IMPL implementation)..."
  if $COMPOSE_CMD $COMPOSE_ARGS up -d --remove-orphans; then
    echo "INFO: Service started successfully."
    $COMPOSE_CMD $COMPOSE_ARGS ps
  else
    echo "ERROR: Failed to start service."
    exit 1
  fi
}

stop_service() {
  echo "INFO: Stopping clab-api service ($IMPL implementation)..."
  if $COMPOSE_CMD $COMPOSE_ARGS down --remove-orphans; then
    echo "INFO: Service stopped successfully."
  else
    echo "WARN: Service stop command did not complete successfully."
  fi
}

restart_service() {
  echo "INFO: Restarting clab-api service ($IMPL implementation)..."
  stop_service
  sleep 2
  start_service
}

backup_volumes() {
  local timestamp=$(date +"%Y%m%d-%H%M%S")
  local backup_filename="${BACKUP_FILENAME_PREFIX}-${IMPL}-${timestamp}.tar.gz"
  local current_dir=$(pwd)

  echo "INFO: Starting backup of persistent volumes ($IMPL implementation)..."
  echo "      Config Volume: $ACTUAL_CONFIG_VOLUME"
  echo "      Home Volume:   $ACTUAL_HOME_VOLUME"
  echo "INFO: Backup target file: ${current_dir}/${backup_filename}"

  if ! docker volume inspect "$ACTUAL_CONFIG_VOLUME" > /dev/null 2>&1; then
    echo "ERROR: Config volume '$ACTUAL_CONFIG_VOLUME' not found."
    exit 1
  fi

  if ! docker volume inspect "$ACTUAL_HOME_VOLUME" > /dev/null 2>&1; then
    echo "ERROR: Home volume '$ACTUAL_HOME_VOLUME' not found."
    exit 1
  fi

  echo "INFO: Running temporary container to create backup..."
  if docker run --rm \
       -v "${ACTUAL_CONFIG_VOLUME}:/volume_config:ro" \
       -v "${ACTUAL_HOME_VOLUME}:/volume_home:ro" \
       -v "${current_dir}:/backup_target" \
       "$TEMP_CONTAINER_IMAGE" \
       bash -c "mkdir -p /tmp/backup-work && \
                tar -C /volume_config -cf /tmp/backup-work/config.tar . && \
                tar -C /volume_home -cf /tmp/backup-work/home.tar . && \
                cd /tmp/backup-work && \
                tar -czf /backup_target/${backup_filename} config.tar home.tar"; then
    echo "INFO: Backup created successfully: ${current_dir}/${backup_filename}"
  else
    echo "ERROR: Failed to create backup tarball."
    rm -f "${current_dir}/${backup_filename}"
    exit 1
  fi
}

restore_volumes() {
  local backup_file="$1"
  local current_dir=$(pwd)
  local backup_filepath

  if [[ "$backup_file" == /* ]]; then
    backup_filepath="$backup_file"
  else
    backup_filepath="${current_dir}/${backup_file}"
  fi

  local backup_basename=$(basename "$backup_filepath")
  local backup_dirname=$(dirname "$backup_filepath")

  echo "INFO: Starting restore process for $IMPL implementation:"
  echo "      File Source: $backup_filepath"
  echo "      Config Volume Target: $ACTUAL_CONFIG_VOLUME"
  echo "      Home Volume Target: $ACTUAL_HOME_VOLUME"

  # --- Basic Checks ---
  if [ ! -f "$backup_filepath" ]; then
    echo "ERROR: Backup file not found: '$backup_filepath'"
    exit 1
  fi

  if is_container_running "$CONTAINER_NAME"; then
    echo "ERROR: Container '$CONTAINER_NAME' is running."
    echo "       Stop the service first: '$0 $IMPL stop'"
    exit 1
  fi

  if ! docker volume inspect "$ACTUAL_CONFIG_VOLUME" > /dev/null 2>&1; then
    echo "ERROR: Target config volume '$ACTUAL_CONFIG_VOLUME' does not exist."
    exit 1
  fi

  if ! docker volume inspect "$ACTUAL_HOME_VOLUME" > /dev/null 2>&1; then
    echo "ERROR: Target home volume '$ACTUAL_HOME_VOLUME' does not exist."
    exit 1
  fi

  # --- Check Archive Structure ---
  echo "INFO: Checking backup archive structure..."
  if ! tar tzf "$backup_filepath" | grep -q 'config.tar'; then
    echo "ERROR: Backup archive '$backup_basename' doesn't contain required files."
    exit 1
  fi

  # --- Confirmation ---
  echo ""
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  echo "This operation will ERASE ALL CURRENT DATA in the following volumes:"
  echo "  - $ACTUAL_CONFIG_VOLUME"
  echo "  - $ACTUAL_HOME_VOLUME"
  echo "And replace it with the contents from the backup file '$backup_basename'."
  echo "This action CANNOT be undone."
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  read -p "Are you absolutely sure you want to proceed? [y/N] " -n 1 -r
  echo

  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Restore cancelled."
    exit 1
  fi

  # --- Perform Restore ---
  echo "INFO: Running temporary container to perform restore..."
  docker run --rm \
     -v "${ACTUAL_CONFIG_VOLUME}:/volume_config" \
     -v "${ACTUAL_HOME_VOLUME}:/volume_home" \
     -v "${backup_dirname}:/backup_source:ro" \
     "$TEMP_CONTAINER_IMAGE" \
     bash -c " \
          mkdir -p /tmp/restore-work && \
          cd /tmp/restore-work && \
          echo '---> Extracting archive components...' && \
          tar xzf '/backup_source/${backup_basename}' && \

          echo '---> Clearing existing config volume contents...' && \
          find /volume_config/ -mindepth 1 -delete && \
          echo '---> Restoring config volume from config.tar...' && \
          tar -C /volume_config -xf config.tar && \
          echo '---> Config volume restore complete.' && \

          echo '---> Clearing existing home volume contents...' && \
          find /volume_home/ -mindepth 1 -delete && \
          echo '---> Restoring home volume from home.tar...' && \
          tar -C /volume_home -xf home.tar && \
          echo '---> Home volume restore complete.' \
     "

  if [ $? -eq 0 ]; then
    echo "INFO: Restore completed successfully."
    echo "      You can now start the service: '$0 $IMPL start'"
  else
    echo "ERROR: Failed to restore volumes."
    echo "       Volume contents might be in an inconsistent state."
    exit 1
  fi
}

show_status() {
  echo "INFO: Checking status of clab-api service ($IMPL implementation)..."
  $COMPOSE_CMD $COMPOSE_ARGS ps
}

show_logs() {
  local follow_flag=""
  if [ "$1" == "-f" ]; then
    follow_flag="-f"
    echo "INFO: Following logs ($IMPL implementation, Ctrl+C to stop)..."
  else
    echo "INFO: Showing logs ($IMPL implementation)..."
  fi
  $COMPOSE_CMD $COMPOSE_ARGS logs $follow_flag
}

# --- Main Script Logic ---
if [ $# -eq 0 ]; then
  usage
  exit 1
fi

COMMAND="$1"
shift

case "$COMMAND" in
  start)
    start_service
    ;;
  stop)
    stop_service
    ;;
  restart)
    restart_service
    ;;
  backup)
    backup_volumes
    ;;
  restore)
    if [ $# -ne 1 ]; then
      echo "ERROR: 'restore' command requires a backup filename argument."
      usage
      exit 1
    fi
    restore_volumes "$1"
    ;;
  status)
    show_status
    ;;
  logs)
    show_logs "$@"
    ;;
  help | -h | --help)
    usage
    ;;
  *)
    echo "ERROR: Unknown command '$COMMAND'"
    usage
    exit 1
    ;;
esac

exit 0