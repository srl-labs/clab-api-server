#!/bin/bash
#
# clab-api-dind-manager.sh - Management script for Containerlab API DinD service
#
# This script helps manage the Docker-in-Docker Containerlab API service,
# including starting/stopping the service, creating backups, and restoring from backups.
# It includes support for the enhanced persistence mechanism with automatic
# sync of user/group files.

# --- Configuration ---
COMPOSE_FILE="docker/docker-compose.yml"
OVERRIDE_COMPOSE_PROJECT_NAME="docker" # <--- SET THIS based on 'docker volume ls' prefix if needed
CONTAINER_NAME="clab-api-debian-dind"
BASE_CONFIG_VOLUME="clab-api-debian-config-data"
BASE_HOME_VOLUME="clab-api-debian-home-data"
BACKUP_FILENAME_PREFIX="clab-api-volumes-backup"
TEMP_CONTAINER_IMAGE="debian:bookworm-slim"

# --- Helper Functions ---
usage() {
  echo "Usage: $0 <command> [arguments]"
  echo ""
  echo "Manages the Containerlab API Docker service with enhanced persistence."
  echo ""
  echo "Commands:"
  echo "  start          Starts the service (Project: '$project_name')."
  echo "  stop           Stops service (Project: '$project_name')."
  echo "  restart        Restarts the service (Project: '$project_name')."
  echo "  backup         Creates backup (.tar.gz) of config & home volumes."
  echo "                 (Volumes: '${ACTUAL_CONFIG_VOLUME}', '${ACTUAL_HOME_VOLUME}')"
  echo "  restore <file> Restores volumes from the specified backup file."
  echo "                 WARNING: Service must be stopped. Volume data will be ERASED."
  echo "                 (Target Volumes: '${ACTUAL_CONFIG_VOLUME}', '${ACTUAL_HOME_VOLUME}')"
  echo "  status         Shows service status (Project: '$project_name')."
  echo "  logs [-f]      Shows service logs (Project: '$project_name')."
  echo "  help, -h       Shows this help message."
  echo ""
  echo "Note on Project/Volume Names:"
  echo "  Project name: '$project_name'. Volume prefix: '${project_name}_'."
  echo "  If commands fail (volume not found), check 'docker volume ls' and set 'OVERRIDE_COMPOSE_PROJECT_NAME'."
}

is_container_running() {
  docker ps -f name="^/${CONTAINER_NAME}$" --format '{{.Names}}' | grep -q "${CONTAINER_NAME}" || \
  docker ps -f name="^${project_name}-${CONTAINER_NAME}-" --format '{{.Names}}' | grep -q "${project_name}-${CONTAINER_NAME}-" || \
  docker ps -f name="^${CONTAINER_NAME}$" --format '{{.Names}}' | grep -q "${CONTAINER_NAME}"
}

# --- Dependency Checks ---
if ! command -v docker &> /dev/null; then echo "ERROR: 'docker' command not found."; exit 1; fi
if ! command -v tar &> /dev/null; then echo "ERROR: 'tar' command not found."; exit 1; fi

# --- Docker Compose Command Detection ---
_compose_cmd=""
if command -v docker compose &> /dev/null; then _compose_cmd="docker compose";
elif command -v docker-compose &> /dev/null; then _compose_cmd="docker-compose"; echo "WARN: Using legacy docker-compose (V1).";
else echo "ERROR: Neither 'docker compose' nor 'docker-compose' command found."; exit 1; fi
echo "INFO: Using compose command: '$_compose_cmd'"

# --- Project Name Determination ---
project_name=""
compose_file_path=$(readlink -f "$COMPOSE_FILE" 2>/dev/null || realpath "$COMPOSE_FILE" 2>/dev/null)
if [ -z "$compose_file_path" ] || [ ! -f "$compose_file_path" ]; then echo "ERROR: Docker Compose file not found at '$COMPOSE_FILE'."; exit 1; fi
if [ -n "$OVERRIDE_COMPOSE_PROJECT_NAME" ]; then
  project_name="$OVERRIDE_COMPOSE_PROJECT_NAME";
  echo "INFO: Using overridden project name: '$project_name'";
else
  compose_dir=$(dirname "$compose_file_path");
  project_name=$(basename "$compose_dir");
  project_name=$(echo "$project_name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_.-]/_/g');
  echo "INFO: Auto-detected project name as '$project_name'.";
  echo "      !!!! If commands fail (volume not found), verify name using 'docker volume ls' and set 'OVERRIDE_COMPOSE_PROJECT_NAME'. !!!! ";
fi

# --- Construct Actual Volume Names ---
ACTUAL_CONFIG_VOLUME="${project_name}_${BASE_CONFIG_VOLUME}"
ACTUAL_HOME_VOLUME="${project_name}_${BASE_HOME_VOLUME}"
COMPOSE_ARGS="-p ${project_name} -f ${compose_file_path}"

# --- Service Commands ---
start_service() {
  echo "INFO: Starting clab-api service (Project: $project_name)..."
  if $_compose_cmd $COMPOSE_ARGS up -d --remove-orphans; then
    echo "INFO: Service started successfully.";
    $_compose_cmd $COMPOSE_ARGS ps;
  else
    echo "ERROR: Failed to start service.";
    exit 1;
  fi
}

stop_service() {
  echo "INFO: Stopping clab-api service (Project: $project_name)..."
  # No explicit backup needed - files are automatically synced in background
  echo "INFO: Running '$_compose_cmd down'..."
  if $_compose_cmd $COMPOSE_ARGS down --remove-orphans; then
    echo "INFO: Service stopped and containers removed successfully.";
  else
    echo "WARN: '$_compose_cmd down' command did not complete successfully.";
  fi
}

restart_service() {
  echo "INFO: Restarting clab-api service (Project: $project_name)..."
  stop_service
  sleep 2
  start_service
}

backup_volumes() {
  # Standard backup - attempts to back up both volumes separately
  local timestamp=$(date +"%Y%m%d-%H%M%S")
  local backup_filename="${BACKUP_FILENAME_PREFIX}-${timestamp}.tar.gz"
  local current_dir=$(pwd)

  echo "INFO: Starting backup of persistent volumes (Project: $project_name)..."
  echo "      Config Volume: $ACTUAL_CONFIG_VOLUME -> archive path 'config/'"
  echo "      Home Volume:   $ACTUAL_HOME_VOLUME -> archive path 'home/'"
  echo "INFO: Backup target file: ${current_dir}/${backup_filename}"

  if ! docker volume inspect "$ACTUAL_CONFIG_VOLUME" > /dev/null 2>&1; then
    echo "ERROR: Config volume '$ACTUAL_CONFIG_VOLUME' not found.";
    exit 1;
  fi

  if ! docker volume inspect "$ACTUAL_HOME_VOLUME" > /dev/null 2>&1; then
    echo "ERROR: Home volume '$ACTUAL_HOME_VOLUME' not found.";
    exit 1;
  fi

  echo "INFO: Running temporary container ($TEMP_CONTAINER_IMAGE) to create backup..."
  if docker run --rm \
       -v "${ACTUAL_CONFIG_VOLUME}:/volume_config:ro" \
       -v "${ACTUAL_HOME_VOLUME}:/volume_home:ro" \
       -v "${current_dir}:/backup_target" \
       "$TEMP_CONTAINER_IMAGE" \
       bash -c "mkdir -p /tmp/backup-work && \
                 tar -C /volume_config -cf /tmp/backup-work/config.tar . && \
                 tar -C /volume_home -cf /tmp/backup-work/home.tar . && \
                 cd /tmp/backup-work && \
                 tar -czf /backup_target/${backup_filename} config.tar home.tar" ; then
    echo "INFO: Backup created successfully: ${current_dir}/${backup_filename}"
    echo "      (Backup includes both 'config/' and 'home/' directories)"
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
    backup_filepath="$backup_file";
  else
    backup_filepath="${current_dir}/${backup_file}";
  fi

  local backup_basename=$(basename "$backup_filepath")
  local backup_dirname=$(dirname "$backup_filepath")

  echo "INFO: Starting restore process:"
  echo "      File Source: $backup_filepath"
  echo "      Config Volume Target: $ACTUAL_CONFIG_VOLUME"
  echo "      Home Volume Target: $ACTUAL_HOME_VOLUME"

  # --- Basic Checks ---
  if [ ! -f "$backup_filepath" ]; then
    echo "ERROR: Backup file not found: '$backup_filepath'";
    exit 1;
  fi

  if is_container_running; then
    echo "ERROR: Container '$CONTAINER_NAME' (or related) appears to be running.";
    echo "       Stop the service first: '$0 stop'";
    exit 1;
  fi

  if ! docker volume inspect "$ACTUAL_CONFIG_VOLUME" > /dev/null 2>&1; then
    echo "ERROR: Target config volume '$ACTUAL_CONFIG_VOLUME' does not exist.";
    exit 1;
  fi

  if ! docker volume inspect "$ACTUAL_HOME_VOLUME" > /dev/null 2>&1; then
    echo "ERROR: Target home volume '$ACTUAL_HOME_VOLUME' does not exist.";
    exit 1;
  fi

  # --- Pre-check Archive Structure ---
  echo "INFO: Checking backup archive structure..."
  # Check for both possible formats
  local format="unknown"

  # Check for new format (tar files)
  if tar tzf "$backup_filepath" | grep -q 'config.tar'; then
      format="new"
      echo "INFO: Detected new backup format (with config.tar)"
  else
      echo "ERROR: Backup archive '$backup_basename' doesn't contain required files."
      echo "       Cannot perform restore."
      exit 1
  fi

  echo "INFO: Archive structure check passed. Proceeding with restore."

  # --- Confirmation ---
  echo "";
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
  echo "This operation will ERASE ALL CURRENT DATA in the following volumes:";
  echo "  - $ACTUAL_CONFIG_VOLUME";
  echo "  - $ACTUAL_HOME_VOLUME";
  echo "And replace it with the contents from the backup file '$backup_basename'.";
  echo "This action CANNOT be undone.";
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
  read -p "Are you absolutely sure you want to proceed? [y/N] " -n 1 -r;
  echo

  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Restore cancelled.";
    exit 1;
  fi

  echo "Proceeding with restore..."

  # --- Use TEMP_CONTAINER_IMAGE ---
  echo "INFO: Running temporary container ($TEMP_CONTAINER_IMAGE) to perform restore..."

  if [ "$format" = "new" ]; then
    # Handle new format (with tar files)
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

            echo '---> Clearing existing config volume contents (/volume_config)...' && \
            find /volume_config/ -mindepth 1 -delete && \
            echo '---> Restoring config volume from config.tar...' && \
            tar -C /volume_config -xf config.tar && \
            echo '---> Config volume restore complete.' && \

            if [ -f home.tar ]; then \
                echo '---> Clearing existing home volume contents (/volume_home)...' && \
                find /volume_home/ -mindepth 1 -delete && \
                echo '---> Restoring home volume from home.tar...' && \
                tar -C /volume_home -xf home.tar && \
                echo '---> Home volume restore complete.'; \
            else \
                echo '---> Skipping home volume restore (no home.tar in archive)'; \
            fi || \
            (echo 'ERROR: Extraction failed inside container!' && exit 1) \
       "
  fi

  if [ $? -eq 0 ]; then
    echo "INFO: Restore completed successfully."
    if [ "$format" = "new" ]; then
      echo "      Volume '$ACTUAL_CONFIG_VOLUME' has been populated from the 'config.tar' in the backup."
      echo "      Volume '$ACTUAL_HOME_VOLUME' has been populated from the 'home.tar' in the backup (if available)."
    else
      echo "      Volume '$ACTUAL_CONFIG_VOLUME' has been populated from the 'config/' directory in the backup."
      echo "      Volume '$ACTUAL_HOME_VOLUME' has been populated from the 'home/' directory in the backup (if available)."
      echo "      User home directories have been properly relocated if needed."
    fi

    # --- Recreate missing home directories ---
    echo "INFO: Starting service temporarily to check for missing home directories..."
    start_service

    echo "INFO: Checking and recreating missing home directories if necessary..."
    docker exec $CONTAINER_NAME bash -c "
        cat /etc/passwd | while IFS=: read -r username x uid gid x homedir x; do
            if [ \$uid -ge 1000 ] && [ ! -d \$homedir ]; then
                echo \"Creating missing home directory: \$homedir for user: \$username\"
                mkdir -p \$homedir
                chown \$username:\$username \$homedir
                chmod 755 \$homedir

                # Copy standard dotfiles from /etc/skel
                if [ -d /etc/skel ]; then
                    cp -a /etc/skel/. \$homedir/
                    chown -R \$username:\$username \$homedir
                fi
            fi
        done
    "

    echo "INFO: Stopping service after home directory check..."
    stop_service

    echo "INFO: Restore process complete."
    echo "      You can now start the service: '$0 start'"
  else
    echo "ERROR: Failed to restore volumes."
    echo "       Check the output above for specific errors from the container."
    echo "       Volume contents might be in an inconsistent state."
    exit 1
  fi
}

show_status() {
    echo "INFO: Checking status of clab-api service (Project: $project_name)..."
    $_compose_cmd $COMPOSE_ARGS ps
}

show_logs() {
    local follow_flag=""
    if [ "$1" == "-f" ]; then
      follow_flag="-f";
      echo "INFO: Following logs (Project: $project_name, Ctrl+C to stop)...";
    else
      echo "INFO: Showing logs (Project: $project_name)...";
    fi
    $_compose_cmd $COMPOSE_ARGS logs $follow_flag
}

# --- Main Script Logic ---
if [ ! -f "$compose_file_path" ]; then
  echo "INTERNAL ERROR: Compose file path lost.";
  exit 1;
fi

if [ $# -eq 0 ]; then
  usage;
  exit 1;
fi

COMMAND="$1";
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
      echo "ERROR: 'restore' command requires a backup filename argument.";
      usage;
      exit 1;
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
    echo "ERROR: Unknown command '$COMMAND'";
    usage;
    exit 1
    ;;
esac

exit 0