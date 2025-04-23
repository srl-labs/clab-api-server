#!/bin/bash


# --- Configuration ---
COMPOSE_FILE="docker/docker-compose.yml"
OVERRIDE_COMPOSE_PROJECT_NAME="docker" # <--- SET THIS based on 'docker volume ls' prefix if needed
CONTAINER_NAME="clab-api-debian-dind"
BASE_CONFIG_VOLUME="clab-api-debian-config-data"
BASE_HOME_VOLUME="clab-api-debian-home-data"
PERSISTENT_CONFIG_DIR="/persistent-config"
ETC_FILES_TO_PERSIST="passwd shadow group gshadow subuid subgid"
BACKUP_FILENAME_PREFIX="clab-api-volumes-backup"
TEMP_CONTAINER_IMAGE="debian:bookworm-slim"

# --- Helper Functions ---
usage() {
  echo "Usage: $0 <command> [arguments]"
  echo ""
  echo "Manages the clab-api Docker Compose service and persistent volumes."
  echo "!! MODIFIED VERSION: 'restore' command is adapted for backups where home dirs are within the 'config/' archive part !!"
  echo ""
  echo "Commands:"
  echo "  start          Starts the service (Project: '$project_name')."
  echo "  stop           Backs up /etc config to volume, stops service (Project: '$project_name')."
  echo "  backup         Creates backup (.tar.gz) of config & home volumes."
  echo "                 (Volumes: '${ACTUAL_CONFIG_VOLUME}', '${ACTUAL_HOME_VOLUME}')"
  echo "                 (NOTE: Standard backup creates separate config/ and home/ archive dirs)"
  echo "  restore <file> Restores ONLY the 'config/' part from the specified backup file"
  echo "                 to the config volume. Ignores 'home/' in archive and target home volume."
  echo "                 WARNING: Service must be stopped. Config volume data will be ERASED."
  echo "                 (Target Volume: '${ACTUAL_CONFIG_VOLUME}')"
  echo "  status         Shows service status (Project: '$project_name')."
  echo "  logs [-f]      Shows service logs (Project: '$project_name')."
  echo "  help, -h       Shows this help message."
  echo ""
  echo "Note on Project/Volume Names:"
  echo "  Project name: '$project_name'. Volume prefix: '${project_name}_'."
  echo "  If commands fail (volume not found), check 'docker volume ls' and set 'OVERRIDE_COMPOSE_PROJECT_NAME'."
}

is_container_running() {
  docker ps -q -f name="^/${CONTAINER_NAME}$" --format '{{.Names}}' | grep -q "${CONTAINER_NAME}" || \
  docker ps -q -f name="^${project_name}-${CONTAINER_NAME}-" --format '{{.Names}}' | grep -q "${project_name}-${CONTAINER_NAME}-" || \
  docker ps -q -f name="^${CONTAINER_NAME}$" --format '{{.Names}}' | grep -q "${CONTAINER_NAME}"
}

backup_user_config() {
  if ! is_container_running; then
    echo "INFO: Container '$CONTAINER_NAME' is not running. Skipping user config backup to volume."
    return 0
  fi
  echo "INFO: Backing up user configuration from running container '$CONTAINER_NAME' to volume '${ACTUAL_CONFIG_VOLUME}'..."
  local backup_cmd="mkdir -p ${PERSISTENT_CONFIG_DIR} && "
  for file in $ETC_FILES_TO_PERSIST; do
    backup_cmd+="cp -p /etc/$file ${PERSISTENT_CONFIG_DIR}/$file 2>/dev/null && echo ' -> Backed up /etc/$file' || echo ' -> Skipped /etc/$file (not found or error)'; "
  done
  backup_cmd+="echo ' -> User config backup attempt finished.'"
  if docker exec "$CONTAINER_NAME" /bin/sh -c "$backup_cmd"; then
    echo "INFO: User configuration backup command executed successfully in container."
    return 0
  else
    echo "ERROR: Failed to execute backup command in container '$CONTAINER_NAME'. Stop aborted."
    return 1
  fi
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
if [ -n "$OVERRIDE_COMPOSE_PROJECT_NAME" ]; then project_name="$OVERRIDE_COMPOSE_PROJECT_NAME"; echo "INFO: Using overridden project name: '$project_name'";
else compose_dir=$(dirname "$compose_file_path"); project_name=$(basename "$compose_dir"); project_name=$(echo "$project_name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_.-]/_/g'); echo "INFO: Auto-detected project name as '$project_name'."; echo "      !!!! If commands fail (volume not found), verify name using 'docker volume ls' and set 'OVERRIDE_COMPOSE_PROJECT_NAME'. !!!! "; fi

# --- Construct Actual Volume Names ---
ACTUAL_CONFIG_VOLUME="${project_name}_${BASE_CONFIG_VOLUME}"
ACTUAL_HOME_VOLUME="${project_name}_${BASE_HOME_VOLUME}"
COMPOSE_ARGS="-p ${project_name} -f ${compose_file_path}"

# --- Service Commands ---
start_service() {
  echo "INFO: Starting clab-api service (Project: $project_name)..."
  if $_compose_cmd $COMPOSE_ARGS up -d --remove-orphans; then echo "INFO: Service started successfully."; $_compose_cmd $COMPOSE_ARGS ps;
  else echo "ERROR: Failed to start service."; exit 1; fi
}

stop_service() {
  echo "INFO: Stopping clab-api service (Project: $project_name)..."
  if ! backup_user_config; then echo "ERROR: User config backup failed. Aborting stop."; exit 1; fi
  echo "INFO: Running '$_compose_cmd down'..."
  if $_compose_cmd $COMPOSE_ARGS down --remove-orphans; then echo "INFO: Service stopped and containers removed successfully.";
  else echo "WARN: '$_compose_cmd down' command did not complete successfully."; fi
}

backup_volumes() {
  # Standard backup - attempts to back up both volumes separately
  local timestamp=$(date +"%Y%m%d-%H%M%S")
  local backup_filename="${BACKUP_FILENAME_PREFIX}-${timestamp}.tar.gz"
  local current_dir=$(pwd)
  echo "INFO: Starting standard backup of persistent volumes (Project: $project_name)..."
  echo "      Config Volume: $ACTUAL_CONFIG_VOLUME -> archive path 'config/'"
  echo "      Home Volume:   $ACTUAL_HOME_VOLUME -> archive path 'home/'"
  echo "INFO: Backup target file: ${current_dir}/${backup_filename}"
  if ! docker volume inspect "$ACTUAL_CONFIG_VOLUME" > /dev/null 2>&1; then echo "ERROR: Config volume '$ACTUAL_CONFIG_VOLUME' not found."; exit 1; fi
  if ! docker volume inspect "$ACTUAL_HOME_VOLUME" > /dev/null 2>&1; then echo "ERROR: Home volume '$ACTUAL_HOME_VOLUME' not found."; exit 1; fi
  echo "INFO: Running temporary container ($TEMP_CONTAINER_IMAGE) to create backup..."
  if docker run --rm \
       -v "${ACTUAL_CONFIG_VOLUME}:/volume_config:ro" \
       -v "${ACTUAL_HOME_VOLUME}:/volume_home:ro" \
       -v "${current_dir}:/backup_target" \
       "$TEMP_CONTAINER_IMAGE" \
       tar czf "/backup_target/${backup_filename}" \
           -C /volume_config --transform='s,^\./,config/,' . \
           -C /volume_home --transform='s,^\./,home/,' . ; then 
    echo "INFO: Backup created successfully: ${current_dir}/${backup_filename}"
    echo "      (Standard backup attempts to include both 'config/' and 'home/' directories)"
  else
    echo "ERROR: Failed to create backup tarball."
    rm -f "${current_dir}/${backup_filename}"
    exit 1
  fi
}

# --- MODIFIED Restore Function ---
restore_volumes() {
  local backup_file="$1"
  local current_dir=$(pwd)
  local backup_filepath
  if [[ "$backup_file" == /* ]]; then backup_filepath="$backup_file"; else backup_filepath="${current_dir}/${backup_file}"; fi
  local backup_basename=$(basename "$backup_filepath")
  local backup_dirname=$(dirname "$backup_filepath")

  echo "INFO: Starting MODIFIED restore process:"
  echo "      -> Will restore ONLY 'config/' from archive into config volume."
  echo "      -> Target home volume ('${ACTUAL_HOME_VOLUME}') will NOT be modified by this restore."
  echo "      File Source: $backup_filepath"
  echo "      Config Volume Target: $ACTUAL_CONFIG_VOLUME"

  # --- Basic Checks ---
  if [ ! -f "$backup_filepath" ]; then echo "ERROR: Backup file not found: '$backup_filepath'"; exit 1; fi
  if is_container_running; then echo "ERROR: Container '$CONTAINER_NAME' (or related) appears to be running."; echo "       Stop the service first: '$0 stop'"; exit 1; fi
  if ! docker volume inspect "$ACTUAL_CONFIG_VOLUME" > /dev/null 2>&1; then echo "ERROR: Target config volume '$ACTUAL_CONFIG_VOLUME' does not exist."; exit 1; fi
  # No check needed for home volume existence as we won't touch it

  # --- Pre-check Archive Structure (Only check for config/) ---
  echo "INFO: Checking backup archive structure for 'config/' directory..."
  if ! tar tzf "$backup_filepath" | grep -q '^config/'; then
      echo "ERROR: Backup archive '$backup_basename' is missing the required top-level 'config/' directory."
      echo "       Cannot perform restore."
      exit 1
  fi
  # Check if home/ exists just to inform the user if they are using a standard backup with this modified restore
  if tar tzf "$backup_filepath" | grep -q '^home/'; then
      echo "WARN: Archive contains a 'home/' directory, but this modified restore WILL NOT use it."
  fi
  echo "INFO: Archive structure check passed (found config/). Proceeding with restore of config volume only."

  # --- Confirmation ---
  echo ""; echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
  echo "This operation will ERASE ALL CURRENT DATA in the following volume:";
  echo "  - $ACTUAL_CONFIG_VOLUME";
  echo "And replace it with the contents of 'config/' from the backup file '$backup_basename'.";
  echo "The home volume ('${ACTUAL_HOME_VOLUME}') WILL NOT BE AFFECTED by this restore.";
  echo "This action CANNOT be undone for the config volume.";
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
  read -p "Are you absolutely sure you want to proceed? [y/N] " -n 1 -r; echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then echo "Restore cancelled."; exit 1; fi
  echo "Proceeding with restore of config volume only..."

  # --- Use TEMP_CONTAINER_IMAGE ---
  echo "INFO: Running temporary container ($TEMP_CONTAINER_IMAGE) to perform restore..."
  # Mount only config volume read-write
  # Mount backup source dir read-only
  # Inside the container:
  # 1. Clear existing data from config volume
  # 2. Extract 'config/' contents into config volume
  if docker run --rm \
       -v "${ACTUAL_CONFIG_VOLUME}:/volume_config" \
       -v "${backup_dirname}:/backup_source:ro" \
       "$TEMP_CONTAINER_IMAGE" \
       sh -c " \
            echo '---> Clearing existing config volume contents (/volume_config)...'; \
            find /volume_config/ -mindepth 1 -delete && \
            echo '---> Extracting 'config/*' from ${backup_basename} into /volume_config...'; \
            tar xzf '/backup_source/${backup_basename}' -C /volume_config --strip-components=1 config && \
            echo '---> Extraction of config volume complete.' || \
            (echo 'ERROR: Extraction failed inside container!' && exit 1) \
       "; then
    echo "INFO: MODIFIED restore completed successfully."
    echo "      Volume '$ACTUAL_CONFIG_VOLUME' has been populated from the 'config/' part of the backup."
    echo "      Home volume '${ACTUAL_HOME_VOLUME}' was NOT modified."
    echo "      You can now start the service: '$0 start'"
  else
    echo "ERROR: Failed to restore config volume."
    echo "       Check the output above for specific errors from the container."
    echo "       Config volume contents might be in an inconsistent state."
    exit 1
  fi
}

show_status() {
    echo "INFO: Checking status of clab-api service (Project: $project_name)..."
    $_compose_cmd $COMPOSE_ARGS ps
}

show_logs() {
    local follow_flag=""
    if [ "$1" == "-f" ]; then follow_flag="-f"; echo "INFO: Following logs (Project: $project_name, Ctrl+C to stop)...";
    else echo "INFO: Showing logs (Project: $project_name)..."; fi
    $_compose_cmd $COMPOSE_ARGS logs $follow_flag
}

# --- Main Script Logic ---
if [ ! -f "$compose_file_path" ]; then echo "INTERNAL ERROR: Compose file path lost."; exit 1; fi
if [ $# -eq 0 ]; then usage; exit 1; fi
COMMAND="$1"; shift
case "$COMMAND" in
  start) start_service ;;
  stop) stop_service ;;
  backup) backup_volumes ;;
  restore)
    if [ $# -ne 1 ]; then echo "ERROR: 'restore' command requires a backup filename argument."; usage; exit 1; fi
    restore_volumes "$1" ;; 
  status) show_status ;;
  logs) show_logs "$@" ;;
  help | -h | --help) usage ;;
  *) echo "ERROR: Unknown command '$COMMAND'"; usage; exit 1 ;;
esac

exit 0