#!/usr/bin/env bash
# scripts/setup-tests-go-env.sh
# Prepare local Linux users/groups so tests_go/.env credentials work.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${REPO_ROOT}/tests_go/.env"

if [[ $EUID -ne 0 ]]; then
  echo "This script must run as root (sudo scripts/setup-tests-go-env.sh)." >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "tests_go/.env not found at $ENV_FILE" >&2
  exit 1
fi

get_env_value() {
  local key="$1"
  local line value
  line="$(grep -E "^${key}=" "$ENV_FILE" | head -n1 || true)"
  if [[ -z "$line" ]]; then
    echo ""
    return
  fi
  value="${line#*=}"
  value="${value%%#*}"
  value="$(echo "$value" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  # Strip optional single/double quotes without breaking JSON snippets later in the file.
  if [[ ${value:0:1} == '"' && ${value: -1} == '"' ]]; then
    value="${value:1:-1}"
  elif [[ ${value:0:1} == "'" && ${value: -1} == "'" ]]; then
    value="${value:1:-1}"
  fi
  echo "$value"
}

require_value() {
  local name="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    echo "Required key '$name' missing or empty in tests_go/.env" >&2
    exit 1
  fi
}

ensure_group() {
  local group="$1"
  if getent group "$group" >/dev/null 2>&1; then
    echo "Group '$group' already exists"
  else
    echo "Creating group '$group'"
    groupadd "$group"
  fi
}

ensure_user() {
  local user="$1"
  local pass="$2"
  shift 2
  local groups=("$@")

  if id -u "$user" >/dev/null 2>&1; then
    echo "User '$user' already exists"
  else
    echo "Creating user '$user'"
    useradd -m -s /bin/bash "$user"
  fi

  echo "${user}:${pass}" | chpasswd

  for grp in "${groups[@]}"; do
    usermod -aG "$grp" "$user"
  done
}

ensure_not_in_groups() {
  local user="$1"
  shift
  local groups=("$@")
  for grp in "${groups[@]}"; do
    if getent group "$grp" >/dev/null 2>&1; then
      if id -nG "$user" 2>/dev/null | grep -qw "$grp"; then
        gpasswd -d "$user" "$grp" >/dev/null 2>&1 || true
      fi
    fi
  done
}

add_user_to_group() {
  local user="$1"
  local group="$2"

  if [[ -z "$user" || -z "$group" ]]; then
    return
  fi

  if ! id -u "$user" >/dev/null 2>&1; then
    echo "User '$user' does not exist; cannot add to group '$group'"
    return
  fi

  if ! getent group "$group" >/dev/null 2>&1; then
    echo "Group '$group' does not exist; cannot add user '$user'"
    return
  fi

  if id -nG "$user" | tr ' ' '\n' | grep -qx "$group"; then
    echo "User '$user' already a member of '$group'"
    return
  fi

  echo "Adding user '$user' to group '$group'"
  usermod -aG "$group" "$user"
}

SUPERUSER_USER="$(get_env_value "SUPERUSER_USER")"
SUPERUSER_PASS="$(get_env_value "SUPERUSER_PASS")"
APIUSER_USER="$(get_env_value "APIUSER_USER")"
APIUSER_PASS="$(get_env_value "APIUSER_PASS")"
UNAUTH_USER="$(get_env_value "UNAUTH_USER")"
UNAUTH_PASS="$(get_env_value "UNAUTH_PASS")"
SUPERUSER_GROUP="$(get_env_value "GOTEST_SUPERUSER_GROUP")"
APIUSER_GROUP="$(get_env_value "GOTEST_API_USER_GROUP")"

require_value "SUPERUSER_USER" "$SUPERUSER_USER"
require_value "SUPERUSER_PASS" "$SUPERUSER_PASS"
require_value "APIUSER_USER" "$APIUSER_USER"
require_value "APIUSER_PASS" "$APIUSER_PASS"
require_value "UNAUTH_USER" "$UNAUTH_USER"
require_value "UNAUTH_PASS" "$UNAUTH_PASS"
require_value "GOTEST_SUPERUSER_GROUP" "$SUPERUSER_GROUP"
require_value "GOTEST_API_USER_GROUP" "$APIUSER_GROUP"

ensure_group "$SUPERUSER_GROUP"
ensure_group "$APIUSER_GROUP"

ensure_user "$SUPERUSER_USER" "$SUPERUSER_PASS" "$SUPERUSER_GROUP" "$APIUSER_GROUP"
ensure_user "$APIUSER_USER" "$APIUSER_PASS" "$APIUSER_GROUP"
ensure_user "$UNAUTH_USER" "$UNAUTH_PASS"
ensure_not_in_groups "$UNAUTH_USER" "$SUPERUSER_GROUP" "$APIUSER_GROUP"

HOST_USER="${SUDO_USER:-}"
if [[ -z "$HOST_USER" ]]; then
  HOST_USER="$(logname 2>/dev/null || true)"
fi

if [[ -n "$HOST_USER" ]]; then
  add_user_to_group "$HOST_USER" "$SUPERUSER_GROUP"
else
  echo "Unable to detect host user for group alignment"
fi

# Ensure root (which runs the API server under sudo) can also set lab owners.
add_user_to_group root "$SUPERUSER_GROUP"

echo "Test users/groups aligned with tests_go/.env"
