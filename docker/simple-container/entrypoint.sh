#!/bin/sh
set -e

is_placeholder_jwt_secret() {
  normalized_secret="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$normalized_secret" in
    *default_secret_change_me*|*a_very_secret_key_change_me_please*|*change_me*|*change-me*|*changeme*|*replace_me*|*replace-me*|*your_jwt_secret*)
      return 0
      ;;
  esac
  return 1
}

if [ -z "${JWT_SECRET:-}" ]; then
  JWT_SECRET="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  export JWT_SECRET
  echo "Generated an ephemeral JWT_SECRET for this container instance."
elif is_placeholder_jwt_secret "$JWT_SECRET"; then
  echo "Refusing to start with a placeholder JWT_SECRET." >&2
  exit 1
fi

# Setup optional labs root. When CLAB_LABS_ROOT is unset, the API server
# stores managed lab files in each authenticated user's ~/.clab directory.
if [ -n "${CLAB_LABS_ROOT:-}" ]; then
  echo "Setting up labs root: $CLAB_LABS_ROOT"
  mkdir -p "$CLAB_LABS_ROOT"
fi

mkdir -p /var/run/netns

# Now execute the command passed to the container
echo "Executing command: $@"
exec "$@"
