#!/usr/bin/env bash
#
# Containerlab API Server installer / upgrader / uninstaller
# Usage examples:
#   curl -sL <RAW‑URL> | sudo -E bash           # install latest, full service
#   curl -sL <RAW‑URL> | sudo -E bash install   # same as above
#   curl -sL <RAW‑URL> | sudo -E bash pull-only --version v0.1.1
#   sudo ./install.sh upgrade
#   sudo ./install.sh uninstall
#
# Environment variables or CLI flags:
#   --version vX.Y.Z   (or VERSION=vX.Y.Z)  ➜ install that version, otherwise latest
#   --yes                              ➜ non‑interactive uninstall

set -euo pipefail

REPO="srl-labs/clab-api-server"
BIN_DIR="/usr/local/bin"
BIN_PATH="${BIN_DIR}/clab-api-server"
ENV_FILE="/etc/clab-api-server.env" # Location where the script *creates* the env file
SERVICE_FILE="/etc/systemd/system/clab-api-server.service"

################################################################################
# Helpers
################################################################################
die()      { echo "❌ $*" >&2; exit 1; }
info()     { echo -e "==> $*"; }
is_root()  { [[ $EUID -eq 0 ]]; }
need_root() { is_root || die "Please run with sudo or as root"; }

arch() {
  case "$(uname -m)" in
    x86_64|amd64)   echo "amd64" ;;
    aarch64|arm64)  echo "arm64" ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
  esac
}

latest_tag() {
  # Follow the redirect of /releases/latest to find the latest tag without using the GitHub API
  curl -sSLI "https://github.com/${REPO}/releases/latest" \
    | grep -i '^location:' \
    | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' \
    | head -n1
}

download_binary() {
  local version="$1" arch="$2" url
  if [[ -z $version ]]; then
     # Attempt the generic "latest/download" asset first
     url="https://github.com/${REPO}/releases/latest/download/clab-api-server-linux-${arch}"
     if ! curl -fsIL "$url" >/dev/null; then
        # Fallback: resolve the latest tag then construct an explicit URL
        version="$(latest_tag)" || die "Could not resolve latest version"
        url="https://github.com/${REPO}/releases/download/${version}/clab-api-server-linux-${arch}"
     fi
  else
     url="https://github.com/${REPO}/releases/download/${version}/clab-api-server-linux-${arch}"
  fi

  info "Fetching binary from $url"
  curl -#SL "$url" -o "${BIN_PATH}.tmp" || die "Download failed from $url"
  chmod +x "${BIN_PATH}.tmp"
  mv -f "${BIN_PATH}.tmp" "$BIN_PATH"
  info "Installed $BIN_PATH"
  "$BIN_PATH" -v || die "Installed binary failed to execute or report version."
}

create_env() {
  [[ -f $ENV_FILE ]] && { info "$ENV_FILE already exists, skipping creation."; return; }
  info "Creating $ENV_FILE"
  sudo tee "$ENV_FILE" >/dev/null <<'EOF'
# Containerlab API Server Configuration
# This file is loaded by the systemd service.
# You can also set these as environment variables.

# --- API Server Settings ---
API_PORT=8080
# Log level: debug, info, warn, error, fatal
LOG_LEVEL=info

# --- Authentication ---
# Secret key for signing JWT tokens. CHANGE THIS IN PRODUCTION!
JWT_SECRET=a_very_secret_key_change_me_please
# Duration for JWT token validity (e.g., 60m, 24h)
JWT_EXPIRATION_MINUTES=60m
# Linux group users must belong to for API login (alternative to clab_admins)
# Leave empty if only clab_admins should log in.
API_USER_GROUP=clab_api
# Linux group for users with superuser privileges (e.g., see/manage all labs)
# Requires membership check, ensure the group exists.
SUPERUSER_GROUP=clab_admins

# --- Containerlab Settings ---
# Container runtime to use (docker, podman, etc.)
CLAB_RUNTIME=docker

# --- Gin Web Framework Settings ---
# Gin mode: debug, release, test
GIN_MODE=release
# Trusted proxies: Comma-separated list of IPs/CIDRs, or 'nil' to disable trust.
# Leave empty to trust all (default, potentially insecure behind proxies).
TRUSTED_PROXIES=

# --- TLS Settings (Optional) ---
# Enable HTTPS (requires cert and key files)
#TLS_ENABLE=true
# Path to the TLS certificate file
#TLS_CERT_FILE=/etc/clab-api-server/certs/server.pem
# Path to the TLS key file
#TLS_KEY_FILE=/etc/clab-api-server/certs/server-key.pem
EOF
  sudo chmod 640 "$ENV_FILE"
  # Set group ownership to the API or superuser group if it exists
  local service_group
  service_group=$(grep -E '^API_USER_GROUP=' "$ENV_FILE" | cut -d= -f2)
  if [[ -z $service_group ]]; then
    service_group=$(grep -E '^SUPERUSER_GROUP=' "$ENV_FILE" | cut -d= -f2)
  fi
  if [[ -n $service_group ]] && getent group "$service_group" >/dev/null; then
    sudo chown root:"$service_group" "$ENV_FILE"
  else
    sudo chown root:root "$ENV_FILE"
  fi
}

create_service() {
  local run_user run_group
  if [[ -n ${SUDO_USER:-} ]] && id -u "$SUDO_USER" &>/dev/null; then
    run_user="$SUDO_USER"
  else
    run_user="root"
    info "Warning: SUDO_USER not found or invalid, service will run as root."
  fi
  run_group=$(id -gn "$run_user") || die "Failed to get primary group for $run_user"

  info "Installing systemd service (user=$run_user group=$run_group)"

  sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Containerlab API Server
Documentation=https://github.com/srl-labs/clab-api-server
After=network.target docker.service

[Service]
Type=simple
User=$run_user
Group=$run_group

EnvironmentFile=$ENV_FILE
ExecStart=$BIN_PATH -env-file $ENV_FILE

Restart=on-failure
RestartSec=10
TimeoutStartSec=30

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable clab-api-server
  info "Systemd service installed. Start it with: sudo systemctl start clab-api-server"
}


remove_service() {
  if [[ -f $SERVICE_FILE ]]; then
    sudo systemctl stop clab-api-server 2>/dev/null || true
    sudo systemctl disable clab-api-server 2>/dev/null || true
    sudo rm -f "$SERVICE_FILE"
    sudo systemctl daemon-reload
    sudo systemctl reset-failed clab-api-server.service 2>/dev/null || true
    info "Removed systemd unit"
  fi
}

remove_env() {
  [[ -f $ENV_FILE ]] && sudo rm -f "$ENV_FILE" && info "Removed $ENV_FILE"
}

remove_binary() {
  [[ -f $BIN_PATH ]] && sudo rm -f "$BIN_PATH" && info "Removed $BIN_PATH"
}

################################################################################
# Parse CLI arguments
################################################################################
ACTION="install"      # default action
VERSION="${VERSION:-}" # env var fallback
YES=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    install|pull-only|upgrade|uninstall) ACTION="$1" ;;
    --version) shift; VERSION="$1" || die "--version requires an argument" ;;
    --yes|-y) YES=1 ;;
    -h|--help)
      cat <<USAGE
Usage: $0 [install|pull-only|upgrade|uninstall] [--version vX.Y.Z] [--yes]
Environment variables:
  VERSION=vX.Y.Z  Specify version to install/upgrade
USAGE
      exit 0
      ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done

need_root
ARCH=$(arch)

info "Selected action: $ACTION"
[[ -n $VERSION ]] && info "Specified version: $VERSION"

case "$ACTION" in
  pull-only)
    download_binary "$VERSION" "$ARCH"
    ;;

  install)
    download_binary "$VERSION" "$ARCH"
    create_env
    create_service
    info "Installation complete. Start the service with: sudo systemctl start clab-api-server"
    ;;

  upgrade)
    info "Upgrading…"
    if systemctl is-active --quiet clab-api-server; then
      sudo systemctl stop clab-api-server
    fi
    download_binary "$VERSION" "$ARCH"
    create_env
    create_service
    sudo systemctl start clab-api-server
    info "Upgrade complete."
    ;;

  uninstall)
    if [[ -z $YES ]]; then
      read -rp "Really uninstall clab-api-server and remove files? (y/N) " ans
      [[ $ans =~ ^[Yy]$ ]] || die "Aborted."
    fi
    remove_service
    remove_binary
    remove_env
    info "Uninstall complete."
    ;;

  *) die "Unhandled action: $ACTION" ;;
esac
