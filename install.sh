#!/usr/bin/env bash
#
# Containerlab API Server installer / upgrader / uninstaller
# Usage examples:
#   curl -sL https://raw.githubusercontent.com/srl-labs/clab-api-server/refs/heads/main/install.sh | sudo -E bash           # install latest, create service – you enable it later
#   curl -sL https://raw.githubusercontent.com/srl-labs/clab-api-server/refs/heads/main/install.sh | sudo -E bash install   # same as above
#   curl -sL https://raw.githubusercontent.com/srl-labs/clab-api-server/refs/heads/main/install.sh | sudo -E bash pull-only --version v0.1.1
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
ENV_FILE="/etc/clab-api-server.env"  # file created by this script; edit after install
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
  # Resolve latest tag without GitHub API
  curl -sSLI "https://github.com/${REPO}/releases/latest" \
    | grep -i '^location:' \
    | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' \
    | head -n1
}

download_binary() {
  local version="$1" arch="$2" url
  if [[ -z $version ]]; then
     url="https://github.com/${REPO}/releases/latest/download/clab-api-server-linux-${arch}"
     if ! curl -fsIL "$url" >/dev/null; then
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
  "$BIN_PATH" -v || die "Installed binary failed to execute"
}

create_env() {
  [[ -f $ENV_FILE ]] && { info "$ENV_FILE already exists, skipping creation."; return; }
  info "Creating $ENV_FILE (edit it before starting the service)"
  sudo tee "$ENV_FILE" >/dev/null <<'EOF'
# Containerlab API Server configuration
# Edit this file, then enable + start the service.

API_PORT=8080
LOG_LEVEL=info

# --- Authentication ---
JWT_SECRET=please_change_me
JWT_EXPIRATION_MINUTES=60m
API_USER_GROUP=clab_api
SUPERUSER_GROUP=clab_admins

# --- Containerlab ---
CLAB_RUNTIME=docker

# --- Gin ---
GIN_MODE=release
TRUSTED_PROXIES=

# --- TLS (optional) ---
#TLS_ENABLE=true
#TLS_CERT_FILE=/etc/clab-api-server/certs/server.pem
#TLS_KEY_FILE=/etc/clab-api-server/certs/server-key.pem
EOF
  sudo chmod 640 "$ENV_FILE"
}

create_service() {
  local run_user run_group
  if [[ -n ${SUDO_USER:-} ]] && id -u "$SUDO_USER" &>/dev/null; then
    run_user="$SUDO_USER"
  else
    run_user="root"
    info "Warning: SUDO_USER not found; service will run as root."
  fi
  run_group=$(id -gn "$run_user") || die "Failed to get group for $run_user"

  info "Writing systemd unit ($SERVICE_FILE)"
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
  info "Systemd unit installed – **not** enabled or started."
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

remove_env() { [[ -f $ENV_FILE ]] && sudo rm -f "$ENV_FILE" && info "Removed $ENV_FILE"; }
remove_binary() { [[ -f $BIN_PATH ]] && sudo rm -f "$BIN_PATH" && info "Removed $BIN_PATH"; }

################################################################################
# CLI parsing
################################################################################
ACTION="install"
VERSION="${VERSION:-}"
YES=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    install|pull-only|upgrade|uninstall) ACTION="$1" ;;
    --version) shift; VERSION="$1" || die "--version requires an argument" ;;
    --yes|-y) YES=1 ;;
    -h|--help)
      cat <<USAGE
Usage: $0 [install|pull-only|upgrade|uninstall] [--version vX.Y.Z] [--yes]
USAGE
      exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done

need_root
ARCH=$(arch)
info "Selected action: $ACTION${VERSION:+ (version $VERSION)}"

case "$ACTION" in
  pull-only)
    download_binary "$VERSION" "$ARCH" ;;

  install)
    download_binary "$VERSION" "$ARCH"
    create_env
    create_service
    info "\nInstallation complete.\n1. Edit $ENV_FILE to suit your environment.\n2. Enable and start the service with:\n   sudo systemctl enable --now clab-api-server\n" ;;

  upgrade)
    info "Upgrading… (service will be left stopped)"
    if systemctl is-active --quiet clab-api-server; then
      sudo systemctl stop clab-api-server
    fi
    download_binary "$VERSION" "$ARCH"
    create_env
    create_service
    info "Upgrade complete. Review $ENV_FILE then restart the service:\n   sudo systemctl restart clab-api-server" ;;

  uninstall)
    if [[ -z $YES ]]; then
      read -rp "Really uninstall clab-api-server and remove files? (y/N) " ans
      [[ $ans =~ ^[Yy]$ ]] || die "Aborted."
    fi
    remove_service; remove_binary; remove_env
    info "Uninstall complete." ;;

  *) die "Unhandled action: $ACTION" ;;
esac
