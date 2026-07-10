#!/usr/bin/env bash
#
# Containerlab API Server installer / upgrader / uninstaller
#
# Quick examples:
#   curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh \
#     | sudo bash -s -- install
#
#   curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh \
#     | sudo bash -s -- install --start
#
#   curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh \
#     | sudo bash -s -- upgrade --version clab-0.73.0-api-0.2.1
#
#   curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh \
#     | sudo bash -s -- uninstall --yes

set -euo pipefail

REPO="srl-labs/clab-api-server"
BIN_DIR="/usr/local/bin"
BIN_PATH="${BIN_DIR}/clab-api-server"
CONFIG_DIR="/etc/clab-api-server"
ENV_FILE="${CONFIG_DIR}/clab-api-server.env"
LEGACY_ENV_FILE="/etc/clab-api-server.env"
SERVICE_NAME="clab-api-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

info() {
  printf '==> %s\n' "$*"
}

need_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Please run with sudo or as root"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
  esac
}

latest_tag() {
  local location tag

  location="$(curl -sSLI "https://github.com/${REPO}/releases/latest" \
    | awk 'tolower($1)=="location:"{print $2}' \
    | tr -d '\r' \
    | tail -n1)"

  [[ -n $location ]] || return 1

  tag="$location"
  if [[ $tag == *"/releases/tag/"* ]]; then
    tag="${tag#*releases/tag/}"
  else
    tag="${tag##*/}"
  fi
  tag="${tag%%\?*}"
  tag="${tag%%#*}"

  [[ -n $tag ]] || return 1
  printf '%s\n' "$tag"
}

generate_jwt_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
    return
  fi

  if command -v od >/dev/null 2>&1; then
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
    return
  fi

  die "Cannot generate JWT_SECRET: install openssl or od"
}

ensure_config_dir() {
  install -d -m 755 "$CONFIG_DIR"
}

migrate_legacy_env() {
  if [[ -f $LEGACY_ENV_FILE && ! -f $ENV_FILE ]]; then
    ensure_config_dir
    mv "$LEGACY_ENV_FILE" "$ENV_FILE"
    chmod 600 "$ENV_FILE" || true
    info "Migrated $LEGACY_ENV_FILE to $ENV_FILE"
  elif [[ -f $LEGACY_ENV_FILE && -f $ENV_FILE ]]; then
    info "Legacy config remains at $LEGACY_ENV_FILE; using $ENV_FILE"
  fi
}

create_env() {
  migrate_legacy_env

  if [[ -f $ENV_FILE ]]; then
    info "$ENV_FILE already exists, leaving it unchanged"
    return
  fi

  local jwt_secret
  jwt_secret="$(generate_jwt_secret)"

  ensure_config_dir
  info "Creating $ENV_FILE"
  (
    umask 077
    tee "$ENV_FILE" >/dev/null <<EOF
# Containerlab API Server configuration.
# Edit this file, then start or restart the clab-api-server service.

API_PORT=8090
# Bind loopback by default. Set 0.0.0.0 or a specific host address only when remote access is intended.
API_LISTEN_ADDRESS=127.0.0.1
API_SERVER_HOST=localhost
LOG_LEVEL=info

# Authentication
JWT_SECRET=${jwt_secret}
JWT_EXPIRATION=24h
API_USER_GROUP=clab_api
SUPERUSER_GROUP=clab_admins

# Containerlab
CLAB_RUNTIME=docker
# Optional absolute root for managed lab workspaces.
# Files are stored under \$CLAB_LABS_ROOT/<username>/ when set.
#CLAB_LABS_ROOT=/var/lib/containerlab/labs

# Browser terminal sessions
TERMINAL_MAX_SESSIONS_PER_USER=128

# Browser access. Example: https://localhost:5173,https://ui.example.com
CORS_ALLOWED_ORIGINS=

# Gin
GIN_MODE=release
TRUSTED_PROXIES=

# TLS
TLS_ENABLE=true
TLS_AUTO_CERT=true
#TLS_CERT_FILE=/etc/clab-api-server/certs/server.pem
#TLS_KEY_FILE=/etc/clab-api-server/certs/server-key.pem
EOF
  )
  chmod 600 "$ENV_FILE"
}

create_default_groups() {
  local group

  need_cmd getent
  need_cmd groupadd

  for group in clab_api clab_admins; do
    if getent group "$group" >/dev/null; then
      info "Group $group already exists"
      continue
    fi

    groupadd "$group"
    info "Created group $group"
  done
}

download_binary() {
  local version="$1" arch="$2" url

  need_cmd curl
  install -d -m 755 "$BIN_DIR"

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
  curl -#fSL "$url" -o "${BIN_PATH}.tmp" || die "Download failed from $url"
  chmod +x "${BIN_PATH}.tmp"
  mv -f "${BIN_PATH}.tmp" "$BIN_PATH"
  info "Installed $BIN_PATH"
  "$BIN_PATH" -v || die "Installed binary failed to execute"
}

create_service() {
  need_cmd systemctl
  create_env

  info "Writing systemd unit $SERVICE_FILE"
  tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Containerlab API Server
Documentation=https://github.com/srl-labs/clab-api-server
Wants=network-online.target
After=network-online.target docker.service
ConditionPathExists=$BIN_PATH

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=$ENV_FILE
ExecStart=$BIN_PATH -env-file $ENV_FILE
Restart=on-failure
RestartSec=10
TimeoutStartSec=30

[Install]
WantedBy=multi-user.target
EOF

  chmod 644 "$SERVICE_FILE"
  systemctl daemon-reload
  info "Systemd unit installed"
}

remove_service() {
  if [[ -f $SERVICE_FILE ]]; then
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop "$SERVICE_NAME" 2>/dev/null || true
      systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    fi
    rm -f "$SERVICE_FILE"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload
      systemctl reset-failed "${SERVICE_NAME}.service" 2>/dev/null || true
    fi
    info "Removed systemd unit"
  fi
}

remove_binary() {
  if [[ -f $BIN_PATH ]]; then
    rm -f "$BIN_PATH"
    info "Removed $BIN_PATH"
  fi
}

purge_config() {
  local removed=""

  if [[ -f $ENV_FILE ]]; then
    rm -f "$ENV_FILE"
    removed=1
    info "Removed $ENV_FILE"
  fi

  if [[ -f $LEGACY_ENV_FILE ]]; then
    rm -f "$LEGACY_ENV_FILE"
    removed=1
    info "Removed $LEGACY_ENV_FILE"
  fi

  rmdir "$CONFIG_DIR" 2>/dev/null || true
  [[ -n $removed ]] || info "No config files found to purge"
}

usage() {
  cat <<USAGE
Usage: $0 [install|pull-only|upgrade|uninstall] [options]

Actions:
  install                  Install binary, config, and systemd unit
  pull-only                Install only the binary
  upgrade                  Replace binary with latest or requested version
  uninstall                Remove service and binary, keep config by default

Options:
  --version TAG            Install or upgrade to a specific release tag
  --start                  Enable and start service after install
  --yes, -y                Do not prompt during uninstall
  --purge                  During uninstall, also remove config files
  -h, --help               Show this help

Downgrade:
  Use "upgrade --version <older-release-tag>" to install an older release.
USAGE
}

ACTION="install"
VERSION="${VERSION:-}"
YES=""
START=""
PURGE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    install|pull-only|upgrade|uninstall)
      ACTION="$1"
      shift
      ;;
    --version)
      [[ $# -ge 2 ]] || die "--version requires an argument"
      VERSION="$2"
      shift 2
      ;;
    --start)
      START=1
      shift
      ;;
    --yes|-y)
      YES=1
      shift
      ;;
    --purge)
      PURGE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown argument: $1"
      ;;
  esac
done

[[ -z $START || $ACTION == "install" ]] || die "--start is only valid with install"
[[ -z $PURGE || $ACTION == "uninstall" ]] || die "--purge is only valid with uninstall"

need_root
ARCH="$(arch)"
info "Selected action: $ACTION${VERSION:+ (version $VERSION)}"

case "$ACTION" in
  pull-only)
    download_binary "$VERSION" "$ARCH"
    ;;

  install)
    download_binary "$VERSION" "$ARCH"
    create_default_groups
    create_service
    if [[ -n $START ]]; then
      systemctl enable --now "$SERVICE_NAME"
      info "Installation complete. Service is enabled and running."
    else
      info "Installation complete. Review $ENV_FILE, then run:"
      info "  sudo systemctl enable --now $SERVICE_NAME"
    fi
    ;;

  upgrade)
    need_cmd systemctl
    was_active=""
    if systemctl is-active --quiet "$SERVICE_NAME"; then
      was_active=1
      info "Stopping active service before upgrade"
      systemctl stop "$SERVICE_NAME"
    fi

    download_binary "$VERSION" "$ARCH"
    create_default_groups
    create_service

    if [[ -n $was_active ]]; then
      systemctl start "$SERVICE_NAME"
      info "Upgrade complete. Service was restarted."
    else
      info "Upgrade complete. Service was not running, so it was left stopped."
    fi
    ;;

  uninstall)
    if [[ -z $YES ]]; then
      if [[ -n $PURGE ]]; then
        read -r -p "Uninstall clab-api-server and purge config files? (y/N) " ans
      else
        read -r -p "Uninstall clab-api-server and keep config files? (y/N) " ans
      fi
      [[ $ans =~ ^[Yy]$ ]] || die "Aborted."
    fi

    remove_service
    remove_binary
    if [[ -n $PURGE ]]; then
      purge_config
    else
      if [[ -f $ENV_FILE ]]; then
        info "Config preserved at $ENV_FILE"
      elif [[ -f $LEGACY_ENV_FILE ]]; then
        info "Config preserved at $LEGACY_ENV_FILE"
      else
        info "No config file found to preserve"
      fi
    fi
    info "Uninstall complete."
    ;;

  *)
    die "Unhandled action: $ACTION"
    ;;
esac
