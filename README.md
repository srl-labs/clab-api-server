# Containerlab API Server

A standalone RESTful API server for managing [Containerlab](https://containerlab.dev/) deployments, enabling programmatic control and remote management of network labs.

---

## Features

* **Lab Management:** Deploy, destroy, redeploy, inspect, and list labs
* **Node Operations:** Execute commands and save configurations
* **SSH Access:** Connect to lab nodes via SSH through the API server
* **Topology Tools:** Generate and deploy CLOS topologies
* **Network Tools:** Manage network emulation, virtual Ethernet pairs, VxLAN tunnels
* **Certification Tools:** Certificate management
* **User Management:** Create, update, delete users and manage permissions using Linux system accounts
* **Health Monitoring:** Check server health status and system metrics
* **Logs:** Check logs of the nodes, static or streaming
* **User Context:** Track ownership and manage files within user home directories
* **Multitenancy:** Support for multiple users with separate access to labs
* **Standalone Topology Editing:** File-scoped topology endpoints for browser UI integration
* **Documentation:** Embedded Swagger UI and ReDoc for API exploration


The latest API endpoints documentation is published on GitHub Pages:
**[Containerlab API Server Documentation](https://srl-labs.github.io/clab-api-server/)**


---

## Prerequisites

| Requirement | Version / Notes |
|-------------|-----------------|
| **Linux** | Any modern distribution. The binaries target **amd64** and **arm64**. |
| **PAM** | Uses the default `login` PAM service. No extra configuration needed on most distros. |
| **User / Group** | Users must belong to the configured API or superuser group. The installer creates the default groups. |
| **Docker** | Required for containerized deployment or when using Docker as container runtime |

> [!NOTE]
> The API server uses containerlab as an integrated Go library - no separate `containerlab` binary installation is required.

---

## Deployment Options

Choose the method that matches how long the API server should live:

| Method | Best for | Notes |
|--------|----------|-------|
| **Systemd installer** | Persistent lab hosts and GUI backends | Recommended for normal use. |
| **Containerlab tools command** | Quick trials, demos, temporary access | Starts the API server as a container. |
| **Direct binary / pull-only** | Debugging or custom supervision | You manage config and process lifetime. |
| **Docker run** | Advanced container-managed deployments | You manage mounts, config, and lifecycle. |

### 1. Systemd Installer

Install the latest release. The installer selects the correct `amd64` or `arm64` binary automatically:

```bash
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- install
```

If the host needs a proxy to reach GitHub or other external endpoints, export the standard proxy variables and preserve them for the root-side installer:

```bash
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080
export NO_PROXY=localhost,127.0.0.1
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo -E bash -s -- install
```

This will:
- Download the binary to `/usr/local/bin/clab-api-server`
- Create a default configuration at `/etc/clab-api-server/clab-api-server.env`
- Create a systemd unit at `/etc/systemd/system/clab-api-server.service`
- Create the default Linux groups `clab_api` and `clab_admins` if they do not exist
- Generate a random `JWT_SECRET` for new installations

Review the configuration and add users to the API group before starting the service:

```bash
sudoedit /etc/clab-api-server/clab-api-server.env
sudo usermod -aG clab_api <username>
sudo systemctl enable --now clab-api-server
```

For proxy environments, also add `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` to `/etc/clab-api-server/clab-api-server.env` before starting the service. If you used `install --start`, restart `clab-api-server` after editing the file.

For an immediate start with the generated defaults, use `install --start`.

The systemd service runs as `root` because the API server controls host container runtime resources, network namespaces, Linux users, and lab files.

By default, managed topology files are stored under each Linux user's `~/.clab` directory. To store GUI-created and API-managed lab workspaces somewhere else, set `CLAB_LABS_ROOT` in `/etc/clab-api-server/clab-api-server.env` to an absolute path, for example:

```bash
CLAB_LABS_ROOT=/var/lib/containerlab/labs
```

With that setting, files are stored under `/var/lib/containerlab/labs/<username>/`. `~` expansion is not supported because the service runs as `root` while authenticating separate Linux users.

### 2. Containerlab Tools Command

Use Containerlab's built-in command for quick trials or temporary API access:

```bash
# Start the API server as a container
sudo containerlab tools api-server start [flags]

# Stop the API server container
sudo containerlab tools api-server stop

# Check API server container status
sudo containerlab tools api-server status
```

This method automatically handles Docker image pulling, container creation, and environment configuration.

Common flags for the start command include:
- `--port | -p`: Port to expose the API server on (default: `8090`)
- `--host`: Host address for the API server (default: `localhost`)
- `--labs-dir | -l`: Directory to mount as the managed labs root
- `--jwt-secret`: JWT secret key for authentication, generated randomly if unset
- `--tls-enable`: Enable TLS for HTTPS connections, enabled by default

> [!NOTE]
> The standalone systemd install and the Containerlab tools helper both default to port `8090` and HTTPS.

Native and systemd installs bind `127.0.0.1` by default. To accept connections from a container or another host, set `API_LISTEN_ADDRESS` to the specific host address, or to `0.0.0.0` when all interfaces are intentionally required. `API_SERVER_HOST` remains the advertised hostname used in generated SSH access details and TLS certificate names; it does not control the listener.

When `TLS_AUTO_CERT=true`, the server logs the path and SHA-256 fingerprint of a reusable self-signed public certificate. Clients such as `vscode-containerlab` can show that fingerprint for first-use, endpoint-scoped approval without modifying the operating-system trust store. Clients without certificate pinning must explicitly trust the PEM, configure it as a private CA, or opt into disabled verification for an isolated development endpoint. The certificate is not a public CA chain and is intentionally not installed into the host trust store automatically. Production and remote deployments should set `TLS_CERT_FILE` and `TLS_KEY_FILE` to a certificate chain issued by their normal private or public CA.

### 3. Direct Binary / Pull-Only

Use `pull-only` when you only want the architecture-specific binary:

```bash
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- pull-only
```

Then run it with your own process management:

```bash
sudo clab-api-server -env-file /path/to/clab-api-server.env
```

Configure via environment variables or a `.env` file. See [`.env.example`](./.env.example) and the [Configuration Reference](#configuration-reference) for available options.

If using proxy environment variables with a direct `sudo` run, preserve them with `sudo -E`.

### 4. Docker Deployment

Run the API server as a Docker container with access to the host resources:

```bash
docker run -d \
  --name clab-api-server \
  --privileged \
  --network host \
  --pid host \
  -e API_LISTEN_ADDRESS=0.0.0.0 \
  -e LOG_LEVEL=debug \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /var/run/netns:/var/run/netns \
  -v /var/lib/docker/containers:/var/lib/docker/containers \
  -v /etc/passwd:/etc/passwd:ro \
  -v /etc/shadow:/etc/shadow:ro \
  -v /etc/group:/etc/group:ro \
  -v /etc/gshadow:/etc/gshadow:ro \
  -v /home:/home \
  ghcr.io/srl-labs/clab-api-server/clab-api-server:latest
```
> [!NOTE]
> Volume mounts enable Docker management, networking features, Linux PAM authentication, and user file storage. No containerlab binary is required - it's integrated as a Go library.

The image does not contain a default API account or configuration file. PAM users and groups come from the mounted host account databases. When `JWT_SECRET` is unset, the entrypoint generates a cryptographically random secret for that container instance; you may instead provide a persistent secret of at least 32 random characters for explicit secret management. Tokens are tied to the issuing server process start and are invalidated on restart, so active-active replicas cannot share bearer sessions even when configured with the same secret; use a single API replica (or sticky routing with re-authentication). Placeholder and short secrets are rejected at startup.

This Docker example uses the default managed lab storage: each authenticated user's `~/.clab` directory from the mounted `/home`. To use a different root, add both `CLAB_LABS_ROOT` and a matching volume mount:

```bash
  -e CLAB_LABS_ROOT=/var/lib/containerlab/labs \
  -v /var/lib/containerlab/labs:/var/lib/containerlab/labs \
```

## Lifecycle Management

Check for a newer API server release and upgrade the installed binary:

```bash
clab-api-server version check
sudo clab-api-server version upgrade
```

The installer can also upgrade to latest or replace the binary with a specific release tag. Installing an older tag is the supported downgrade path:

```bash
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- upgrade
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- upgrade --version clab-0.73.0-api-0.2.1
```

Upgrade stops and restarts the service only if it was running before the upgrade.

Uninstall removes the service and binary while keeping configuration by default:

```bash
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- uninstall
```

Remove the configuration intentionally with `--purge`:

```bash
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- uninstall --purge
```

After startup, verify the service:

```bash
sudo systemctl status clab-api-server
```

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `8090` | Server listening port |
| `API_LISTEN_ADDRESS` | `127.0.0.1` | Network address to bind. Set a specific host address or `0.0.0.0` only when container/remote access is intended. The published container image overrides this to `0.0.0.0`. |
| `API_SERVER_HOST` | `localhost` | Hostname/IP used in SSH access URLs |
| `TERMINAL_MAX_SESSIONS_PER_USER` | `128` | Maximum active browser terminal sessions per API user |
| `JWT_SECRET` | generated by installer | **CRITICAL**: Secret key for JWT token generation. Must contain at least 32 characters and must not be a placeholder. The Docker entrypoint generates an ephemeral value when unset. |
| `JWT_EXPIRATION` | `24h` | JWT token lifetime (e.g., "24h", "7d") |
| `API_USER_GROUP` | `clab_api` | Linux group for API access |
| `SUPERUSER_GROUP` | `clab_admins` | Linux group for elevated privileges |
| `CLAB_RUNTIME` | `docker` | Container runtime used by Containerlab |
| `CLAB_LABS_ROOT` | unset | Optional absolute root for managed lab workspaces. When set, users store labs under `$CLAB_LABS_ROOT/<username>/`; otherwise labs use `<home>/.clab/`. |
| `LOG_LEVEL` | `info` | Log verbosity (`debug`, `info`, `warn`, `error`) |
| `CORS_ALLOWED_ORIGINS` | | Comma-separated browser origin allowlist (for standalone UI) |
| `GIN_MODE` | `release` | Web framework mode (`debug` or `release`) |
| `SSH_BASE_PORT` | `2223` | Starting port for SSH proxy allocation |
| `SSH_MAX_PORT` | `2322` | Maximum port for SSH proxy allocation |
| `TLS_ENABLE` | `true` | Enable TLS for HTTPS |
| `TLS_AUTO_CERT` | `true` | Generate/reuse a local self-signed certificate when cert/key files are unset |
| `TLS_CERT_FILE` | | Path to TLS certificate when overriding auto certificate generation |
| `TLS_KEY_FILE` | | Path to TLS private key when overriding auto certificate generation |

## Authentication

The Containerlab API Server uses Linux system users and passwords for authentication. Users must:

* Exist as valid Linux users on the system where the API server runs
* Belong to the configured `API_USER_GROUP` (`clab_api` by default) or `SUPERUSER_GROUP` (`clab_admins` by default)

When authenticating via the API, provide the Linux username and password to receive a JWT token for subsequent requests.

## Privilege Model & Security

* **Server user** – The process runs with permissions to access the container runtime.
* **Authenticated users** – Must be members of `API_USER_GROUP` or `SUPERUSER_GROUP`.
* **Bearer-token lifetime** – Basic API group membership is checked when a token is issued. Existing tokens remain valid until their configured expiry or a server restart, so choose `JWT_EXPIRATION` accordingly. Superuser authorization is evaluated against current group membership for each privileged action.
* **Library integration** – Containerlab is embedded as a Go library, not executed as a separate CLI process.
* **Lifecycle concurrency** – Operations that depend on containerlab's process-wide working directory or owner environment are intentionally serialized. This prevents one user's request from observing another user's path or identity state; read-only runtime operations that do not use that state remain concurrent.
* **Archive safety** – Lab archives are extracted into a scoped staging directory, limited to 10,000 entries and 256 MiB compressed/uncompressed content, then validated and swapped into place. The prior workspace is retained until containerlab accepts the replacement and is restored if deployment fails. Top-level `.archive-*` and `.backup-*` names are reserved for this internal transaction state; workspace APIs hide them and reject direct access. Path traversal, duplicate paths, symbolic links, hard links, and special files are rejected.
* **Ownership** – Lab ownership is tracked via container labels.
* **SSH sessions** – Allocated ports forward to container port 22 with automatic expiration.
* **Security controls** – PAM for credential validation, JWT for session management, input validation, and HTTPS by default.

## API Documentation

Access interactive API documentation at:

```
https://<server_ip>:<API_PORT>/swagger/index.html  # Swagger UI
https://<server_ip>:<API_PORT>/redoc               # ReDoc UI
```

## API Usage Example

```bash
# Authenticate with your Linux username and password
TOKEN=$(curl -sk -X POST https://localhost:8090/login \
  -H "Content-Type: application/json" \
  -d '{"username":"your_linux_username","password":"your_linux_password"}' \
  | jq -r '.token')

# Optional: request a custom token lifetime for this login
TOKEN_CUSTOM=$(curl -sk -X POST https://localhost:8090/login \
  -H "Content-Type: application/json" \
  -d '{"username":"your_linux_username","password":"your_linux_password","sessionDuration":"36h"}' \
  | jq -r '.token')

# List labs
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8090/api/v1/labs

# Deploy a lab
curl -k -X POST https://localhost:8090/api/v1/labs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"topologyContent":{"name":"srl01","topology":{"kinds":{"nokia_srlinux":{"type":"ixrd3","image":"ghcr.io/nokia/srlinux"}},"nodes":{"srl1":{"kind":"nokia_srlinux"},"srl2":{"kind":"nokia_srlinux"}},"links":[{"endpoints":["srl1:e1-1","srl2:e1-1"]}]}}}'
```

## Standalone UI Endpoints

The standalone `containerlab-gui` app uses these authenticated endpoints:

- `GET /api/v1/topologies` - list editable topology files for the user
- `GET|PUT /api/v1/topologies/{labName}/yaml` - read/write canonical topology YAML (`<lab>.clab.yml`)
- `GET|PUT /api/v1/topologies/{labName}/annotations` - read/write canonical annotations JSON (`<lab>.clab.yml.annotations.json`)
- `GET|PUT|DELETE|HEAD /api/v1/topologies/{labName}/file?path=<relativePath>` - scoped file operations inside the lab directory
- `POST /api/v1/topologies/{labName}/file/rename` - scoped rename operation
- `POST /api/v1/topologies/{labName}/deploy` - deploy an on-disk topology by lab name

Enable browser access by setting `CORS_ALLOWED_ORIGINS` (for example `https://localhost:5173`).

## Flashpost Collection

[Flashpost](https://marketplace.visualstudio.com/items?itemName=VASubasRaj.flashpost) is a free alternative to [Postman](https://www.postman.com/) that runs entirely in VS Code as an extension.

The examples folder contains a Flashpost collection that demonstrates how to use the Containerlab API. The collection provides ready-to-use requests for all API endpoints.

The collection assumes that the server is running on `localhost:8090`, but you can change the server URL via a variable.

To use the collection:

1. Install the [Flashpost VS Code extension](https://marketplace.visualstudio.com/items?itemName=VASubasRaj.flashpost)
2. Import the collection from the json file in the examples folder

### Variables

The collection makes use of the following variables:

* `USER_NAME` - Linux user name that client will use for authentication with the clab api server
* `USER_PASSWORD` - Linux user password that client will use for authentication with the clab api server
* `baseUrl` - for example: `localhost:8090`

## Development

For development setup:

```bash
git clone https://github.com/srl-labs/clab-api-server.git
cd clab-api-server
cp .env.example .env      # edit JWT_SECRET

# build & run
task                      # tidy → swag docs → build binary
./clab-api-server
```
