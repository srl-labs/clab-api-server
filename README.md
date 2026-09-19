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
> Volume mounts enable Docker management, networking features, Linux PAM authentication, and user file storage. Host PID mode also lets the API server keep the lab host's `/etc/hosts` entries synchronized. No containerlab binary is required - it's integrated as a Go library.

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
| `API_SERVER_HOST` | `localhost` | Hostname/IP used in SSH access URLs |
| `TERMINAL_MAX_SESSIONS_PER_USER` | `128` | Maximum active browser terminal sessions per API user |
| `JWT_SECRET` | generated by installer | **CRITICAL**: Secret key for JWT token generation |
| `JWT_EXPIRATION` | `24h` | JWT token lifetime (e.g., "24h", "7d") |
| `API_USER_GROUP` | `clab_api` | Linux group for API access |
| `SUPERUSER_GROUP` | `clab_admins` | Linux group for elevated privileges |
| `CLAB_RUNTIME` | `docker` | Container runtime used by Containerlab |
| `CLAB_LABS_ROOT` | unset | Optional absolute root for managed lab workspaces. When set, users store labs under `$CLAB_LABS_ROOT/<username>/`; otherwise labs use `<home>/.clab/`. |
| `CLAB_SHARED_LABS_ROOT` | unset | Optional absolute folder shared by all authenticated API users, exposed as `@shared/` in workspace and topology file paths. |
| `CLAB_HOSTS_FILE` | unset | Optional absolute host-visible hosts file to synchronize. The container entrypoint detects `/proc/1/root/etc/hosts` automatically when running with host PID mode. |
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
* **Library integration** – Containerlab is embedded as a Go library, not executed as a separate CLI process.
* **Ownership** – Lab ownership is tracked via container labels. Regular users manage their own labs and labs in `CLAB_SHARED_LABS_ROOT`; superusers can manage all labs.
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

The standalone UI uses these authenticated endpoints:

- `GET /api/v1/labs/topology/files` - recursively list editable topology files
- `GET|PUT /api/v1/labs/{labName}/topology/yaml` - read/write the running lab topology or the canonical undeployed topology (`<lab>.clab.yml`)
- `GET|PUT /api/v1/labs/{labName}/topology/annotations` - read/write the corresponding canonical annotations
- `GET|PUT|DELETE|HEAD /api/v1/labs/{labName}/topology/file?path=<relativePath>` - file operations using paths returned by the listing
- `POST /api/v1/labs/{labName}/topology/file/rename` - rename a file
- `POST /api/v1/labs/{labName}/deploy?path=<relativePath>` - deploy a selected on-disk topology

You can keep multiple topologies and shared artifacts in one Git repository under
`~/.clab` (or `CLAB_LABS_ROOT/<username>`). Discovery includes every `*.clab.yml`
and `*.clab.yaml` file in nested directories. For example, `repo/labs/topology1.clab.yaml`
and `repo/labs/topology2.clab.yaml` appear as separate entries:

```json
{
  "labName": "topology1",
  "yamlFileName": "repo/labs/topology1.clab.yaml",
  "annotationsFileName": "repo/labs/topology1.clab.yaml.annotations.json",
  "hasAnnotations": false,
  "deploymentState": "undeployed"
}
```

`yamlFileName` and `annotationsFileName` are paths relative to the managed workspace
root. Use the complete returned path to open, edit, deploy, or annotate that
specific topology, including when different repositories use the same filename.
For example, deploy the entry above with:

```bash
curl -k -X POST -H "Authorization: Bearer <token>" \
  'https://localhost:8090/api/v1/labs/topology1/deploy?path=repo%2Flabs%2Ftopology1.clab.yaml'
```

Existing flat and one-directory-per-lab workspaces keep their lab names, and legacy
lab-relative file requests still work. Explicit workspace paths take precedence
when their first directory exists in the workspace. New repository entries use
the YAML `name`, falling back to the filename when necessary. The path identifies
the document; lab names must still be distinct to deploy labs simultaneously.
Hidden files/directories (including `.git`), `node_modules`, `__pycache__`, symbolic
links, and runtime directories containing `.state.clab.yaml` or `topology-data.json`
are excluded from discovery. Repositories named `clab-*` remain discoverable.

Enable browser access by setting `CORS_ALLOWED_ORIGINS` (for example `https://localhost:5173`).

### Shared labs

Set `CLAB_SHARED_LABS_ROOT=/var/lib/containerlab/shared-labs` in the server's
environment and restart it to enable a shared workspace. Use a dedicated absolute
folder separate from personal workspaces. For a containerized server, mount this
folder at the same absolute path on the host and inside the server container.
Leave the setting empty to keep sharing disabled.

Every authenticated API user can read, edit, deploy, operate, and destroy labs in
this folder. This grants access to all API users; it does not define per-user or
per-group sharing rules. Personal labs keep their existing access rules. File
access through the API does not require changing Linux users' group memberships.

The folder appears as `@shared` in the workspace tree. Topology discovery includes
shared files with paths such as `@shared/demo/demo.clab.yml`, including when the
lab is undeployed. Create the directory and upload a topology through the existing
workspace endpoints, then deploy the returned path:

```bash
curl -k -X POST -H "Authorization: Bearer <token>" \
  -H 'Content-Type: application/json' -d '{"path":"@shared/demo"}' \
  https://localhost:8090/api/v1/labs/workspace/directory

curl -k -X PUT -H "Authorization: Bearer <token>" \
  --data-binary @demo.clab.yml \
  'https://localhost:8090/api/v1/labs/workspace/file?path=%40shared%2Fdemo%2Fdemo.clab.yml'

curl -k -X POST -H "Authorization: Bearer <token>" \
  'https://localhost:8090/api/v1/labs/demo/deploy?path=%40shared%2Fdemo%2Fdemo.clab.yml'
```

Another API user can now access `/api/v1/labs/demo`, its nodes, topology documents,
and events. Redeploying or reconfiguring a shared lab preserves the deployment
owner. To reconfigure, use the on-disk deploy endpoint with the same shared path
and `reconfigure=true`. Direct JSON, archive, and URL deployment endpoints continue
to create personal labs. Lab names must be unique across running labs.

Destroying a lab keeps its source available to collaborators. With
`purgeLabDir=true`, its topology parent directory is also deleted, provided it is
below the shared root; the shared root itself cannot be purged. Moves between
personal and shared workspaces are rejected. Terminal, SSH, and capture sessions
remain private to the user who creates them, with existing superuser access.

To run the shared-lab integration tests, configure the server as above and run
`GOTEST_SHARED_LABS=true go test -count=1 ./tests_go -run TestSharedLabsSuite`.
The tests use `tests_go/.env` and create and remove a temporary second API user.

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
