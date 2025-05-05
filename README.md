# Containerlab API Server

A standalone RESTful API server for managing [Containerlab](https://containerlab.dev/) deployments, enabling programmatic control and remote management of network labs.


---

## ✨ Features

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
* **Documentation:** Embedded Swagger UI and ReDoc for API exploration

---

## ⚙️ Prerequisites

| Requirement | Version / Notes |
|-------------|-----------------|
| **Containerlab** | **v0.68.0+**<br/>`clab` must be on the `PATH` of the user that runs the API server. |
| **Linux** | Any modern distribution. The binaries target **amd64** and **arm64**. |
| **PAM** | Uses the default `login` PAM service. No extra configuration needed on most distros. |
| **User / Group** | Linux groups must exist as defined in your `.env` (`API_USER_GROUP`, `SUPERUSER_GROUP`). |
| **Docker** | Required for containerized deployment or when using Docker as container runtime |

---

## 🚀 Deployment Options

The Containerlab API Server can be deployed in several ways:

### 1. Containerlab Tools Command

Use Containerlab's built-in command to manage the API server directly:

```bash
# Start the API server
containerlab tools api-server start [flags]

# Stop the API server
containerlab tools api-server stop

# Check API server status
containerlab tools api-server status
```

This method automatically handles Docker image pulling, container creation, and environment configuration. The API server provides a RESTful HTTP interface for managing Containerlab operations programmatically, including lab deployment, node management, and configuration tasks.

Common flags for the start command include:
- `--port | -p`: Port to expose the API server on (default: 8080)
- `--host`: Host address for the API server (default: localhost)
- `--labs-dir | -l`: Directory to mount as shared labs directory
- `--jwt-secret`: JWT secret key for authentication
- `--tls-enable`: Enable TLS for HTTPS connections

This is the simplest way to deploy the API server if you already have Containerlab installed.

Once the server is up and running, you can access the interactive API documentation at:
- Swagger UI: `http://<server_ip>:<API_PORT>/swagger/index.html`
- ReDoc UI: `http://<server_ip>:<API_PORT>/redoc`

### 2. Binary Installation

The simplest approach for direct installation on a Linux host:

```bash
curl -sL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo -E bash
```

This will:
- Download the appropriate binary for your architecture to `/usr/local/bin/clab-api-server`
- Create a default configuration at `/etc/clab-api-server.env`
- Create a systemd unit at `/etc/systemd/system/clab-api-server.service`

For post-installation steps, see the [Post-Install Configuration](#-post-install-configuration) section below.

### 3. Docker Deployment

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
  -v /usr/bin/containerlab:/usr/bin/containerlab:ro \
  -v /etc/passwd:/etc/passwd:ro \
  -v /etc/shadow:/etc/shadow:ro \
  -v /etc/group:/etc/group:ro \
  -v /etc/gshadow:/etc/gshadow:ro \
  -v /home:/home \
  ghcr.io/srl-labs/clab-api-server/clab-api-server:latest
```
> [!NOTE]
> Volume mounts enable Docker management, networking features, Linux PAM authentication, and user file storage.


### 4. Other Docker Deployment Options

The repository also includes support for Docker-in-Docker (DinD) and Docker-out-of-Docker (DooD) deployment models:

- **Docker-in-Docker (DinD)**: A fully isolated environment with its own Docker engine
- **Docker-out-of-Docker (DooD)**: Uses the host's Docker daemon for better performance

For these options, clone the repository and use the provided `clab-api-manager.sh` script:

```bash
git clone https://github.com/srl-labs/clab-api-server.git
cd clab-api-server
cp docker/common/.env.example docker/common/.env  # Edit as needed
./clab-api-manager.sh [dind|dood] start
```

## 🔧 Post-Install Configuration

1. **Edit the configuration**
   - For binary install: `/etc/clab-api-server.env`
   - For Docker install: `docker/common/.env`

   At a minimum, change `JWT_SECRET` to a strong random string and set `API_SERVER_HOST` to your server's IP/hostname.

2. **Enable & start the service** (for binary installation):

   ```bash
   sudo systemctl enable --now clab-api-server
   ```

3. **Verify**

   ```bash
   # For binary install
   sudo systemctl status clab-api-server

   # For Docker install
   ./clab-api-manager.sh [dind|dood] status
   ./clab-api-manager.sh [dind|dood] logs
   ```

## 🗄️ Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `8080` | Server listening port |
| `API_SERVER_HOST` | `localhost` | Hostname/IP used in SSH access URLs |
| `JWT_SECRET` | `please_change_me` | **CRITICAL**: Secret key for JWT token generation |
| `JWT_EXPIRATION` | `60m` | JWT token lifetime (e.g., "60m", "24h") |
| `API_USER_GROUP` | `clab_api` | Linux group for API access |
| `SUPERUSER_GROUP` | `clab_admins` | Linux group for elevated privileges |
| `CLAB_RUNTIME` | `docker` | Container runtime used by Containerlab |
| `LOG_LEVEL` | `info` | Log verbosity (`debug`, `info`, `warn`, `error`) |
| `GIN_MODE` | `release` | Web framework mode (`debug` or `release`) |
| `SSH_BASE_PORT` | `2223` | Starting port for SSH proxy allocation |
| `SSH_MAX_PORT` | `2322` | Maximum port for SSH proxy allocation |
| `TLS_ENABLE` | `false` | Enable TLS for HTTPS |
| `TLS_CERT_FILE` | | Path to TLS certificate when enabled |
| `TLS_KEY_FILE` | | Path to TLS private key when enabled |

## 🔐 Authentication

The Containerlab API Server uses Linux system users and passwords for authentication. Users must:

* Exist as valid Linux users on the system where the API server runs
* Belong to the configured `API_USER_GROUP` (`clab_api` by default) or `SUPERUSER_GROUP` (`clab_admins` by default)

When authenticating via the API, provide the Linux username and password to receive a JWT token for subsequent requests.

## 📡 Managing Docker Deployments

For the simple Docker deployment, use standard Docker commands:

```bash
# Basic commands
docker start clab-api-server    # Start the service
docker stop clab-api-server     # Stop the service
docker restart clab-api-server  # Restart the service
docker ps -f name=clab-api-server  # Check service status
docker logs clab-api-server     # View logs
docker logs -f clab-api-server  # Follow logs
```

For DinD/DooD deployments, use the provided management script:

```bash
# Basic commands
./clab-api-manager.sh [dind|dood] start    # Start the service
./clab-api-manager.sh [dind|dood] stop     # Stop the service
./clab-api-manager.sh [dind|dood] logs     # View logs

# Data persistence commands
./clab-api-manager.sh [dind|dood] backup   # Create a backup
./clab-api-manager.sh [dind|dood] restore <backup-file>  # Restore from backup
```

## 🛡️ Privilege Model & Security

* **Server user** – The process runs with permissions to execute `clab` and access the container runtime.
* **Authenticated users** – Must be members of `API_USER_GROUP` or `SUPERUSER_GROUP`.
* **Command execution** – All commands run as the server user, not the authenticated user.
* **Ownership** – Lab ownership is tracked via container labels.
* **SSH sessions** – Allocated ports forward to container port 22 with automatic expiration.
* **Security controls** – PAM for credential validation, JWT for session management, input validation, and optional TLS.

## 📝 API Documentation

Access interactive API documentation at:

```
http://<server_ip>:<API_PORT>/swagger/index.html  # Swagger UI
http://<server_ip>:<API_PORT>/redoc               # ReDoc UI
```

## 🚀 API Usage Example

```bash
# Authenticate with your Linux username and password
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"your_linux_username","password":"your_linux_password"}' \
  | jq -r '.token')

# List labs
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/labs

# Deploy a lab
curl -X POST http://localhost:8080/api/v1/labs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonTopology":{"name":"srl01","topology":{"kinds":{"nokia_srlinux":{"type":"ixrd3","image":"ghcr.io/nokia/srlinux"}},"nodes":{"srl1":{"kind":"nokia_srlinux"},"srl2":{"kind":"nokia_srlinux"}},"links":[{"endpoints":["srl1:e1-1","srl2:e1-1"]}]}}}'
```

## 🔌 Flashpost Collection

[Flashpost](https://marketplace.visualstudio.com/items?itemName=VASubasRaj.flashpost) is a free alternative to [Postman](https://www.postman.com/) that runs entirely in VS Code as an extension.

The examples folder contains a Flashpost collection that demonstrates how to use the Containerlab API. The collection provides ready-to-use requests for all API endpoints.

The collection assumes that the server is running on `localhost:8080`, but you can change the server URL via a variable.

To use the collection:

1. Install the [Flashpost VS Code extension](https://marketplace.visualstudio.com/items?itemName=VASubasRaj.flashpost)
2. Import the collection from the json file in the examples folder

### Variables

The collection makes use of the following variables:

* `USER_NAME` - Linux user name that client will use for authentication with the clab api server
* `USER_PASSWORD` - Linux user password that client will use for authentication with the clab api server
* `baseUrl` - for example: `localhost:8080`

## 👩‍💻 Development

For development setup:

```bash
git clone https://github.com/srl-labs/clab-api-server.git
cd clab-api-server
cp .env.example .env      # edit JWT_SECRET

# build & run
task                      # tidy → swag docs → build binary
./clab-api-server
```

## 📜 License

Distributed under the **Apache 2.0** license. See `LICENSE` for details.