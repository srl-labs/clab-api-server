# Containerlab API Server

A standalone RESTful API server for managing [Containerlab](https://containerlab.dev/) deployments, enabling programmatic control and remote management of network labs.

> 📚 **Looking for detailed integration information?** Check out the [Integration Guide](docs/integration_guide.md) for in-depth documentation on architecture, deployment models, and configuration details.

---

## ✨ Features

* **Lab Management:** Deploy, destroy, redeploy, inspect, and list labs
* **Node Operations:** Execute commands and save configurations
* **SSH Access:** Connect to lab nodes via SSH through the API server
* **Topology Tools:** Generate and deploy CLOS topologies
* **Network Tools:** Manage network emulation, virtual Ethernet pairs, VxLAN tunnels
* **Certification Tools:** Certificate management
* **User Management:** Create, update, delete users and manage permissions
* **Health Monitoring:** Check server health status and system metrics
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

> [!NOTE]
> Containerlab 0.68.0+ is not available yet, but the 0.1.0 release of the clab‑api‑server is compatible with Containerlab 0.67.0.

## 🚀 Deployment Options

The Containerlab API Server can be deployed in three primary ways:

### 1. Binary Installation (Recommended for Production)

The simplest approach for direct installation on a Linux host:

```bash
curl -sL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo -E bash
```

This will:
- Download the appropriate binary for your architecture to `/usr/local/bin/clab-api-server`
- Create a default configuration at `/etc/clab-api-server.env`
- Create a systemd unit at `/etc/systemd/system/clab-api-server.service`

For post-installation steps, see the [Post-Install Configuration](#-post-install-configuration) section below.

### 2. Docker-in-Docker (DinD) Deployment

A fully self-contained Docker solution with its own internal Docker engine:

```bash
# Clone the repository
git clone https://github.com/srl-labs/clab-api-server.git
cd clab-api-server

# Configure environment variables
cp docker/common/.env.example docker/common/.env
nano docker/common/.env  # Edit configuration as needed

# Build the Docker image
docker compose -f docker/dind/docker-compose.yml build

# Start the service
./clab-api-manager.sh dind start
```

**Advantages:**
- Completely isolated environment
- No need to mount the host Docker socket
- Clean separation between host and API container

**Considerations:**
- Additional performance overhead
- Double-nested containers
- Docker storage managed within a volume

### 3. Docker-out-of-Docker (DooD) Deployment

Uses the host's Docker daemon for better performance:

```bash
# Clone the repository
git clone https://github.com/srl-labs/clab-api-server.git
cd clab-api-server

# Configure environment variables
cp docker/common/.env.example docker/common/.env
nano docker/common/.env  # Edit configuration as needed

# Build the Docker image
docker compose -f docker/dood/docker-compose.yml build

# Start the service
./clab-api-manager.sh dood start
```

**Advantages:**
- Better performance compared to DinD
- Access to host's existing images
- Single Docker layer

**Considerations:**
- Requires privileged access to host Docker socket
- Shared resource space with the host
- Potential security implications

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

## 📡 Managing Containerized Deployments

The `clab-api-manager.sh` script simplifies managing Docker deployments:

```bash
# Basic commands (replace [dind|dood] with your preferred implementation)
./clab-api-manager.sh [dind|dood] start    # Start the service
./clab-api-manager.sh [dind|dood] stop     # Stop the service
./clab-api-manager.sh [dind|dood] restart  # Restart the service
./clab-api-manager.sh [dind|dood] status   # Check service status
./clab-api-manager.sh [dind|dood] logs     # View logs
./clab-api-manager.sh [dind|dood] logs -f  # Follow logs

# Data persistence commands
./clab-api-manager.sh [dind|dood] backup                 # Create a backup
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
# Authenticate and get token
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}' \
  | jq -r '.token')

# List labs
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/labs

# Deploy a lab
curl -X POST http://localhost:8080/api/v1/labs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "topologyContent": "name: simple-lab\ntopology:\n  nodes:\n    router1:\n      kind: linux\n    router2:\n      kind: linux\n  links:\n    - endpoints: [\"router1:eth1\", \"router2:eth1\"]"
  }'
```

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