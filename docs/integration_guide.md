# Containerlab API Server Integration Guide

## Introduction

The Containerlab API Server provides a RESTful API interface for managing [Containerlab](https://containerlab.dev/) deployments, enabling programmatic control over network labs. This comprehensive guide explains the architecture, deployment options, configuration details, and operational considerations to help you successfully integrate the API server into your environment.

## Architectural Concepts

### Core Components

The Containerlab API Server consists of several key components:

1. **API Server Process**: A Go-based HTTP server that provides the RESTful API endpoints
2. **Authentication System**: PAM-based Linux user authentication with JWT tokens for session management
3. **Command Execution Engine**: Interfaces with the containerlab CLI (`clab`) to perform operations
4. **SSH Proxy Manager**: Manages SSH tunnels to lab nodes via port forwarding
5. **User Context Manager**: Tracks user ownership and manages file operations

### Deployment Models

The server can be deployed in three primary configurations:

1. **Binary Installation**
   - Direct installation on a Linux host
   - Runs as a system service (typically systemd)
   - Interacts directly with the host's container runtime
   - Recommended for production environments

2. **Docker-in-Docker (DinD)**
   - Runs within a Docker container with its own Docker daemon
   - Fully self-contained solution with complete isolation
   - Labs run inside containers that are themselves inside the API container
   - Useful for testing, development, or when strict isolation is required

3. **Docker-out-of-Docker (DooD)**
   - Runs within a Docker container but uses the host's Docker daemon
   - Better performance than DinD with fewer isolation layers
   - Requires privileged access to the host Docker socket
   - Good balance of isolation and performance for most use cases

### User Privilege Model

The API server employs a hybrid model for privileges:

- **Server Process User**: The user under which the clab-api-server process runs
  - Needs Docker permissions or membership in the Docker group
  - Executes all containerlab commands and manages SSH tunnels
  - For binary installation, defined in the systemd unit file
  - For containerized installation, runs as the container user

- **Authenticated API Users**: Linux users authenticated via PAM
  - Must belong to either `API_USER_GROUP` or `SUPERUSER_GROUP`
  - Can only see and manage their own labs unless they're superusers
  - Passwords validated against the Linux PAM system

- **Lab Ownership and Context**
  - Labs deployed through the API are tagged with ownership information
  - The API server tracks ownership via Docker labels
  - Each user has their own context for lab files and configurations

### Data Persistence Architecture

The API server stores data in several locations depending on deployment mode:

#### Binary Installation
- **Configuration**: Central config in `/etc/clab-api-server.env`
- **User Home Directories**: Lab files and topologies stored in each user's `~/.clab/` directory
- **Container Data**: Normal Docker storage on the host

#### Docker-in-Docker (DinD)
- **Configuration**: Environment file at `docker/common/.env`
- **User Home Directories**: Stored in the `clab-api-home-data` Docker volume
- **User Account Info**: Persisted in the `clab-api-config-data` Docker volume
- **Inner Docker Data**: Stored in the `clab-api-dind-data` Docker volume

#### Docker-out-of-Docker (DooD)
- **Configuration**: Environment file at `docker/common/.env`
- **User Home Directories**: Stored in the `clab-api-home-data` Docker volume
- **User Account Info**: Persisted in the `clab-api-config-data` Docker volume
- **Container Data**: Uses the host's Docker storage

## Detailed Deployment Guide

### Binary Installation

#### Prerequisites
- Linux system (amd64 or arm64)
- Containerlab (v0.68.0+)
- Docker or another container runtime
- PAM authentication working for Linux users

#### Installation Steps

1. **Run the installation script**:
   ```bash
   curl -sL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo -E bash
   ```

2. **Configure the server**:
   ```bash
   sudo vi /etc/clab-api-server.env
   ```

   Critical settings to modify:
   - `JWT_SECRET`: Set to a strong random string
   - `API_SERVER_HOST`: Set to the server's IP address or hostname
   - `API_USER_GROUP` and `SUPERUSER_GROUP`: Verify these groups exist

3. **Create required Linux groups** (if they don't exist):
   ```bash
   sudo groupadd clab_api
   sudo groupadd clab_admins
   ```

4. **Create an initial admin user**:
   ```bash
   sudo useradd -m -s /bin/bash admin
   sudo passwd admin
   sudo usermod -aG clab_admins admin
   ```

5. **Enable and start the service**:
   ```bash
   sudo systemctl enable --now clab-api-server
   ```

6. **Verify operation**:
   ```bash
   sudo systemctl status clab-api-server
   curl http://localhost:8080/health
   ```

#### Advanced Binary Configuration

The systemd unit created by the install script includes several important settings:

```
[Unit]
Description=Containerlab API Server
After=network.target
Wants=network.target

[Service]
User=root  # Consider using a dedicated non-root user with Docker access
WorkingDirectory=/usr/local/bin
ExecStart=/usr/local/bin/clab-api-server -env-file /etc/clab-api-server.env
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

You can modify this unit file to use a dedicated non-root user with Docker access instead of root:

```bash
# Create a dedicated user
sudo useradd -m -s /bin/bash clab-api
sudo usermod -aG docker clab-api

# Update the systemd unit
sudo sed -i 's/User=root/User=clab-api/' /etc/systemd/system/clab-api-server.service
sudo systemctl daemon-reload
sudo systemctl restart clab-api-server
```

### Docker-in-Docker (DinD) Deployment

#### Prerequisites
- Linux system with Docker
- Docker Compose (v2.x preferred)

#### Deployment Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/srl-labs/clab-api-server.git
   cd clab-api-server
   ```

2. **Configure environment**:
   ```bash
   cp docker/common/.env.example docker/common/.env
   nano docker/common/.env
   ```

   Critical settings:
   - `JWT_SECRET`: Set to a strong random string
   - `API_SERVER_HOST`: Set to the server's IP address or hostname
   - `API_PORT`: Server listening port (default: 8080)
   - `SSH_BASE_PORT` & `SSH_MAX_PORT`: Range of ports for SSH tunnels

3. **Start the service using the management script**:
   ```bash
   ./clab-api-manager.sh dind start
   ```

4. **Verify operation**:
   ```bash
   ./clab-api-manager.sh dind status
   curl http://localhost:8080/health
   ```

#### DinD Architecture Details

The Docker-in-Docker deployment uses:

- **Privileged container**: Required for nested Docker functionality
- **Multiple Docker volumes**:
  - `clab-api-dind-data`: For the inner Docker daemon's data
  - `clab-api-home-data`: For user home directories
  - `clab-api-config-data`: For persistent user/group configuration

The entrypoint script performs several important functions:
- Starts the inner Docker daemon
- Sets up user persistence mechanisms
- Configures necessary groups
- Exposes required ports for the API and SSH tunnels

### Docker-out-of-Docker (DooD) Deployment

#### Prerequisites
- Linux system with Docker
- Docker Compose (v2.x preferred)

#### Deployment Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/srl-labs/clab-api-server.git
   cd clab-api-server
   ```

2. **Configure environment**:
   ```bash
   cp docker/common/.env.example docker/common/.env
   nano docker/common/.env
   ```

   Critical settings (same as DinD, but runtime implications differ):
   - `JWT_SECRET`: Set to a strong random string
   - `API_SERVER_HOST`: Set to the server's IP address or hostname
   - `API_PORT`: Server listening port (default: 8080)
   - `SSH_BASE_PORT` & `SSH_MAX_PORT`: Range of ports for SSH tunnels

3. **Start the service using the management script**:
   ```bash
   ./clab-api-manager.sh dood start
   ```

4. **Verify operation**:
   ```bash
   ./clab-api-manager.sh dood status
   curl http://localhost:8080/health
   ```

#### DooD Architecture Details

The Docker-out-of-Docker deployment uses:

- **Host's Docker socket**: Mounted into the container as `/var/run/docker.sock`
- **Network mode: host**: Uses the host's networking stack directly
- **PID namespace: host**: Shares the host's process namespace
- **Privileged mode**: Required for full containerlab functionality
- **Docker volumes**:
  - `clab-api-home-data`: For user home directories
  - `clab-api-config-data`: For persistent user/group configuration
- **Host mounts**:
  - `/var/run/docker.sock`: Docker socket for container control
  - `/var/run/netns`: Network namespaces for containerlab
  - `/var/lib/docker/containers`: Container data visibility

The entrypoint script:
- Sets up user persistence mechanisms
- Configures necessary groups
- Creates symbolic links for shared labs directories
- Verifies Docker socket access

## Detailed Configuration Reference

### Environment Variables

#### Core Server Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `8080` | Server listening port |
| `API_SERVER_HOST` | `localhost` | Hostname/IP used in SSH access URLs |
| `LOG_LEVEL` | `info` | Log verbosity (`debug`, `info`, `warn`, `error`) |
| `GIN_MODE` | `release` | Web framework mode (`debug` or `release`) |

#### Authentication & Security
| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | `please_change_me` | **CRITICAL**: Secret key for JWT token generation |
| `JWT_EXPIRATION` | `60m` | JWT token lifetime (e.g., "60m", "24h") |
| `API_USER_GROUP` | `clab_api` | Linux group for API access |
| `SUPERUSER_GROUP` | `clab_admins` | Linux group for elevated privileges |

#### Containerlab Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `CLAB_RUNTIME` | `docker` | Container runtime used by Containerlab |
| `CLAB_SHARED_LABS_DIR` | `/opt/containerlab/labs` | Shared labs directory on host (DooD only) |

#### SSH Proxy Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_BASE_PORT` | `2223` | Starting port for SSH proxy allocation |
| `SSH_MAX_PORT` | `2322` | Maximum port for SSH proxy allocation |

#### TLS Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `TLS_ENABLE` | `false` | Enable TLS for HTTPS |
| `TLS_CERT_FILE` | | Path to TLS certificate when enabled |
| `TLS_KEY_FILE` | | Path to TLS private key when enabled |
| `TRUSTED_PROXIES` | | Comma-separated list of trusted proxy IPs |

## Data Persistence & Backup

### Understanding Persistence in DinD/DooD

Both containerized deployments use Docker volumes for persistence:

1. **Configuration Volume** (`clab-api-config-data`)
   - Contains Linux user/group information
   - Includes `/etc/passwd`, `/etc/shadow`, `/etc/group`, etc.
   - Critical for user authentication and permissions

2. **Home Volume** (`clab-api-home-data`)
   - Contains all user home directories
   - Stores lab topologies and configurations
   - Contains user-specific settings and SSH keys

3. **Docker Data Volume** (`clab-api-dind-data`, DinD only)
   - Contains the inner Docker daemon's data
   - Stores container images, volumes, networks
   - Not present in DooD mode (uses host Docker)

### Backup and Restore

The `clab-api-manager.sh` script provides backup and restore functionality:

#### Creating a Backup
```bash
./clab-api-manager.sh dind backup
# or
./clab-api-manager.sh dood backup
```

This creates a timestamped backup file in the current directory:
```
clab-api-volumes-backup-dind-20250424-123456.tar.gz
```

The backup includes all persistent volumes in a single compressed tarball.

#### Restoring from Backup
```bash
# First stop the service
./clab-api-manager.sh dind stop

# Then restore
./clab-api-manager.sh dind restore clab-api-volumes-backup-dind-20250424-123456.tar.gz

# Restart the service
./clab-api-manager.sh dind start
```

**Important**: The restore operation erases all existing data in the volumes. You will be prompted for confirmation before proceeding.

### Binary Installation Backups

For binary installations, use standard Linux backup procedures:

1. Back up the configuration file:
   ```bash
   sudo cp /etc/clab-api-server.env /etc/clab-api-server.env.bak
   ```

2. Back up user home directories:
   ```bash
   # For all users with ~/.clab directories
   for user in $(ls /home); do
     if [ -d "/home/$user/.clab" ]; then
       sudo tar -czf "/backup/clab-$user-$(date +%Y%m%d).tar.gz" -C "/home/$user" .clab
     fi
   done
   ```

## User Management & Security

### User Authentication Flow

1. Client sends credentials to `/login` endpoint
2. Server validates credentials against Linux PAM
3. If valid and in required groups, server issues a JWT token
4. Client uses JWT token in Authorization header for subsequent requests
5. Server validates token and extracts username for each request
6. Server performs operations in the context of the authenticated user

### Creating API Users

#### For Binary Installation

```bash
# Create a regular API user
sudo useradd -m -s /bin/bash example-user
sudo passwd example-user
sudo usermod -aG clab_api example-user

# Create a superuser with admin privileges
sudo useradd -m -s /bin/bash admin-user
sudo passwd admin-user
sudo usermod -aG clab_admins admin-user
```

#### For Docker Installation

You can either use the API itself (via a superuser account) or CLI commands:

```bash
# Access the container
docker exec -it clab-api-dind bash

# Create a regular API user
useradd -m -s /bin/bash example-user
echo "example-user:password" | chpasswd
usermod -aG clab_api example-user

# Create a superuser
useradd -m -s /bin/bash admin-user
echo "admin-user:password" | chpasswd
usermod -aG clab_admins admin-user
```

### Lab Ownership & Access Control

Labs are tagged with the username of the creator:

- Each lab is associated with the user who deployed it via Docker labels
- Regular users can only see and manage their own labs
- Superusers (members of `SUPERUSER_GROUP`) can access all labs
- The API enforces these restrictions at the request level

## API Usage Examples

### Authentication

```bash
# Authenticate and get token
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}' \
  | jq -r '.token')

# Use the token in subsequent requests
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/labs
```

### Lab Management

#### Deploying a Lab

```bash
curl -X POST http://localhost:8080/api/v1/labs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "topologyContent": "name: simple-lab\ntopology:\n  nodes:\n    router1:\n      kind: linux\n    router2:\n      kind: linux\n  links:\n    - endpoints: [\"router1:eth1\", \"router2:eth1\"]"
  }'
```

#### Listing Labs

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/labs
```

#### Executing Commands on Nodes

```bash
curl -X POST http://localhost:8080/api/v1/labs/simple-lab/nodes/clab-simple-lab-router1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "ip a"
  }'
```

#### SSH Access to Nodes

```bash
curl -X POST http://localhost:8080/api/v1/labs/simple-lab/nodes/clab-simple-lab-router1/ssh \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sshUsername": "root",
    "duration": "1h"
  }'
```

This returns SSH connection details:

```json
{
  "port": 2223,
  "host": "server-hostname",
  "username": "root",
  "expiration": "2025-04-24T12:34:56Z",
  "command": "ssh -p 2223 root@server-hostname"
}
```

### User Management API (Superusers Only)

#### Creating a New User

```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "password": "securepassword",
    "groups": ["clab_api"]
  }'
```

#### Listing Users

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/users
```

## Performance Considerations

### Deployment Mode Comparison

| Aspect | Binary | DinD | DooD |
|--------|--------|------|------|
| **Performance** | Best | Moderate | Good |
| **Isolation** | Minimal | Highest | Medium |
| **Resource Usage** | Low | High | Medium |
| **Setup Complexity** | Medium | Low | Low |
| **Security Model** | Complex | Simple | Medium |
| **Scalability** | High | Limited | Medium |

### Optimizing for Performance

1. **Binary Installation**
   - Most direct and highest performance
   - Recommended for production environments with high load
   - Consider using a dedicated user rather than root

2. **DooD Deployment**
   - Good compromise between isolation and performance
   - Use for multi-tenant environments where resource efficiency matters
   - Consider using a dedicated Docker daemon if security is a concern

3. **DinD Deployment**
   - Highest isolation but with performance overhead
   - Good for development, testing, or demo environments
   - Consider increasing container resources for better performance

## Troubleshooting

### Binary Installation

Check the service status and logs:

```bash
sudo systemctl status clab-api-server
sudo journalctl -u clab-api-server -f
```

Common issues:
- JWT_SECRET not set properly (authentication failures)
- Required Linux groups don't exist (user creation/login issues)
- Server user doesn't have Docker permissions (lab deployment failures)
- Network port conflicts (server start failures)

### Docker Installation

Check container status and logs:

```bash
./clab-api-manager.sh dind status
./clab-api-manager.sh dind logs
```

Or directly with Docker:

```bash
docker ps | grep clab-api
docker logs clab-api-dind
```

Common issues:
- Configuration errors in `.env` file
- Port conflicts with host services
- Docker socket permission issues (DooD)
- Inner Docker daemon startup failures (DinD)
- Volume permission issues

### Specific Error Scenarios

#### Authentication Failures

```
{"error":"invalid credentials"}
```

Troubleshooting steps:
1. Verify the user exists in the system
2. Confirm the user is in the required group (`API_USER_GROUP` or `SUPERUSER_GROUP`)
3. Try to authenticate with the credentials directly on the system
4. Check PAM configuration if using custom authentication

#### Lab Deployment Failures

```
{"error":"failed to deploy lab: command execution failed: exit status 1"}
```

Troubleshooting steps:
1. Check server logs for detailed error messages
2. Verify Docker daemon is running and accessible
3. Check if the topology is valid (try running it directly with containerlab)
4. Confirm access to required images and resources

#### SSH Tunnel Issues

```
{"error":"failed to create SSH tunnel: no available ports"}
```

Troubleshooting steps:
1. Check if all ports in the SSH port range are in use
2. Verify the port range configuration (`SSH_BASE_PORT` and `SSH_MAX_PORT`)
3. Try terminating expired SSH sessions via the API
4. Restart the service to release all SSH tunnels

## Integration With Other Systems

### Automation Platforms

The API server can be integrated with automation platforms like:

- **Ansible**: Create playbooks that interact with the API
- **GitLab CI/CD**: Automate lab deployment for testing pipelines
- **Jenkins**: Integrate network lab testing into CI/CD workflows

Example Ansible task:

```yaml
- name: Deploy Containerlab topology
  uri:
    url: "http://{{ clab_api_host }}/api/v1/labs"
    method: POST
    body_format: json
    headers:
      Authorization: "Bearer {{ clab_api_token }}"
    body:
      topologyContent: "{{ lookup('file', 'topology.yml') }}"
    status_code: 200
  register: lab_result
```

### Frontend Integration

The API can be used with custom web interfaces or dashboards:

1. **Authentication Flow**:
   - Frontend collects credentials
   - Calls `/login` endpoint to get JWT token
   - Stores token in local storage or session
   - Includes token in all subsequent API calls

2. **Lab Management**:
   - Provide UI for creating, listing, and managing labs
   - Display lab status and details
   - Offer SSH access via web-based terminals

3. **User Management**:
   - Admin interface for creating and managing users
   - Role-based access control using the superuser concept

## Upgrade Procedures

### Binary Installation

Use the install script with the `upgrade` action:

```bash
curl -sL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo -E bash -s -- upgrade
```

Or specify a version:

```bash
curl -sL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo -E bash -s -- --version v0.1.1 upgrade
```

### Docker Installation

Pull the latest images and restart:

```bash
cd clab-api-server
git pull

# For DinD
./clab-api-manager.sh dind restart

# For DooD
./clab-api-manager.sh dood restart
```

Alternatively, for specific versions:

```bash
cd clab-api-server
git checkout v0.1.1

# For DinD
./clab-api-manager.sh dind restart

# For DooD
./clab-api-manager.sh dood restart
```

## Conclusion

The Containerlab API Server provides a powerful, flexible interface for managing network labs programmatically. By understanding its architecture, deployment options, and configuration details, you can successfully integrate it into your environment and leverage its capabilities for network automation, testing, and education.

The choice between binary installation, Docker-in-Docker, and Docker-out-of-Docker depends on your specific requirements for performance, isolation, and security. Each approach has its strengths and considerations, making the API server adaptable to various use cases.

For the latest information and updates, refer to the project repository and the embedded API documentation available via the Swagger UI or ReDoc interfaces.