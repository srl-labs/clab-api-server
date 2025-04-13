# Containerlab API Server

This project provides a standalone RESTful API server written in Go to interact with the [Containerlab](https://containerlab.dev/) command-line tool (clab). It allows you to manage Containerlab deployments programmatically or remotely.

## Features

* **Lab Management:** Deploy, destroy, redeploy, inspect, and list labs
* **Node Operations:** Execute commands and save configurations
* **Topology Tools:** Generate and deploy CLOS topologies
* **Network Tools:** Manage network emulation, virtual Ethernet pairs, VxLAN tunnels
* **Certification tools:** Certificate management, user authentication via Linux PAM and JWT
* **User Context:** Track ownership and manage files within user home directories
* **Configuration:** Configurable via environment variables and .env files
* **Documentation:** Embedded Swagger UI for API exploration

## Prerequisites

Before running the `clab-api` server, ensure the following are set up on the server machine:

1.  **Containerlab:** The `clab` executable must be installed and available in the system's `PATH` for the user running the API server. See [Containerlab Installation Guide](https://containerlab.dev/install/).
2.  **Linux System:** The API server is designed for Linux environments.
3.  **PAM Configuration:** Pluggable Authentication Modules (PAM) must be configured correctly ( Linux default is good ). The API uses the `login` service by default. PAM is available on most Linux distributions out of the box and doesn't require additional installation for using the pre-built binary.
4.  **User Group:** A Linux group named `clab_admins` must exist. Only users belonging to this group can successfully authenticate via the `/login` endpoint.

## Installation

1.  **Download:** Obtain the latest `clab-api-server` binary for your architecture from the [Releases](https://github.com/srl-labs/clab-api-server/releases) page.
2.  **Place Binary:** Copy the downloaded binary to a suitable location on your server, for example, `/usr/local/bin/`.
    ```bash
    sudo mv ./clab-api-server_linux_amd64 /usr/local/bin/clab-api-server
    sudo chmod +x /usr/local/bin/clab-api-server
    ```
3.  **Create User Group:** Ensure the `clab_admins` group exists.
    ```bash
    sudo groupadd clab_admins
    ```
    
4.  **Add Users:** Add any Linux users who should be allowed to use the API to the `clab_admins` group.
    ```bash
    sudo usermod -aG clab_admins your_linux_username
    ```
    *(Users may need to log out and log back in for group changes to take effect)*

## Configuration

The server is configured via environment variables or a `.env` file located in the same directory as the binary.

1.  **Create `.env` file:**
    ```bash
    cd /path/where/you/placed/the/binary # e.g., /usr/local/bin
    sudo nano .env
    ```
2.  **Populate `.env`:** Copy the following content and **change `JWT_SECRET`** to a strong, random value.

    ```dotenv
    # --- Server Settings ---
    API_PORT=8080

    # --- Security ---
    # IMPORTANT: Change this to a long, random, secret string!
    JWT_SECRET=default_secret_change_me
    JWT_EXPIRATION_MINUTES=60m # Token validity duration

    # Optional: Specify a group whose members bypass ownership checks (e.g., "clab_superusers")
    # Leave empty ("") to disable superuser functionality.
    SUPERUSER_GROUP=""

    # --- Containerlab ---
    # Specify the container runtime clab should use (e.g., docker, podman). Defaults to 'docker'.
    CLAB_RUNTIME=docker

    # --- Logging ---
    # Log level: debug, info, warn, error, fatal. Defaults to 'info'.
    LOG_LEVEL=info

    # --- TLS ---
    # Enable HTTPS (true/false). Defaults to false.
    TLS_ENABLE=false
    # Path to the TLS certificate file (e.g., /etc/clab-api/cert.pem)
    TLS_CERT_FILE=""
    # Path to the TLS key file (e.g., /etc/clab-api/key.pem)
    TLS_KEY_FILE=""

    # --- Gin Web Framework Settings ---
    # Gin mode: debug, release, test. Defaults to 'debug'. Use 'release' for production.
    GIN_MODE=debug
    # Comma-separated list of trusted proxy IPs/CIDRs, or "nil" to disable proxy trust.
    # Empty string (default) trusts all proxies (use with caution).
    # Example: TRUSTED_PROXIES="192.168.1.100,10.0.0.0/16"
    TRUSTED_PROXIES=""
    ```
3.  **Set Permissions:** Ensure the `.env` file is readable by the user running the server.
    ```bash
    # Example if running as root, adjust owner/group if running as a different user
    sudo chown root:root .env
    sudo chmod 600 .env
    ```

**Environment Variables:** Any setting in the `.env` file can be overridden by setting the corresponding environment variable (e.g., `export API_PORT=9090`).

## Running the Server

You can run the server directly or set it up as a systemd service for background operation and management.

### Directly (for testing):

```bash
# Run as a user with clab and container runtime access
# (sudo might be needed if that user is root or requires elevated privileges for runtime access)
sudo /usr/local/bin/clab-api-server
```

### As a systemd Service (Recommended):

1. **Create Service File:** Create a file named `/etc/systemd/system/clab-api.service`:
```bash
sudo nano /etc/systemd/system/clab-api.service
```

2. **Add Service Definition:** Paste the following content. Adjust User, Group, WorkingDirectory, and ExecStart if necessary. Ensure the specified User has clab and container runtime access, and can read the .env file.
```ini
[Unit]
Description=Containerlab API Server
After=network.target docker.service # Add other runtimes if needed (e.g., podman.service)

[Service]
User=root # Or a dedicated user with necessary permissions
Group=root # Or the primary group of the dedicated user
WorkingDirectory=/usr/local/bin # Directory containing the binary and .env file
ExecStart=/usr/local/bin/clab-api-server
Restart=on-failure
RestartSec=5s
# Optional: Load environment variables from a different file if not using .env in WorkingDirectory
# EnvironmentFile=/etc/clab-api/clab-api.conf

[Install]
WantedBy=multi-user.target
```

3. **Enable and Start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable clab-api.service
sudo systemctl start clab-api.service
```

4. **Check Status:**
```bash
sudo systemctl status clab-api.service
journalctl -u clab-api.service -f # View logs
```

## API Usage

### Authentication

- **Endpoint:** `POST /login`
- **Request Body (JSON):**
```json
{
  "username": "your_linux_user",
  "password": "your_linux_password"
}
```
(Note: `your_linux_user` must be a member of the `clab_admins` group)

- **Response (JSON):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```
Copy the received JWT token.

### Authenticated Requests

For all endpoints under `/api/v1/`, include the JWT token in the Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

Example using curl:

```bash
TOKEN="your_jwt_token"
API_HOST="localhost:8080" # Or your server address

# List labs
curl -H "Authorization: Bearer $TOKEN" http://$API_HOST/api/v1/labs
```

## API Documentation (Swagger UI)

Once the server is running, access the interactive API documentation in your browser:

http://<server_ip_or_hostname>:<API_PORT>/swagger/index.html

(e.g., http://localhost:8080/swagger/index.html)

The Swagger UI allows you to:

- Explore all available endpoints.
- View request/response models.
- Try out API calls directly from the browser (use the "Authorize" button to input your `Bearer <token>`).

## Privilege Model and Security

**Server User:** The API server process runs as the user specified in the systemd service file or the user who manually starts it. This user requires:
- Permission to execute `clab`.
- Access to the configured container runtime (e.g., member of `docker` group).
- Read/write access to `~/.clab/` directories for all potential authenticated users if deploying topologies via content/archive or using certificate features. This is a significant permission requirement. Consider security implications carefully.
- Read access to the `.env` configuration file.

**Authenticated User:** The API authenticates Linux users via PAM and checks for `clab_admins` group membership.

**Command Execution:** `clab` commands are executed as the server user, not the authenticated user.

**Ownership:**
- Lab ownership for API operations (inspect, destroy, list, etc.) is determined by the owner label set on containers by clab during deployment.
- File operations (topology saving, certificate generation) attempt to create files/directories within the authenticated user's home directory (`~/.clab/`) and set ownership to that user. This requires the server user to have sufficient permissions (e.g., running as root or having write access to user homes).

**Security Measures:**
- JWT for session management.
- PAM for credential validation.
- Input validation (regex) for names and paths.
- Path sanitization to prevent directory traversal.
- Configurable TLS for encrypted communication.
- Configurable trusted proxies.
- Command execution timeout.

**IMPORTANT:** Granting the server user write access to user home directories has security implications. Ensure you understand and accept the risks.

## Development

These instructions are for developers contributing to the clab-api server. Users should refer to the Installation section above.

### Prerequisites

- **Go:** Version 1.21 or higher.
- **Task:** A task runner. Install via [Task Installation](https://taskfile.dev/installation/).
- **System Dependencies:** `build-essential`, `libpam-dev` (Debian/Ubuntu) or `pam-devel` (CentOS/Fedora).

### Setup

1. **Clone:** `git clone https://github.com/srl-labs/clab-api-server.git && cd clab-api`
2. **Install Dependencies:** `task deps` (Installs system build dependencies)
3. **Configure Environment:** Copy `.env.example` to `.env` and set a strong `JWT_SECRET`.
4. **Build:** `task` (Runs `go mod tidy`, generates Swagger docs, and builds the binary `clab-api-server`)

### Taskfile Commands

- `task tidy`: Run `go mod tidy`.
- `task swag`: Generate/update Swagger documentation (`./docs`). Requires swag CLI (`go install github.com/swaggo/swag/cmd/swag@latest`).
- `task build`: Compile the server binary.
- `task deps`: Install system build dependencies using apt.
- `task`: Default task: runs tidy, swag, then build.

### Running Locally

```bash
# Ensure clab is in PATH and you have runtime access
./clab-api-server
```

Access Swagger UI at http://localhost:8080/swagger/index.html.