# Containerlab API Server

This project provides a standalone RESTful API server written in Go to interact with the [Containerlab](https://containerlab.dev/) command‑line tool (clab). It allows you to manage Containerlab deployments programmatically or remotely.

---

## ✨ Features

* **Lab Management:** Deploy, destroy, redeploy, inspect, and list labs
* **Node Operations:** Execute commands and save configurations
* **SSH Access:** Connect to lab nodes via SSH through the API server
* **Topology Tools:** Generate and deploy CLOS topologies
* **Network Tools:** Manage network emulation, virtual Ethernet pairs, VxLAN tunnels
* **Certification Tools:** Certificate management
* **User Management:** Create, update, delete users and manage their permissions
* **Health Monitoring:** Check server health status and system metrics
* **User Context:** Track ownership and manage files within user home directories
* **Configuration:** Configurable via environment variables and `.env` files
* **Documentation:** Embedded Swagger UI for API exploration

---

## ⚙️  Prerequisites

| Requirement | Version / Notes |
|-------------|-----------------|
| **Containerlab** | **v0.68.0+**<br/>`clab` must be on the `PATH` of the user that runs the API server. |
| **Linux** | Any modern distribution. The binaries we publish target **amd64** and **arm64**. |
| **PAM** | Uses the default `login` PAM service. No extra configuration needed on most distros. |
| **User / Group** | Linux groups must exist as defined in your `.env` (`API_USER_GROUP`, `SUPERUSER_GROUP`). |

---

> [!NOTE]
> Containerlab 0.68.0+ is not available yet, but the 0.1.0 release of the clab‑api‑server is compatible with Containerlab 0.67.0.

## 🚀 Quick install / upgrade

A single script handles **install**, **upgrade**, **pull‑only**, and **uninstall** workflows. It automatically

* downloads the correct binary for **amd64**/**arm64**,
* installs it to **`/usr/local/bin/clab-api-server`**,
* writes a default **`/etc/clab-api-server.env`** configuration file, and
* creates a **systemd unit** at **`/etc/systemd/system/clab-api-server.service`** (but does **not** enable it).

```bash
curl -sL https://raw.githubusercontent.com/srl-labs/clab-api-server/refs/heads/main/install.sh | sudo -E bash
```

### Common Flags & Actions

| Action / flag | Purpose |
|---------------|---------|
| `install` *(default)* | Fresh install – creates env + service if they don't exist. |
| `upgrade` | Replace an existing binary with the latest (or `--version`). The script stops the service, upgrades the binary, updates the unit/env if needed, and leaves the service **stopped**. |
| `pull-only` | Just download the binary; do **not** write env/service files. |
| `uninstall --yes` | Remove the binary, env file, and systemd unit **non‑interactively**. |
| `--version vX.Y.Z` | Install / upgrade to the specified tag instead of the latest. |

> [!TIP]
> Run the script without arguments to see a short usage summary.

---

## 🔧 Post‑install steps

1. **Edit the configuration** `/etc/clab-api-server.env`

   At a minimum, change `JWT_SECRET` to a strong random string.

   ```bash
   sudo vi /etc/clab-api-server.env   # or your editor of choice
   ```

2. **Enable & start the service** (after you edited the env file):

   ```bash
   sudo systemctl enable --now clab-api-server
   ```

3. **Verify**

   ```bash
   sudo systemctl status clab-api-server
   journalctl -u clab-api-server -f
   ```

### Manual binary install (optional)

If you prefer not to use the script you can still download a release from the [Releases page](https://github.com/srl-labs/clab-api-server/releases) and follow the traditional steps. The rest of this document assumes you used the script – adjust paths accordingly if you go manual.

---

## 🗄️ Configuration reference

All options can be set via **environment variables**, the shipped **`/etc/clab-api-server.env`** file, or the **`.env`** file next to the binary. The script creates the central `/etc/…env` file by default because it plays nicer with systemd.

```dotenv
# Containerlab API Server configuration (excerpt)
API_PORT=8080
API_SERVER_HOST=localhost
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

# --- SSH (otional) ---
#SSH proxy port range (Default: 2222-2322)
#SSH_BASE_PORT=2222
#SSH_MAX_PORT=2322

# --- TLS (optional) ---
#TLS_ENABLE=true
#TLS_CERT_FILE=/etc/clab-api-server/certs/server.pem
#TLS_KEY_FILE=/etc/clab-api-server/certs/server-key.pem
```

> [!NOTE]
> Settings defined as environment variables always take precedence over the file.

---

## 🏃‍♂️ Running without systemd (for development / CI)

```bash
sudo /usr/local/bin/clab-api-server -env-file /etc/clab-api-server.env
```

---

## 🔒 Privilege model & security

* **Server user** – defined in the systemd unit (default: the user that executed the install script). Needs rights to run **clab** and access the container runtime (e.g. be in the `docker` group).
* **Authenticated Linux user** – validated via PAM, must be member of `API_USER_GROUP` (default `clab_api`) or `SUPERUSER_GROUP` (`clab_admins`).
* **Command execution** – all **clab** commands *and* SSH proxies run as the *server* user, *not* the authenticated user.
* **Ownership** – Lab ownership is inferred from clab container labels; file operations attempt to store artifacts under the authenticated user's home.
* **SSH sessions** – The SSH manager allocates local ports (default **2222‑2322**) and forwards traffic to container port 22. Sessions expire automatically (default **1 h**, max **24 h**) and can be listed or terminated via the API.
* **Security controls** – PAM for credential validation, JWT for session management, input validation & path sanitisation, optional TLS with client‑cert auth, execution timeouts.

See the full *Privilege Model and Security* section further below for details.

---

## 📡 API Usage

### 1. Authentication

```http
POST /login
Content‑Type: application/json

{
  "username": "alice",
  "password": "<linux_password>"
}
```

Successful logins return a JWT token:

```json
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…"}
```

### 2. Use the token

```
Authorization: Bearer <token>
```

Example:

```bash
TOKEN="$(… obtain via /login …)"
API_HOST="localhost:8080"

curl -H "Authorization: Bearer $TOKEN" \
     http://${API_HOST}/api/v1/labs
```

### 3. Check server health

Basic health check (no auth required):

```bash
curl http://${API_HOST}/health
```

Detailed system metrics (requires superuser privileges):

```bash
curl -H "Authorization: Bearer $TOKEN" \
     http://${API_HOST}/api/v1/health/metrics
```

---
## 📝 API documentation (Swagger & ReDoc)

Open your browser at one of these URLs:

```
http://<server_ip>:<API_PORT>/swagger/index.html  # Swagger UI
http://<server_ip>:<API_PORT>/redoc               # ReDoc UI (more user-friendly alternative)
```

For Swagger UI, use the **Authorize** button in the top‑right corner to paste your `Bearer <token>` and explore the API interactively.

ReDoc provides a more user-friendly, responsive documentation interface that's easier to navigate for complex APIs.
---

## 🛡️ Privilege model & security (in depth)

<details>
<summary>Click to expand</summary>

### Server user

The API process runs as the user defined in the systemd unit (`User=`). This user requires:

* Permission to execute **clab**
* Membership in the container runtime group (e.g. `docker`)
* If the server is mused with mutliple users, than the server needs sudo privileges or Write access to users' `~/.clab/`

### Authenticated Linux user

A user must either

* belong to **`API_USER_GROUP`** (default `clab_api`) **or**
* belong to **`SUPERUSER_GROUP`** (`clab_admins`).

### Command execution & ownership

* All clab commands are executed as the **server** user.
* The API tracks lab ownership via container labels.
* Generated files are stored in the authenticated user's home whenever possible.

### Security controls

* **PAM** for credential validation
* **JWT** for session management
* **Input validation & path sanitisation** against directory traversal
* **TLS** support with optional client‑cert auth
* **Execution timeouts** for clab commands
* **SSH session limits** and automatic expiration

> [!IMPORTANT]
>  Granting the server user write access to other users' home directories has security implications. Review your threat model carefully before production deployments.

</details>

---

## 👩‍💻 Development

The developer workflow is unchanged – the install script is only for production use.

### Requirements

* **Go ≥ 1.21**
* **Task** – <https://taskfile.dev/installation/>
* System deps: `build-essential`, `libpam-dev` *(Debian/Ubuntu)* or `pam-devel` *(RHEL/Fedora)*

### Quick start

```bash
git clone https://github.com/srl-labs/clab-api-server.git
cd clab-api-server
cp .env.example .env      # edit JWT_SECRET

# build & run
task            # tidy → swag docs → build binary
./clab-api-server
```

Open <http://localhost:8080/swagger/index.html>

### Taskfile targets

| Task | Description |
|------|-------------|
| `task tidy`  | `go mod tidy` |
| `task swag`  | Generate / update Swagger docs |
| `task build` | Compile the binary (`bin/clab-api-server`) |
| `task deps`  | Install build deps (apt) |
| `task` *(default)* | tidy → swag → build |

---

## 📜 License

Distributed under the **Apache 2.0** license. See `LICENSE` for details.