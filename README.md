# Containerlab API Server

This project provides a standalone RESTful API server written in Go to interact with the [Containerlab](https://containerlab.dev/) command-line tool.


## Features

*   **Deploy Labs:** Start labs from `.clab.yml` files located in user home directories.
*   **Destroy Labs:** Stop and clean up running labs.
*   **Inspect Labs:** Get details about running labs and nodes.
*   **List Labs:** View all running labs associated with the user.
*   **Authentication:** JWT-based (login required).
*   **Authorization:** API endpoints require a valid JWT.
*   **User Context:** Executes `clab` commands as the authenticated Linux.
*   **Swagger/OpenAPI:** Auto-generated API documentation.

## Prerequisites

1.  **Go:** Version 1.20 or higher.
2.  **Containerlab:** The `clab` executable must be installed and available in the system's `PATH`.


## Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/flosch62/clab-api
    cd clab-api
    ```

2.  **Install Task (Taskfile runner):**
    You can install [Task](https://taskfile.dev) via the official script:
    
    ```bash
    sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b ~/.local/bin
    ```
    Then add this to your shell config if it's not already in your PATH:

    ```bash
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
    source ~/.zshrc
    ```
    Verify with:
    ```bash
    task --version
    ```

3.  **Configure Environment:**

    Create a `.env` file in the project root (copy from `.env.example`) and **change `JWT_SECRET`** to a strong, random value.
    ```bash
    cp .env.example .env
    ```
    
    Edit .env and set a strong JWT_SECRET

4.  **Install System Dependencies:**

    ```bash
    task deps
    ```

5.  **Build the Server:**
    ```bash
    task         # runs tidy, swag, and build
    ```

## Running the Server

```bash
    sudo ./clab-api-server # sudo only needed in case of multiuser server
```

> [!NOTE]
> The server will start, typically on port **8080** (or as configured in `.env`).

---

## API Usage

### Authentication

**POST** `/login`  
JSON Body:
```json
{
  "username": "your_linux_user",
  "password": "your_linux_password"
}
```
- Returns a **JWT token**.  


### Authenticated Requests

Include the token in the `Authorization` header for all `/api/v1/*` requests:
Authorization: Bearer <your_jwt_token>

---

## Endpoints

- **Swagger UI:** http://localhost:8080/swagger/index.html

### Labs
- **POST** `/api/v1/labs`  
  Deploy a lab (requires `topologyFile` relative to user home).

- **GET** `/api/v1/labs`  
  List running labs for the user.

- **GET** `/api/v1/labs/{labName}`  
  Inspect a specific lab.

- **DELETE** `/api/v1/labs/{labName}`  
  Destroy a specific lab.


---

## Taskfile Commands

- `task tidy` – Run `go mod tidy`
- `task swag` – Generate Swagger docs
- `task build` – Compile the server
- `task deps` – Install system dependencies to build (`build-essential`, `libpam-dev`)
- `task` – Run the default task: tidy → swag → build

---

## Build and Run Summary

1. Generate Swagger Docs: `task swag`
2. Build the server: `task build`
3. Run: `./clab-api-server`
4. Open Swagger: http://localhost:8080/swagger/index.html
5. Use Postman, curl, or similar to log in and interact with endpoints


# Privilege Model and Security Considerations

## API Server Execution Model

- Runs as the user who starts the server (not as authenticated users)
- This user needs:
  - Container runtime access (e.g., docker group membership)
  - Execute permission for the `clab` binary
  - Read/write access to authenticated users' home directories

## Command Execution

- All commands run directly as the API server user (no sudo)
- Lab ownership tracked via container labels, not actual file ownership
- Lab ownernship needs to bet set for the authenticated users (not done yet)

## Authentication & Authorization

- PAM-based authentication against Linux user accounts
- JWT tokens with configurable expiration (default 60 minutes)
- User context tracked for authorization but not for execution
- Optional superuser group can view/manage all labs

## File Operations

- Creates and manages files in `~/.clab/<labname>/` directories
- Directory permissions: 0750 (rwxr-x---)
- File permissions: 0640 (rw-r-----)
- All files owned by by the authenticated users 

## Security Considerations

- Path sanitization prevents directory traversal attacks
- Input validation prevents command injection (lab name regex: `^[a-zA-Z0-9_-]+$`)
- Command execution has timeout protection (default 5 minutes)
- No privilege separation/dropping occurs during execution