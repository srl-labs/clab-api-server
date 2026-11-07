---
description: Full REST API reference of clab-api-server, generated from the source.
---

# REST API

Every endpoint, parameter, and response, generated from the server's source with each release.
{ .lead }

<div class="hero-actions" markdown>
[Open the API reference :lucide-arrow-up-right:](../api/index.html){ .hero-button .hero-button-primary }
[OpenAPI JSON](../api/swagger.json){ .hero-button .hero-button-secondary }
[OpenAPI YAML](../api/swagger.yaml){ .hero-button .hero-button-secondary }
</div>

## Areas

| Path | What it covers |
| --- | --- |
| `POST /login` | Sign in with a Linux account; returns a JWT. |
| `GET /health` | Status, version, runtime, and `features`. No token needed. |
| `/api/v1/labs` | Deploy, inspect, redeploy, apply, validate, and destroy labs. Exec, save, logs, stats, interfaces, graphs. |
| `/api/v1/labs/{lab}/nodes/{node}` | One node: start, stop, restart, logs, SSH, browser terminals, and proxied web ports. |
| `/api/v1/labs/{lab}/capture` | Packet capture streams and Wireshark sessions. |
| `/api/v1/labs/workspace`, `…/topology` | Files in the user's workspace. See [workspaces](../guides/workspaces.md). |
| `/api/v1/events` | Live container and interface events (NDJSON). |
| `/api/v1/terminal-sessions`, `/api/v1/ssh` | Open terminal and SSH sessions. |
| `/api/v1/tools` | Certificates, netem, veth, VxLAN, Edgeshark. |
| `/api/v1/images` | Container images on the host. |
| `/api/v1/users` | Linux user management. |
| `/api/v1/version` | Server version and update check. |

## On a running server

The same reference, matching that server's version:

```text
https://<host>:8090/swagger/index.html   # Swagger UI, try calls with your token
https://<host>:8090/redoc                # ReDoc
```
