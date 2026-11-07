---
description: Requirements and the ways to run clab-api-server.
---

# Install

The server runs on Linux, `amd64` or `arm64`. Containerlab is built in, so there is no separate `containerlab` binary to install.
{ .lead }

## Requirements

| Requirement | Notes |
| --- | --- |
| Linux | Any modern distribution. |
| Container runtime | Docker (default) or Podman on the host, or a Kubernetes cluster with [clabernetes](../guides/kubernetes.md). |
| PAM | The default `login` PAM service. Nothing to configure on most distributions. |
| Groups | Users who sign in must be in `clab_api` or `clab_admins`. The installer creates both. |

## Choose a method

| Method | Best for | You manage |
| --- | --- | --- |
| [Systemd service](service.md) | Lab hosts you keep, backends for the Containerlab Apps | Nothing beyond the config file. **Recommended.** |
| [`containerlab tools api-server`](container.md#containerlab-tools) | Trials, demos, temporary access | Nothing; it pulls and starts a container. |
| [`docker run`](container.md#docker-run) | Hosts where everything runs in containers | Mounts, config, and lifecycle. |
| [Binary](binary.md) | Debugging, custom supervision | Config and process lifetime. |

All methods listen on HTTPS port `8090` by default.

<div class="next" markdown>
[:lucide-arrow-right: Systemd service](service.md)
</div>
