---
description: Run clab-api-server as a container, with containerlab tools or docker run.
---

# Container

The server image is `ghcr.io/srl-labs/clab-api-server/clab-api-server`. Containerlab can start it for you, or you run it yourself.
{ .lead }

## containerlab tools

The quickest way to try the server. Containerlab pulls the image, creates the container, and configures it:

```bash
sudo containerlab tools api-server start
sudo containerlab tools api-server status
sudo containerlab tools api-server stop
```

Common flags of `start`:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--port`, `-p` | `8090` | Port the API is exposed on. |
| `--host` | `localhost` | Host address of the API server. |
| `--labs-dir`, `-l` | | Directory mounted as the labs root. |
| `--jwt-secret` | random | Secret that signs session tokens. |
| `--tls-enable` | `true` | Serve HTTPS. |

## docker run

For hosts where you manage containers yourself. The server needs the host's container runtime, network namespaces, Linux accounts, and home directories:

```bash
docker run -d \
  --name clab-api-server \
  --privileged \
  --network host \
  --pid host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /var/run/netns:/var/run/netns \
  -v /var/lib/docker/containers:/var/lib/docker/containers \
  -v /etc/passwd:/etc/passwd:ro \
  -v /etc/shadow:/etc/shadow:ro \
  -v /etc/group:/etc/group:ro \
  -v /etc/gshadow:/etc/gshadow:ro \
  -v /home:/home \
  -v /var/lib/clab-api-server:/var/lib/clab-api-server \
  ghcr.io/srl-labs/clab-api-server/clab-api-server:latest
```

| Mount or flag | Why |
| --- | --- |
| Docker socket, `/var/lib/docker/containers` | Manage lab containers and read their logs. |
| `/var/run/netns`, `--network host`, `--privileged` | Wire links and run network tools. |
| `/etc/passwd`, `shadow`, `group`, `gshadow` | Sign users in with PAM and check their groups. |
| `/home` | Users' workspaces (`~/.clab/`). |
| `--pid host` | Keep the host's `/etc/hosts` entries for lab nodes up to date. |

Pass settings with `-e`, for example `-e LOG_LEVEL=debug`. See the [configuration reference](../reference/configuration.md).

### Paths that must match

Paths the server hands to containerlab must be the same inside and outside the container. To use another labs root, set the variable and mount it at the same path:

```bash
  -e CLAB_LABS_ROOT=/var/lib/containerlab/labs \
  -v /var/lib/containerlab/labs:/var/lib/containerlab/labs \
```

The same applies to `CLAB_SHARED_LABS_ROOT` and `CLAB_RESTORE_STAGING_DIR`.
