---
description: Every setting of clab-api-server, with defaults.
---

# Configuration

The server reads settings from environment variables, or from an env file passed with `-env-file`. The systemd install uses `/etc/clab-api-server/clab-api-server.env`; restart the service after a change.
{ .lead }

Start from [`.env.example`](https://github.com/srl-labs/clab-api-server/blob/main/.env.example).

## Server

| Variable | Default | What it does |
| --- | --- | --- |
| `API_PORT` | `8090` | Listen port. |
| `API_SERVER_HOST` | `localhost` (installer) | Host name or IP clients use to reach this host, for example in SSH access details. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `GIN_MODE` | `release` (installer) | Web framework mode: `debug` or `release`. |
| `TRUSTED_PROXIES` | empty | Reverse proxies whose forwarded headers are trusted: comma-separated IPs, `nil` for none, empty for all. |
| `CORS_ALLOWED_ORIGINS` | empty | Comma-separated browser origins allowed to call the API directly. |

## TLS

| Variable | Default | What it does |
| --- | --- | --- |
| `TLS_ENABLE` | `true` | Serve HTTPS. |
| `TLS_AUTO_CERT` | `true` | Create and reuse a self-signed certificate when no certificate files are set. |
| `TLS_CERT_FILE` | empty | Your certificate. |
| `TLS_KEY_FILE` | empty | Its private key. |

## Sign-in

| Variable | Default | What it does |
| --- | --- | --- |
| `JWT_SECRET` | random (installer) | Signs session tokens. Keep it secret; changing it signs everyone out. |
| `JWT_EXPIRATION` | `24h` | Token lifetime, for example `24h` or `7d`. |
| `API_USER_GROUP` | `clab_api` | Linux group that may sign in. |
| `SUPERUSER_GROUP` | `clab_admins` | Linux group that sees and manages every lab and user. |

## Labs and files

| Variable | Default | What it does |
| --- | --- | --- |
| `CLAB_RUNTIME` | `docker` | `docker`, `podman`, or `c9s` for [Kubernetes](../guides/kubernetes.md). |
| `CLAB_LABS_ROOT` | empty | Absolute root for workspaces: `$CLAB_LABS_ROOT/<user>/`. Empty uses `~/.clab/`. |
| `CLAB_SHARED_LABS_ROOT` | empty | Absolute folder for [shared labs](../guides/shared-labs.md). Empty turns them off. |
| `CLAB_HOSTS_FILE` | empty | Host-visible hosts file to keep lab entries in. In a container with `--pid host`, `/proc/1/root/etc/hosts` is found automatically. |
| `CLAB_RESTORE_STAGING_DIR` | `/var/lib/clab-api-server/restore` | Where [snapshot restores](../guides/deploy-options.md#snapshot-restore) are staged. |

## Terminals, SSH, and scripts

| Variable | Default | What it does |
| --- | --- | --- |
| `SSH_BASE_PORT` | `2223` | First port for SSH access through the server. |
| `SSH_MAX_PORT` | `2322` | Last port for SSH access. |
| `TERMINAL_MAX_SESSIONS_PER_USER` | `128` | Open browser terminals per user. |
| `TERMINAL_IDLE_TIMEOUT` | `30m` | How long a resumable terminal keeps running after its last client left. Other terminals end with their client. |
| `API_HOST_SCRIPTS` | `false` | Let script buttons run shell scripts on this host, each as the signed-in Linux user. Accounts with a `nologin` or `false` shell are refused. No effect on c9s. |

## Packet capture

| Variable | Default | What it does |
| --- | --- | --- |
| `CAPTURE_WIRESHARK_DOCKER_IMAGE` | `ghcr.io/srl-labs/wireshark-vnc-docker:latest` | Image of Wireshark-in-the-browser sessions. |
| `CAPTURE_WIRESHARK_PULL_POLICY` | `always` | `always`, `missing`, or `never`. |
| `CAPTURE_WIRESHARK_SESSION_TTL` | `2h` | Lifetime of a Wireshark session. |
| `CAPTURE_PACKETFLIX_PORT` | `5001` | Edgeshark packetflix port (Docker and Podman). |
| `CAPTURE_REMOTE_HOSTNAME` | empty | Host name put into Edgeshark capture links. |
| `CAPTURE_EDGESHARK_EXTRA_ENV_VARS` | empty | Extra environment variables for Edgeshark, for example proxy settings. |

## Fabric checks (fcling)

Docker and Podman only.

| Variable | Default | What it does |
| --- | --- | --- |
| `FCLING_DOCKER_IMAGE` | `ghcr.io/srl-labs/fcling:0.9.0` | Image of fcling reports and each lab's fabric engine. |
| `FCLING_PULL_POLICY` | `missing` | `always`, `missing`, or `never`. |
| `FCLING_GNMI_PORT` | `57400` | gNMI port for nodes of labs without their own. Set one per lab with `gnmiPort` on `POST /api/v1/labs/{lab}/fcling/engine`. |
| `FCLING_STATE_DIR` | `/var/lib/clab-api-server/fcling` | Where each lab's chosen gNMI port is kept. |

## Kubernetes (c9s)

Only with `CLAB_RUNTIME=c9s`. See [Labs on Kubernetes](../guides/kubernetes.md#configuration) for details.

| Variable | Default | What it does |
| --- | --- | --- |
| `CLAB_KUBECONFIG` | empty | Kubeconfig file. Empty uses `KUBECONFIG`, `~/.kube/config`, or the Pod's ServiceAccount. |
| `CLAB_KUBE_CONTEXT` | empty | Kubeconfig context. |
| `CLAB_KUBE_USER_PREFIX` | `clab:` | Prefix of the Kubernetes users and groups the server acts as. |
| `CLAB_KUBE_NAMESPACE_TEMPLATE` | `c9s-{user}-{lab}` | Namespace of a user's lab. |
| `CLAB_KUBE_LAB_QUOTA` | empty | ResourceQuota manifest created in every lab namespace. |
| `CLAB_C9S_EXPOSE_TYPE` | `None` | Service type of lab nodes: `None`, `ClusterIP`, `Headless`, or `LoadBalancer`. |
| `CLAB_C9S_PERSISTENCE` | `true` | Keep node storage across Pod replacement and a plain destroy. |
| `CLAB_C9S_IMAGE_PULL_SECRET` | empty | Image pull secret copied into every lab namespace. |

## What topologies can read

After loading its settings, the server removes them (every variable on this page except `CLAB_RUNTIME`) from its own environment, so `${VAR}` in a topology cannot read them. Other variables, such as proxy settings, `DOCKER_*`, and containerlab's own `CLAB_*` options, stay visible to containerlab and to topologies. Do not keep secrets in them.
