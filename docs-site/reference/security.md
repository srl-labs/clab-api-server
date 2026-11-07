---
description: Who the server runs as, how users are checked, and what keeps them apart.
---

# Security model

The server runs as `root` and acts on behalf of Linux users. These are the rules that keep users apart.
{ .lead }

| Topic | How it works |
| --- | --- |
| **Server process** | Runs as `root`, since it controls the container runtime, network namespaces, Linux users, and lab files. Containerlab runs inside it as a library, not as a separate command. |
| **Sign-in** | Linux credentials checked by PAM. Only members of `API_USER_GROUP` or `SUPERUSER_GROUP` get a token. |
| **Sessions** | JWTs signed with `JWT_SECRET`, valid for `JWT_EXPIRATION`. |
| **Ownership** | Containers carry their owner as a label. Users reach their own labs and shared labs; superusers reach all. |
| **Files** | Each user's workspace belongs to that user. Paths are checked to stay inside the workspace or the shared folder. |
| **SSH access** | A port from `SSH_BASE_PORT`–`SSH_MAX_PORT` forwards to the node's port 22 and expires automatically. |
| **Transport** | HTTPS by default, with a self-signed certificate until you provide one. |
| **Topology variables** | The server's own settings are removed from its environment, so topologies cannot read `JWT_SECRET` and friends. See [configuration](configuration.md#what-topologies-can-read). |
| **Kubernetes** | With c9s, the server acts as the user towards the cluster, and Kubernetes RBAC decides. See [trust model](../guides/kubernetes.md#trust-model). |

## Recommendations

- Keep `JWT_SECRET` long and random. The installer generates one.
- Use your own certificate with `TLS_CERT_FILE` and `TLS_KEY_FILE` for hosts others reach.
- Put only trusted people in `clab_admins`: they see and operate every lab and manage Linux users.
- Leave `API_HOST_SCRIPTS` off unless users should run scripts on the host as themselves.
- Treat a lab host as shared infrastructure: anyone who can deploy a privileged lab node can reach the host through it.
