---
description: Lifecycle timeouts and starting vrnetlab nodes from VM snapshots.
---

# Deploy options

## Timeout

Deploy, redeploy, apply, and destroy take an optional `timeout`: containerlab's `--timeout` as a Go duration such as `90s`, `15m`, or `1h`, at most `2h`.

```bash
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/labs/demo/deploy?path=demo.clab.yml&timeout=30m"
```

It applies to `POST /api/v1/labs`, `/api/v1/labs/archive`, `/api/v1/labs/{lab}/deploy`, `/apply`, `PUT /api/v1/labs/{lab}`, and `DELETE /api/v1/labs/{lab}`.

| Runtime | Default |
| --- | --- |
| Docker, Podman | 5 minutes |
| c9s (Kubernetes) | 10 minutes, since clusters pull images and schedule Pods slower |

The request itself runs for the timeout plus 5 minutes (a redeploy for twice the timeout plus 5 minutes), so containerlab's own timeout error reaches the client. Servers that take `timeout` list `lab-lifecycle-timeout` in `/health` features.

## Snapshot restore

Deploy calls accept `restoreAll` and `restore` to start vrnetlab nodes from VM snapshots in the user's workspace.

The server opens each snapshot once, checks it, and places that exact file at `$CLAB_RESTORE_STAGING_DIR/<lab>/<node>.tar`. Only that file is mounted into the node, so changing the workspace afterwards does not change what the node uses.

**Disk space.** The staged file is a hard link when the staging folder is on the same filesystem and mount as the workspace, so it costs nothing extra. Otherwise the snapshot is copied. To avoid copies, put `CLAB_RESTORE_STAGING_DIR` on the same mount as the workspaces, for example `/home/.clab-api-restore` with the [Docker deployment](../install/container.md#docker-run).

**Ownership.** The folder and every parent must be owned by `root` and not writable by other users. The server creates missing folders. In a container, mount it at the same path as on the host.

**Lifetime.** Staged files stay while the lab exists, so node restarts work. The next restore of a node replaces its file. Destroying the lab, or the node with a node filter, through the API removes them.

Snapshots need Docker or Podman; they are not available on c9s.
