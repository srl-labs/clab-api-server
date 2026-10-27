# Running on Kubernetes (clabernetes)

With `CLAB_RUNTIME=c9s` the API server runs labs on a Kubernetes cluster through
[clabernetes](https://containerlab.dev/manual/clabernetes/) (c9s) instead of Docker or Podman
on its own host. It uses the c9s lab runtime of the containerlab library it links, so labs
behave as `containerlab deploy -r c9s` labs do.

## Requirements

- Kubernetes 1.31 or later.
- clabernetes with node run state (`Node.spec.runState`, clabernetes 0.11 or later). The
  server refuses to start against an older clabernetes.
- Lab namespaces run with the Pod Security level `privileged`: device containers and the
  clabwire sidecar are privileged.
- A default StorageClass that provisions volumes dynamically, unless
  `CLAB_C9S_PERSISTENCE=false`.
- For node stats: the resource metrics API (`metrics.k8s.io`, e.g. metrics-server).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CLAB_RUNTIME` | `docker` | `c9s` runs labs on Kubernetes. |
| `CLAB_KUBECONFIG` | (empty) | Kubeconfig file. Empty uses `KUBECONFIG`, `~/.kube/config`, or in a Pod the ServiceAccount. |
| `CLAB_KUBE_CONTEXT` | (empty) | Kubeconfig context; empty uses the current context. |
| `CLAB_KUBE_NAMESPACE` | (empty) | One namespace for every lab (`namespaceMode` `fixed`). Empty gives every lab its own namespace `c9s-<lab>` (`per-lab`). |
| `CLAB_C9S_EXPOSE_TYPE` | `None` | Service type of lab nodes: `None`, `ClusterIP`, `Headless` or `LoadBalancer`. With `None`, clients reach nodes through the server. |
| `CLAB_C9S_PERSISTENCE` | `true` | Keep node storage (saved configuration) across Pod replacement and a plain destroy. |
| `CLAB_C9S_IMAGE_PULL_SECRET` | (empty) | Docker-config Secret the device Pods pull images with. |

## Startup checks

Before it serves requests the server:

1. runs a `SelfSubjectAccessReview` for every permission it needs and lists every one that
   is denied, and
2. reads the `nodes.c9s.run` CRD and requires `spec.runState`.

If either fails, it exits with a message that names what is missing.

## What clients see

`GET /health` reports the runtime:

```json
{
  "status": "healthy",
  "runtime": "c9s",
  "namespaceMode": "per-lab",
  "features": ["validate", "graph-mermaid", "graph-dot", "exec-filters", "lab-lifecycle-node-filter",
               "save-copy", "inspect-details", "node-stats", "log-stream", "terminal-resume",
               "node-logs-runtime", "interface-state", "c9s-runtime"]
}
```

| Feature | Meaning |
|---|---|
| `c9s-runtime` | Labs run on Kubernetes through clabernetes. Only with `CLAB_RUNTIME=c9s`. |
| `node-logs-runtime` | Node logs come from the configured runtime (on c9s: the device container log). |
| `interface-state` | The events stream reports interface `up`/`down` events. |
| `node-stats` | Left out on c9s while `metrics.k8s.io` is not served. |

Features that need Docker or Podman on the server host are left out on c9s:
`snapshot-save`, `deploy-restore`, `sshx-readers`, `gotty-options`.

Inspect records of c9s nodes carry `namespace`, `pod`, `container`, `node_uid`,
`exposed_ports` and `load_balancer_address`; `container_id` is `<namespace>/<lab>/<node>` and
the node name is `<lab>-<node>`.

## How the server reaches nodes

| Path | On c9s |
|---|---|
| Deploy, apply, destroy, inspect, start/stop/restart, exec, save, validate, events | containerlab's c9s runtime. Apply is a deploy; `dryRun=true` returns the plan as `runtimePlan`. |
| Node logs | The device container log (`tail`, `follow`, timestamps). |
| Terminals | `shell` and `telnet` exec in the device container; `ssh` logs in with the server's SSH client over a port-forward to port 22, or to the LoadBalancer address when the node exposes port 22. |
| SSH access (`/nodes/{node}/ssh`) | The server's port range as before; every connection is a port-forward to the node's port 22. |
| Browser ports | The node's exposed ports, each with a `proxyPath`: `ANY /api/v1/labs/{lab}/nodes/{node}/ports/{port}/proxy/*` proxies HTTP and WebSockets through a port-forward. The `Authorization` header is not forwarded. |
| Stats | `metrics.k8s.io` (CPU over the metrics window, memory working set of the device containers). Without the API the stats stream answers 501. |
| Graphs | Rendered from the topology file, without the cluster. |

Lab names must be lowercase DNS labels (letters, digits and dashes, starting with a letter).
Other names are refused with the name to use instead.

## Not supported on c9s

These answer `501` with `<operation> is not supported by lab runtime c9s`:

- image management (`/images`)
- Edgeshark, Packetflix capture and Wireshark VNC sessions
- netem, veth, VxLAN and TX offload tools
- VM snapshots (`/snapshots`) and deploys that restore them
- SSHX and GoTTY sharing, fcli, Tailscale status
- pause and unpause
- interface and link inspection (`/interfaces`, `/links`)
- host metrics (`/health/metrics`)

Deploy options that only local runtimes have (node filter, management network overrides,
export templates, graceful destroy) also answer 501.
