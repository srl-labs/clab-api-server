# Running on Kubernetes (clabernetes)

With `CLAB_RUNTIME=c9s` the API server runs labs on a Kubernetes cluster through
[clabernetes](https://containerlab.dev/manual/clabernetes/) (c9s) instead of Docker or Podman
on its own host. It uses the c9s lab runtime of the containerlab library it links, so labs
behave as `containerlab deploy -r c9s` labs do.

On c9s, **Kubernetes RBAC is the authority over labs.** The server acts as the signed-in user
for every lab call, and uses its own identity only to provision lab namespaces.

## Requirements

- Kubernetes 1.31 or later.
- clabernetes with node run state and the clabwire capture contract (0.11 or later). The
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
| `CLAB_KUBE_USER_PREFIX` | `clab:` | Prefix of the Kubernetes user and group names the server acts as, so they cannot collide with the cluster's own users. |
| `CLAB_KUBE_NAMESPACE_TEMPLATE` | `c9s-{user}-{lab}` | Namespace of a user's lab. Needs `{user}` and `{lab}`. |
| `CLAB_KUBE_LAB_QUOTA` | (empty) | Absolute path of a ResourceQuota manifest (YAML) created in every new lab namespace. |
| `CLAB_C9S_EXPOSE_TYPE` | `None` | Service type of lab nodes: `None`, `ClusterIP`, `Headless` or `LoadBalancer`. With `None`, clients reach nodes through the server. |
| `CLAB_C9S_PERSISTENCE` | `true` | Keep node storage (saved configuration) across Pod replacement and a plain destroy. |
| `CLAB_C9S_IMAGE_PULL_SECRET` | (empty) | Docker-config Secret the device Pods pull images with, as `<namespace>/<name>` or a name in the server's own namespace. The server copies it into every lab namespace. |

`CLAB_KUBE_NAMESPACE` cannot be used with c9s: every lab has its own namespace.

## Users and their rights

| Linux | Kubernetes |
|---|---|
| user `alice` | user `clab:alice`, group `clab:users` |
| member of `SUPERUSER_GROUP` | additionally group `clab:admins` |
| member of the Linux group that owns a shared lab's directory | additionally group `clab:shared-<group>` for that lab |

**Provisioning (the server's identity).** On the first deploy of a lab the server creates its
namespace (`c9s-<user>-<lab>`, or `c9s-shared-<lab>` for a topology under `@shared/`) with
the labels `containerlab.dev/runtime=clabernetes`, `clab-owner=<user>`, `clab-lab=<lab>`,
`app.kubernetes.io/managed-by=clab-api-server` and
`pod-security.kubernetes.io/enforce=privileged`, and in it:

- a RoleBinding of `clabernetes-lab-editor` to `clab:<user>` (or the group
  `clab:shared-<group>`); the role also grants get on the namespace object, which containerlab
  reads before it deploys into it, and bound in the namespace that is the lab's namespace only,
- the ResourceQuota from `CLAB_KUBE_LAB_QUOTA`, and a copy of the image pull secret, if set.

**Lab calls (the user's identity).** Deploy, apply, destroy, inspect, exec, save,
start/stop/restart, events, logs, terminals, port-forwards and stats run through the
containerlab library as the user, with Kubernetes impersonation. The cluster's audit log names
the user, and a user has the same rights through the server as with `kubectl`.

**Listing.** The server lists the namespaces labelled `clab-owner=<user>` (and the shared ones
of the user's groups) with its own identity, then inspects each as the user. Superusers
inspect every namespace as `clab:admins`. The events stream watches each of the user's lab
namespaces as the user.

**Destroy.** A plain destroy keeps the node storage (the saved configuration) and therefore the
namespace; the next deploy reuses both. The server deletes the namespace once containerlab
removed the lab and no claims are left, and always on `cleanup=true`. It only deletes
namespaces it created.

**Names.** Lab names are unique per user, not per server: two users may both have a lab
`demo`. A superuser addressing a lab name that several other users have gets `409`.

The server's own checks (`clab-owner`, superuser, shared workspace) stay in place, so a request
fails closed if either the server or Kubernetes refuses it.

**What users can edit.** The lab editor role lets users update their Topology, which carries
the lab's `clab-owner` label and the topology file containerlab deployed from (annotation
`containerlab.dev/topo-file`). The server reads, applies and purges that file, so it does not
take either from the Topology: a lab's owner is the one of its namespace, and its topology file
(`labPath`/`absLabPath` in inspect) is kept only when it lies in the owner's workspace, or for a
shared lab in the shared workspace under a directory of the lab's group. Otherwise inspect
reports `k8s://<namespace>/topologies/<lab>`, as for a lab without a recorded file, and file
operations that need the topology answer `404`. The events stream corrects the `clab-owner` and
`clab-topo-file` attributes of container events the same way, so they always match inspect; an
event whose records the server cannot check (the cluster does not answer) is left out.

## RBAC

Apply both manifests once (adjust `clab:` if you change `CLAB_KUBE_USER_PREFIX`):

- [`kubernetes/provisioner-rbac.yaml`](kubernetes/provisioner-rbac.yaml): the server's
  ServiceAccount `clab-api-server` and the ClusterRole `clab-api-server-provisioner`.
- [`kubernetes/admins-rbac.yaml`](kubernetes/admins-rbac.yaml): a ClusterRoleBinding of
  `clabernetes-lab-editor` to the group `clab:admins`, so superusers see and manage every lab.
  The server never creates cluster-wide bindings itself.

Lab users need nothing besides `clabernetes-lab-editor`, which clabernetes ships
(`labRoles.enabled`).

`clab-api-server-provisioner` allows:

| Resource | Verbs | Why |
|---|---|---|
| `namespaces` | create, delete, get, list | lab namespaces |
| `rolebindings` | create, get | bind the lab's users |
| `clusterroles` `clabernetes-lab-editor` | bind, get | only this role can be handed out; get for the startup check |
| `users` | impersonate | act as the user; `resourceNames` cannot match a prefix, so users are not limited (list every `clab:<user>` to limit them) |
| `groups` `clab:users`, `clab:admins` | impersonate | add `clab:shared-<group>` for every group that owns shared labs |
| `resourcequotas` | create | `CLAB_KUBE_LAB_QUOTA` |
| `secrets` | create (and get on the source secret) | copy `CLAB_C9S_IMAGE_PULL_SECRET` |

It has no rights on clabernetes resources or Pods itself. The server can
impersonate any user name, so treat its credentials like a cluster administrator's.

Without a kubeconfig, run the server in a Pod with `serviceAccountName: clab-api-server`.
Outside the cluster, give it a kubeconfig for that ServiceAccount:

```bash
kubectl apply -f docs/kubernetes/provisioner-rbac.yaml -f docs/kubernetes/admins-rbac.yaml
TOKEN=$(kubectl -n clab-api-server create token clab-api-server --duration=8760h)
# build a kubeconfig with that token and set CLAB_KUBECONFIG to it
```

Check a user's rights as the server will use them:

```bash
kubectl auth can-i create pods --subresource exec -n c9s-alice-lab1 --as clab:alice --as-group clab:users   # yes
kubectl auth can-i get pods -n c9s-alice-lab1 --as clab:bob --as-group clab:users                           # no
```

## Trust model

These roles isolate **users from each other**: a user can only reach labs in namespaces they
are bound in, and every action is attributed to the user in the audit log.

They do **not** isolate **the worker from the lab**: lab namespaces are PSA `privileged`,
device containers and the `clabwire` sidecar run privileged, and RBAC cannot limit `pods/exec`
to one container. Whoever can deploy a lab or exec into it can reach the worker. That is the
same trust level as `clab_admins` on a Docker host. Clusters shared with other workloads should
keep labs on dedicated, tainted workers (taints and a nodeSelector in the clabernetes
NodeProfile).

## Startup checks

Before it serves requests the server:

1. runs a `SelfSubjectAccessReview` for every permission of `clab-api-server-provisioner` and
   lists every one that is denied,
2. runs containerlab's clabernetes release check: the published OpenAPI schema of
   `nodes.c9s.run` must have `spec.runState` (any authenticated identity may read it), and
3. checks that the ClusterRole `clabernetes-lab-editor` exists.

If any of them fails, it exits with a message that names what is missing.

## What clients see

`GET /health` reports the runtime:

```json
{
  "status": "healthy",
  "runtime": "c9s",
  "namespaceMode": "per-lab",
  "features": ["validate", "graph-mermaid", "graph-dot", "exec-filters", "lab-lifecycle-node-filter",
               "save-copy", "inspect-details", "node-stats", "log-stream", "terminal-resume",
               "node-logs-runtime", "interface-state", "c9s-runtime", "lab-host-info",
               "lab-lifecycle-timeout"]
}
```

| Feature | Meaning |
|---|---|
| `c9s-runtime` | Labs run on Kubernetes through clabernetes. Only with `CLAB_RUNTIME=c9s`. |
| `node-logs-runtime` | Node logs come from the configured runtime (on c9s: the device container log). |
| `interface-state` | The events stream reports interface `up`/`down` events. |
| `node-stats` | Left out on c9s while `metrics.k8s.io` is not served. |
| `lab-host-info` | `GET /api/v1/lab-host` describes the lab runtime (all runtimes). |
| `lab-lifecycle-timeout` | Deploy, redeploy, apply and destroy take `timeout` (see below). With every runtime. |

`namespaceMode` is always `per-lab`: every lab has its own namespace.

`GET /api/v1/lab-host` (any signed-in user) names the cluster and the deploy defaults the
user's labs get:

```json
{
  "runtime": "c9s",
  "defaultTimeout": "10m",
  "c9s": {
    "context": "c9s-provisioner",
    "cluster": "c9s",
    "namespacePattern": "c9s-alice-{lab}",
    "sharedNamespacePattern": "c9s-shared-{lab}",
    "exposeType": "None",
    "persistence": true,
    "imagePullSecret": "regcred",
    "labQuota": false,
    "metrics": true
  }
}
```

`context` and `cluster` are names from the server's kubeconfig (`""` and `in-cluster` with
the Pod's ServiceAccount); the cluster's address, credentials and file paths are never
reported. `namespacePattern` is `CLAB_KUBE_NAMESPACE_TEMPLATE` rendered for the signed-in
user with `{lab}` left in, `imagePullSecret` the secret's name without its namespace,
`labQuota` whether `CLAB_KUBE_LAB_QUOTA` is set, and `metrics` whether `metrics.k8s.io` is
served. `defaultTimeout` is containerlab's timeout of a deploy, redeploy, apply or destroy
that passes no `timeout` (see [Timeouts](#timeouts)). Docker and Podman servers answer
`{"runtime": "docker", "defaultTimeout": "5m"}` (or `podman`) without `c9s`.

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

## Timeouts

On c9s containerlab waits up to 10 minutes by default for a lab's Pods, as
`containerlab deploy -r c9s` does: a cluster pulls node images and schedules Pods slower
than a local Docker. Deploy, redeploy, apply and destroy take an optional `timeout` query
parameter (containerlab's `--timeout`, a Go duration such as `30m`, at most `2h`) for labs
with large images. The request runs for the timeout plus 5 minutes, and a redeploy for twice
the timeout plus 5 minutes, so containerlab's own timeout error reaches the client.

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
