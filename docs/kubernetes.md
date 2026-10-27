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
               "capture-stream", "wireshark-vnc"]
}
```

| Feature | Meaning |
|---|---|
| `c9s-runtime` | Labs run on Kubernetes through clabernetes. Only with `CLAB_RUNTIME=c9s`. |
| `node-logs-runtime` | Node logs come from the configured runtime (on c9s: the device container log). |
| `interface-state` | The events stream reports the state of node interfaces (`create`, `update`, `delete` with `state` `up`, `down`, `lower-layer-down`, ...), as netlink does for Docker labs. |
| `node-stats` | Left out on c9s while `metrics.k8s.io` is not served. |
| `lab-host-info` | `GET /api/v1/lab-host` describes the lab runtime (all runtimes). |
| `capture-stream` | Packet capture through clabwire: `capture/interfaces`, `capture/stream` and capture tickets (see [Packet capture](#packet-capture)). Only with `CLAB_RUNTIME=c9s`. |
| `wireshark-vnc` | Wireshark VNC capture sessions. On c9s only while Docker answers on the server host (checked once a minute). |

`namespaceMode` is always `per-lab`: every lab has its own namespace.

`GET /api/v1/lab-host` (any signed-in user) names the cluster and the deploy defaults the
user's labs get:

```json
{
  "runtime": "c9s",
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
served. Docker and Podman servers answer `{"runtime": "docker"}` (or `podman`) without `c9s`.

Features that need Docker or Podman on the server host are left out on c9s:
`snapshot-save`, `deploy-restore`, `sshx-readers`, `gotty-options`.

Inspect records of c9s nodes carry `namespace`, `pod`, `container`, `node_uid`,
`exposed_ports` and `load_balancer_address`; `container_id` is `<namespace>/<lab>/<node>` and
the node name is `<lab>-<node>`. Otherwise they read like Docker's:

- `state` is `created`, `running` or `exited`, and `status` `Created`, `health: starting`,
  `healthy` or `Exited`;
- `labPath`/`absLabPath` is the topology file on the server host the lab was deployed from (see
  [What users can edit](#users-and-their-rights) for when the server reports
  `k8s://<namespace>/topologies/<lab>` instead).

The events stream is containerlab's: container events with Docker's actions (`create`, `start`,
`kill`, `stop`, `die`, `destroy`, `health_status: ...`) and attributes (`containerlab`,
`clab-node-name`, `clab-node-kind`, `clab-owner`, `clab-topo-file`, `image`, `mgmt_ipv4`,
`state`, ...), plus `namespace`, `node` and `pod`; interface events for the node's link
interfaces under their topology names, `eth0` and `lo`. A user's stream covers the namespaces
of the user's labs; a superuser's every namespace.

## How the server reaches nodes

| Path | On c9s |
|---|---|
| Deploy, apply, destroy, inspect, start/stop/restart, exec, save, validate, events | containerlab's c9s runtime. Apply is a deploy; `dryRun=true` returns the plan as `runtimePlan`. |
| Node logs | The device container log (`tail`, `follow`, timestamps). |
| Terminals | `shell` and `telnet` exec in the device container; `ssh` logs in with the server's SSH client over a port-forward to port 22, or to the LoadBalancer address when the node exposes port 22. |
| SSH access (`/nodes/{node}/ssh`) | The server's port range as before; every connection is a port-forward to the node's port 22. |
| Browser ports | The node's exposed ports, each with a `proxyPath`: `ANY /api/v1/labs/{lab}/nodes/{node}/ports/{port}/proxy/*` proxies HTTP and WebSockets through a port-forward. The `Authorization` header is not forwarded. |
| Stats | `metrics.k8s.io` (CPU over the metrics window, memory working set of the device containers). Without the API the stats stream answers 501. |
| Packet capture | containerlab's c9s capture: clabwire in the node's pod, one merged pcapng stream. See [Packet capture](#packet-capture). |
| Interfaces (`/interfaces`) | containerlab's c9s interface inspection as the user: per running node (`<lab>-<node>`) the lab link interfaces with their aliases, `eth0` and `lo`, with MAC, index, MTU, type and state, the interfaces the events stream reports. |
| Graphs | Rendered from the topology file, without the cluster. |

Lab names must be lowercase DNS labels (letters, digits and dashes, starting with a letter).
Other names are refused with the name to use instead.

## Packet capture

On c9s the server captures through containerlab's c9s capture: `clabwire`, the sidecar in
every lab pod, captures the requested lab link interfaces, and containerlab merges them into one
pcapng section. Every call runs as the signed-in user, so Kubernetes decides whether the user may
capture (`pods/exec` on the lab's pods, which `clabernetes-lab-editor` grants). Edgeshark is not
used: clabwire only allows the interfaces of the lab's links, so the management interface and
`c9s0` cannot be captured.

The stream has one interface per target, named `<node>:<interface>`, before any packet, and
packets in timestamp order. Captures longer than clabwire's one-hour limit are chained by
containerlab without gaps or duplicates. When the client goes away the capture stops in the pod
(clabwire ends on stdin close).

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/labs/{lab}/capture/interfaces` | The capturable interfaces of the running nodes: `[{"node","interface","alias"?,"peerNode","peerInterface"}]`. |
| `GET /api/v1/labs/{lab}/capture/stream?target=<node>:<iface>[&target=…][&duration=30s][&packetLimit=N][&snapLength=N][&download=1]` | The capture as `application/x-pcapng`, chunked and flushed as it is produced, until the duration or packet limit is reached or the client disconnects. `download=1` adds `Content-Disposition: attachment; filename="<lab>-<timestamp>.pcapng"`. Errors before the first byte are JSON: 400 for a target the lab cannot capture, 403 when Kubernetes refuses, 404 for a lab the user does not have, 409 for a node that is not running, 501 without c9s. |
| `POST /api/v1/labs/{lab}/capture/tickets` | Body `{"targets":[{"node","interface"}],"duration"?:"30s"}`; answers `201 {"ticket","packetflixUri","expiresAt"}`. |
| `GET /api/v1/capture/packetflix/{ticket}` | A websocket without a bearer token: the ticket is the credential. |

A target names the node as the topology does (or its sanitized name) and the interface by name
or alias, e.g. `srl1:ethernet-1/1`. The node ends at the first colon.

**Tickets and Packetflix.** Clients that cannot send a bearer token use a ticket: 256 random
bits, single use, valid for 60 seconds, bound to the user, the lab and the targets. Redeeming it
starts the capture as that user and sends the pcapng stream in binary websocket messages, like
Edgeshark's Packetflix service, so Edgeshark's `packetflix:` URL handler
([cshargextcap](https://github.com/siemens/cshargextcap)) works unchanged: open `packetflixUri`
and Wireshark starts capturing. The URI carries the `container` query parameter cshargextcap
requires. The interfaces a client names (the `network-interfaces` of `container`, and `nif`,
also as `Clustershark-*` headers) must be targets of the ticket, otherwise the server answers
`403` (a single-use ticket is used up); the capture covers the `nif` targets, or all of the
ticket's. Unknown, used, revoked and expired tickets get `404`. The server's request and
error logs show ticket paths as `/api/v1/capture/packetflix/<redacted>`. cshargextcap
asks `{ticket}/discover/mobyshark` first and dials `{ticket}/capture`; the server answers both.
The capture ends with a close frame (1000) after the ticket's duration, or when the client
closes.

The scheme and host of `packetflixUri` come from the request. Behind a reverse proxy, list the
proxy in `TRUSTED_PROXIES`; only then does the server use its `X-Forwarded-Proto` and
`X-Forwarded-Host`.

**Wireshark VNC.** `POST /api/v1/labs/{lab}/capture/wireshark-vnc-sessions` takes the node's
inspect name (`<lab>-<node>`) as `containerName` and an interface (or alias) as
`interfaceName`, and starts one Wireshark VNC container per node on the server host. Its
`PACKETFLIX_LINK` is a ticket URL of this server, reached through the Docker host gateway; it
is not attached to an Edgeshark network. With TLS, the container reaches the server under the
first DNS name of its certificate other than `localhost` (mapped to the host gateway), or its
first non-loopback IP address, and trusts the certificate (mounted, `SSL_CERT_FILE`). The
certificate therefore needs such a name; the auto-generated one has the host name. This needs
Docker on the server host; without it the routes answer 501 and `/health` leaves out
`wireshark-vnc`.

A session's link carries a **session ticket**, so restarting the capture inside its Wireshark
works: it is bound to the user, the lab and the session's targets like any ticket, but redeems
any number of times while the session exists. Closing the session, or its expiry
(`CAPTURE_WIRESHARK_SESSION_TTL`), revokes it: it is refused from then on, and captures that
still run on it end (close `1008` "capture ticket revoked"), as does the container.

## Not supported on c9s

These answer `501` with `<operation> is not supported by lab runtime c9s`:

- image management (`/images`)
- Edgeshark (`/tools/edgeshark/*`) and Edgeshark's Packetflix URIs (`/capture/packetflix`); use
  [packet capture](#packet-capture) instead
- Wireshark VNC sessions when the server host has no Docker
- netem, veth, VxLAN and TX offload tools
- VM snapshots (`/snapshots`) and deploys that restore them
- SSHX and GoTTY sharing, fcli, Tailscale status
- pause and unpause
- link inspection (`/links`)
- host metrics (`/health/metrics`)

Deploy options that only local runtimes have (node filter, management network overrides,
export templates, graceful destroy) also answer 501.
