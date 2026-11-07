---
description: Run labs on a Kubernetes cluster through clabernetes, with Kubernetes RBAC as the authority.
---

# Labs on Kubernetes

With `CLAB_RUNTIME=c9s` the API server runs labs on a Kubernetes cluster through
[clabernetes](https://containerlab.dev/manual/clabernetes/) (c9s) instead of Docker or Podman
on its own host. It uses the c9s lab runtime of the containerlab library it links, so labs
behave as `containerlab deploy -r c9s` labs do.
{ .lead }

<figure class="diagram" markdown>

```clab file="diagrams/kubernetes.clab.yml" annotations="diagrams/kubernetes.clab.yml.annotations.json" title="Labs on Kubernetes through the API server" height="380" borderless="true" zoom="false" pan="false" fit-padding="0.1"
```

<figcaption>Each lab gets its own namespace. The server creates it, then acts as the signed-in user, so Kubernetes RBAC decides what each user may do.</figcaption>
</figure>

In short: **Kubernetes RBAC is the authority over labs.** The server uses its own identity only
to create a namespace for each lab. For everything else it acts as the signed-in user, so a user
has the same rights through the server as with `kubectl`, and the cluster's audit log names them.

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

## Set up

<div class="steps" markdown>

1. **Install clabernetes** with its lab roles enabled (`labRoles.enabled`). This ships the
   ClusterRole `clabernetes-lab-editor` that lab users get.

2. **Apply the server's RBAC.** Adjust `clab:` in the files if you change `CLAB_KUBE_USER_PREFIX`.

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/srl-labs/clab-api-server/main/docs/kubernetes/provisioner-rbac.yaml \
      -f https://raw.githubusercontent.com/srl-labs/clab-api-server/main/docs/kubernetes/admins-rbac.yaml
    ```

    - [`provisioner-rbac.yaml`](https://github.com/srl-labs/clab-api-server/blob/main/docs/kubernetes/provisioner-rbac.yaml):
      the ServiceAccount `clab-api-server` and its ClusterRole `clab-api-server-provisioner`.
    - [`admins-rbac.yaml`](https://github.com/srl-labs/clab-api-server/blob/main/docs/kubernetes/admins-rbac.yaml):
      binds `clabernetes-lab-editor` to the group `clab:admins`, so superusers see every lab.

3. **Give the server its identity.** Inside the cluster, run it in a Pod with
   `serviceAccountName: clab-api-server`. Outside, build a kubeconfig from a token of that
   ServiceAccount and point `CLAB_KUBECONFIG` at it:

    ```bash
    kubectl -n clab-api-server create token clab-api-server --duration=8760h
    ```

4. **Switch the runtime** and restart the server:

    ```bash
    CLAB_RUNTIME=c9s
    ```

    On start the server checks its permissions, the clabernetes version, and the lab role, and
    exits with a clear message if something is missing.

</div>

Check a user's rights as the server will use them:

```bash
kubectl auth can-i create pods --subresource exec -n c9s-alice-lab1 --as clab:alice --as-group clab:users   # yes
kubectl auth can-i get pods -n c9s-alice-lab1 --as clab:bob --as-group clab:users                           # no
```

## Users and their rights

| Linux | Kubernetes |
|---|---|
| user `alice` | user `clab:alice`, group `clab:users` |
| member of `SUPERUSER_GROUP` | additionally group `clab:admins` |
| member of the Linux group that owns a shared lab's directory | additionally group `clab:shared-<group>` for that lab |

Each lab lives in its own namespace, `c9s-<user>-<lab>` (or `c9s-shared-<lab>` for a shared lab).
Two users may both have a lab called `demo`.

## Trust model

These roles isolate **users from each other**: a user can only reach labs in namespaces they
are bound in, and every action is attributed to the user in the audit log.

They do **not** isolate **the worker from the lab**: lab namespaces are PSA `privileged`,
device containers and the `clabwire` sidecar run privileged, and RBAC cannot limit `pods/exec`
to one container. Whoever can deploy a lab or exec into it can reach the worker. That is the
same trust level as `clab_admins` on a Docker host. Clusters shared with other workloads should
keep labs on dedicated, tainted workers (taints and a nodeSelector in the clabernetes
NodeProfile).

## Not supported on c9s

These answer `501` with `<operation> is not supported by lab runtime c9s`:

- image management (`/images`)
- Edgeshark (`/tools/edgeshark/*`) and Edgeshark's Packetflix URIs (`/capture/packetflix`); use
  [packet capture](../reference/kubernetes.md#packet-capture) instead
- Wireshark VNC sessions when the server host has no Docker
- netem, veth, VxLAN and TX offload tools
- VM snapshots (`/snapshots`) and deploys that restore them
- SSHX and GoTTY sharing, fcli, Tailscale status
- pause and unpause
- link inspection (`/links`)
- host metrics (`/health/metrics`)

Deploy options that only local runtimes have (node filter, management network overrides,
export templates, graceful destroy) also answer 501.

<div class="next" markdown>
[:lucide-arrow-right: Kubernetes internals](../reference/kubernetes.md)
</div>
