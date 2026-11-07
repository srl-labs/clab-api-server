---
description: What the API server does on a lab host, who it acts as, and where labs live.
---

# How it works

`clab-api-server` is a single binary that embeds containerlab as a Go library. It runs on the lab host, signs users in with their Linux accounts, and runs containerlab for them.
{ .lead }

<div class="facts" markdown>
<div markdown>

Sign-in

Linux user and password, checked through PAM. The server returns a JWT for the following calls.

</div>
<div markdown>

Labs

Docker or Podman on the same host, or a Kubernetes cluster through clabernetes.

</div>
<div markdown>

Files

Each user's topologies live in a workspace: `~/.clab/` or `$CLAB_LABS_ROOT/<user>/`.

</div>
</div>

## A request, end to end

<figure class="diagram" markdown>

```clab file="diagrams/architecture.clab.yml" annotations="diagrams/architecture.clab.yml.annotations.json" title="How clients reach labs through the API server" height="380" borderless="true" zoom="false" pan="false" fit-padding="0.1"
```

<figcaption>Every client talks HTTPS to one server. The server runs each lab on behalf of the user who owns it.</figcaption>
</figure>

1. A client calls `POST /login` with a Linux user name and password. The server checks them with PAM and checks that the user is in `API_USER_GROUP` or `SUPERUSER_GROUP`.
2. The server answers with a JWT. Every call to `/api/v1/*` carries it as `Authorization: Bearer <token>`.
3. For a lab call, the server resolves the topology in the user's workspace and runs the containerlab operation in-process.
4. Containers are labelled with their owner. Listing, inspecting, and operating labs only reach labs the user owns, shared labs, or, for superusers, every lab.

## Who sees what

| User | Sees and manages |
| --- | --- |
| Member of `API_USER_GROUP` (`clab_api`) | Own labs and [shared labs](../guides/shared-labs.md). |
| Member of `SUPERUSER_GROUP` (`clab_admins`) | Every lab on the host, and the user management endpoints. |

With `CLAB_RUNTIME=c9s`, Kubernetes RBAC decides instead, and the server acts as the user towards the cluster. See [Labs on Kubernetes](../guides/kubernetes.md).

## Clients

- **Containerlab Apps.** The [VS Code extension, desktop app, and web app](https://srl-labs.github.io/containerlab-app/docs/) sign in to a lab host and use this API for everything.
- **Scripts and CI.** Anything that speaks HTTPS and JSON. See [Use the API](../guides/api.md).
- **Interactive docs.** A running server serves Swagger UI at `/swagger/index.html` and ReDoc at `/redoc`.

<div class="next" markdown>
[:lucide-arrow-right: Install](../install/index.md)
[:lucide-arrow-right: Security model](../reference/security.md)
</div>
