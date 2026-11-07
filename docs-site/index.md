---
title: Containerlab over HTTPS
template: home.html
hide:
  - navigation
  - toc
  - path
---

<div class="home-hero" markdown>
# <span class="hero-wordmark"></span> over HTTPS

<div class="hero-side" markdown>
<p class="hero-lede"><strong>One server on your lab host. Every lab, every user, one REST API.</strong> Deploy, inspect, exec, capture, and share labs from scripts, CI, or the Containerlab Apps.</p>

<div class="hero-actions" markdown>
[Quick start :lucide-arrow-right:](getting-started/quick-start.md){ .hero-button .hero-button-primary }
[API reference :lucide-arrow-up-right:](reference/api.md){ .hero-button .hero-button-secondary }
</div>
</div>

</div>

<div class="home-code" markdown>
```bash
# Install on a Linux host with Docker
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- install --start

# Sign in with a Linux account, then list your labs
TOKEN=$(curl -sk https://lab-host:8090/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"..."}' | jq -r .token)
curl -sk -H "Authorization: Bearer $TOKEN" https://lab-host:8090/api/v1/labs
```
</div>

<div class="home-section-heading" markdown>
## One server between your tools and your labs

Clients sign in with a Linux account and get a token. The server runs each lab for the user who asked, and keeps users' labs apart.
</div>

```clab file="diagrams/architecture.clab.yml" annotations="diagrams/architecture.clab.yml.annotations.json" title="How clients reach labs through the API server" height="400" borderless="true" zoom="false" pan="false" fit-padding="0.1"
```

<div class="home-section-heading" markdown>
## Everything containerlab does, over the network

Containerlab is built in as a library. There is no separate CLI to install, and every call runs as the signed-in user's lab.
</div>

<div class="home-features" markdown>
<div markdown>
<span class="card-icon">:lucide-play:</span>

### Lab lifecycle

Deploy from JSON, a file, an archive, or a URL. Redeploy, apply changes, and destroy.

[Use the API](guides/api.md){ .card-link }
</div>
<div markdown>
<span class="card-icon">:lucide-folder-tree:</span>

### Workspaces

Every user gets a lab workspace. Keep topologies in Git repositories and edit them over the API.

[Workspaces](guides/workspaces.md){ .card-link }
</div>
<div markdown>
<span class="card-icon">:lucide-square-terminal:</span>

### Get in

Exec commands, browser terminals, SSH through the server, and node logs, live or static.

[Common calls](guides/api.md#common-calls){ .card-link }
</div>
<div markdown>
<span class="card-icon">:lucide-radio-tower:</span>

### Capture

Stream pcapng from any link, or open Wireshark in the browser.

[Capture packets](guides/api.md#capture-packets){ .card-link }
</div>
<div markdown>
<span class="card-icon">:lucide-users:</span>

### Multi-user

Linux accounts sign in. Users see their own labs, admins see all, and shared labs are open to everyone.

[Users and sign-in](guides/users.md){ .card-link }
</div>
<div markdown>
<span class="card-icon">:lucide-container:</span>

### Docker, Podman, Kubernetes

Run labs next to the server, or on a cluster through clabernetes with Kubernetes RBAC.

[Labs on Kubernetes](guides/kubernetes.md){ .card-link }
</div>
</div>

<div class="home-section-heading" markdown>
## Pick how it runs

All three serve HTTPS on port `8090` and sign users in with their Linux accounts.
</div>

<div class="home-cards" markdown>
<div class="home-card" markdown>
<span class="card-icon">:lucide-server:</span>

### Systemd service

The installer sets up the binary, a config file, the user groups, and a service. For hosts you keep.

[Install the service :lucide-arrow-up-right:](install/service.md){ .card-link }
</div>
<div class="home-card" markdown>
<span class="card-icon">:lucide-box:</span>

### Container

One `containerlab tools api-server start`, or your own `docker run`. For trials and container-managed hosts.

[Run in a container :lucide-arrow-up-right:](install/container.md){ .card-link }
</div>
<div class="home-card" markdown>
<span class="card-icon">:lucide-terminal:</span>

### Binary

Download the binary and supervise it yourself. For debugging and custom setups.

[Run the binary :lucide-arrow-up-right:](install/binary.md){ .card-link }
</div>
</div>

<div class="home-bottom" markdown>
<div markdown>
### A lab host in five minutes
Install the server, add a user, and deploy a lab with `curl`.
</div>
[Start the quick start :lucide-arrow-up-right:](getting-started/quick-start.md){ .hero-button .hero-button-primary }
</div>
