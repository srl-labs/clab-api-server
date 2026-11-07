---
description: Download the clab-api-server binary and run it under your own supervision.
---

# Binary

Download only the binary for the host's architecture, and run it the way you want.
{ .lead }

```bash
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- pull-only
```

This installs `/usr/local/bin/clab-api-server` and nothing else. Start it with an env file:

```bash
sudo clab-api-server -env-file /path/to/clab-api-server.env
```

Start from [`.env.example`](https://github.com/srl-labs/clab-api-server/blob/main/.env.example) and change at least `JWT_SECRET`. Every setting can also be an environment variable; see the [configuration reference](../reference/configuration.md).

!!! note
    Run it as `root`, like the service does. With a direct `sudo` run, keep proxy variables with `sudo -E`.

The groups in `API_USER_GROUP` and `SUPERUSER_GROUP` must exist:

```bash
sudo groupadd -f clab_api
sudo groupadd -f clab_admins
```
