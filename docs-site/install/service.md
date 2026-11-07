---
description: Install clab-api-server as a systemd service with the installer script.
---

# Systemd service

The installer picks the right binary for the host, writes a config file, creates the user groups, and installs a systemd unit.
{ .lead }

<div class="steps" markdown>

1. **Run the installer.**

    ```bash
    curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- install
    ```

    It creates:

    - `/usr/local/bin/clab-api-server`
    - `/etc/clab-api-server/clab-api-server.env`, with a random `JWT_SECRET`
    - `/etc/systemd/system/clab-api-server.service`
    - the groups `clab_api` and `clab_admins`, if missing

2. **Review the config.** At least set `API_SERVER_HOST` to the name or address clients use to reach this host.

    ```bash
    sudoedit /etc/clab-api-server/clab-api-server.env
    ```

    All settings are listed in the [configuration reference](../reference/configuration.md).

3. **Let users in.**

    ```bash
    sudo usermod -aG clab_api alice      # own labs
    sudo usermod -aG clab_admins bob     # every lab
    ```

4. **Start the service.**

    ```bash
    sudo systemctl enable --now clab-api-server
    sudo systemctl status clab-api-server
    ```

</div>

!!! tip
    `install --start` enables and starts the service right away with the generated defaults. Restart it after you edit the config file.

The service runs as `root`: it controls the container runtime, network namespaces, Linux users, and lab files.

## Behind a proxy

Export the proxy variables and keep them for the installer with `sudo -E`:

```bash
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080
export NO_PROXY=localhost,127.0.0.1
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo -E bash -s -- install
```

The service needs them too: add `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` to `/etc/clab-api-server/clab-api-server.env` and restart it.

## Store labs outside home directories

By default each user's topologies live in `~/.clab/`. To keep them elsewhere, set an absolute path:

```bash
CLAB_LABS_ROOT=/var/lib/containerlab/labs
```

Files then go to `/var/lib/containerlab/labs/<username>/`. `~` is not expanded, because the service runs as `root` on behalf of many users.

<div class="next" markdown>
[:lucide-arrow-right: Quick start](../getting-started/quick-start.md)
[:lucide-arrow-right: Upgrade and remove](upgrade.md)
</div>
