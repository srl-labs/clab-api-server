---
description: Check for updates, upgrade, downgrade, and uninstall clab-api-server.
---

# Upgrade and remove

## Upgrade

Check for a newer release and upgrade the installed binary in place:

```bash
clab-api-server version check
sudo clab-api-server version upgrade
```

The installer can do the same, and also install a specific release. Installing an older tag is the supported way to downgrade:

```bash
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- upgrade
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- upgrade --version clab-0.73.0-api-0.2.1
```

An upgrade restarts the service only if it was running before. Release tags are listed on the [releases page](https://github.com/srl-labs/clab-api-server/releases).

## Uninstall

Remove the service and binary, and keep the config file:

```bash
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- uninstall
```

Add `--purge` to remove the config too, and `--yes` to skip the prompt.

Uninstalling leaves labs, workspaces, and the `clab_api` and `clab_admins` groups in place.
