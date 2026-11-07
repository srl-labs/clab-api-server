---
description: Install the API server, add a user, and deploy a lab with curl.
---

# Quick start

Install the server on a Linux host with Docker, let one user in, and run a two-node lab with nothing but `curl`.
{ .lead }

This is the lab you will run: two Linux containers, wired together on `eth1`.

```clab file="diagrams/hello.clab.yml" view="split" height="280" fit-padding="0.6"
```

<div class="steps" markdown>

1. **Install and start the server.**

    ```bash
    curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- install --start
    ```

    The server now listens on `https://<host>:8090` with a self-signed certificate.

2. **Let a user in.** Any Linux account in the `clab_api` group can sign in with its password.

    ```bash
    sudo usermod -aG clab_api alice
    ```

3. **Sign in.** The response holds a JWT for every further call.

    ```bash
    API=https://localhost:8090
    TOKEN=$(curl -sk -X POST $API/login \
      -H 'Content-Type: application/json' \
      -d '{"username":"alice","password":"..."}' | jq -r .token)
    ```

4. **Save the topology.** Write the lab above to `hello.clab.yml`, or download it from the diagram:

    ```bash
    cat > hello.clab.yml <<'EOF'
    name: hello

    topology:
      defaults:
        kind: linux
        image: alpine:3.23
      nodes:
        client: {}
        server: {}
      links:
        - endpoints: [client:eth1, server:eth1]
    EOF
    ```

5. **Upload and deploy it.** The file goes into your [workspace](../guides/workspaces.md), then the server deploys it from there:

    ```bash
    curl -sk -X PUT "$API/api/v1/labs/workspace/file?path=hello.clab.yml" \
      -H "Authorization: Bearer $TOKEN" --data-binary @hello.clab.yml

    curl -sk -X POST "$API/api/v1/labs/hello/deploy?path=hello.clab.yml" \
      -H "Authorization: Bearer $TOKEN"
    ```

6. **Look inside.** Inspect the lab, then ping across the link from `client`:

    ```bash
    curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/labs/hello

    curl -sk -X POST "$API/api/v1/labs/hello/exec?nodes=client" \
      -H "Authorization: Bearer $TOKEN" \
      -H 'Content-Type: application/json' \
      -d '{"command": "ip addr add 10.0.0.1/24 dev eth1"}'
    curl -sk -X POST "$API/api/v1/labs/hello/exec?nodes=server" \
      -H "Authorization: Bearer $TOKEN" \
      -H 'Content-Type: application/json' \
      -d '{"command": "ip addr add 10.0.0.2/24 dev eth1"}'
    curl -sk -X POST "$API/api/v1/labs/hello/exec?nodes=client" \
      -H "Authorization: Bearer $TOKEN" \
      -H 'Content-Type: application/json' \
      -d '{"command": "ping -c 3 10.0.0.2"}'
    ```

    Each answer holds the command's `stdout`, `stderr`, and exit code per node.

7. **Destroy it.**

    ```bash
    curl -sk -X DELETE "$API/api/v1/labs/hello" -H "Authorization: Bearer $TOKEN"
    ```

</div>

`hello.clab.yml` stays in Alice's workspace (`~/.clab/` by default), ready to deploy again. The [Containerlab Apps](https://srl-labs.github.io/containerlab-app/docs/) show the same lab, and can draw, deploy, and open terminals on it.

<div class="next" markdown>
[:lucide-arrow-right: How it works](how-it-works.md)
[:lucide-arrow-right: Use the API](../guides/api.md)
[:lucide-arrow-right: Configuration](../reference/configuration.md)
</div>
