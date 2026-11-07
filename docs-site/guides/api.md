---
description: Sign in, call the most common endpoints, stream events, and explore the API.
---

# Use the API

Every call except `/login` and `/health` needs a token. Sign in once, then send the token as a bearer header.
{ .lead }

## Sign in

```bash
API=https://localhost:8090
TOKEN=$(curl -sk -X POST $API/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"..."}' | jq -r .token)
```

A token lasts `JWT_EXPIRATION` (default `24h`). Ask for another lifetime at sign-in with `sessionDuration`:

```json
{"username": "alice", "password": "...", "sessionDuration": "36h"}
```

The server uses a self-signed certificate unless you [configure one](../reference/configuration.md#tls), hence `-k` in these examples.

## Common calls

| What | Call |
| --- | --- |
| List labs | `GET /api/v1/labs` |
| Deploy from JSON or a URL | `POST /api/v1/labs` with `topologyContent` or `topologySourceUrl` |
| Deploy a file from the workspace | `POST /api/v1/labs/{lab}/deploy?path=<file>` |
| Deploy an archive | `POST /api/v1/labs/archive` (zip or tar.gz) |
| Inspect a lab | `GET /api/v1/labs/{lab}` |
| Redeploy | `PUT /api/v1/labs/{lab}` |
| Destroy | `DELETE /api/v1/labs/{lab}` (`cleanup`, `purgeLabDir`, `graceful`) |
| Run a command | `POST /api/v1/labs/{lab}/exec` (`nodes`, `label` filters) |
| Save configs | `POST /api/v1/labs/{lab}/save` |
| Node logs | `GET /api/v1/labs/{lab}/nodes/{node}/logs` |
| SSH through the server | `POST /api/v1/labs/{lab}/nodes/{node}/ssh` |
| Capture packets | `GET /api/v1/labs/{lab}/capture/stream?target=<node>:<iface>` |
| Events | `GET /api/v1/events` |
| Server status and features | `GET /health` |

The full list, with every parameter and response, is in the [REST API reference](../reference/api.md).

### Deploy and inspect

```bash
curl -sk -X POST $API/api/v1/labs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"topologyContent":{"name":"srl01","topology":{
        "kinds":{"nokia_srlinux":{"type":"ixrd3","image":"ghcr.io/nokia/srlinux"}},
        "nodes":{"srl1":{"kind":"nokia_srlinux"},"srl2":{"kind":"nokia_srlinux"}},
        "links":[{"endpoints":["srl1:e1-1","srl2:e1-1"]}]}}}'

curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/labs/srl01
```

### Capture packets

Stream a capture to Wireshark on your machine:

```bash
curl -sk -N -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/labs/srl01/capture/stream?target=srl1:e1-1" | wireshark -k -i -
```

Repeat `target` to capture several interfaces into one stream. `GET /api/v1/labs/{lab}/capture/interfaces` lists what can be captured.

### Follow events

`/api/v1/events` streams container and interface events as NDJSON, one object per line:

```bash
curl -sk -N -H "Authorization: Bearer $TOKEN" "$API/api/v1/events?initialState=true"
```

Add `interfaceStats=true` for interface counters.

## Check what a server supports

`GET /health` needs no token. Its `features` list names optional capabilities, so clients can hide what an older server or another runtime does not offer:

```bash
curl -sk $API/health | jq .features
```

## Explore interactively

A running server documents itself:

```text
https://<host>:8090/swagger/index.html   # Swagger UI, try calls in the browser
https://<host>:8090/redoc                # ReDoc
```

### Flashpost collection

[Flashpost](https://marketplace.visualstudio.com/items?itemName=VASubasRaj.flashpost) is a REST client inside VS Code. The repository ships a ready-made collection for every endpoint in [`example/flashpost`](https://github.com/srl-labs/clab-api-server/tree/main/example/flashpost). Import it and set its variables:

| Variable | Value |
| --- | --- |
| `USER_NAME` | Linux user to sign in as |
| `USER_PASSWORD` | Its password |
| `baseUrl` | For example `localhost:8090` |
