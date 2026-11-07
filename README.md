# Containerlab API Server

Run [containerlab](https://containerlab.dev/) labs on a Linux host and drive them over HTTPS. One server, every lab, every user, one REST API: deploy, inspect, exec, capture, and share labs from scripts, CI, or the [Containerlab Apps](https://srl-labs.github.io/containerlab-app/docs/).

**Documentation: [srl-labs.github.io/clab-api-server](https://srl-labs.github.io/clab-api-server/)** · [API reference](https://srl-labs.github.io/clab-api-server/api/)

## Install

On a Linux host with Docker (`amd64` or `arm64`):

```bash
curl -fsSL https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh | sudo bash -s -- install
sudo usermod -aG clab_api <username>
sudo systemctl enable --now clab-api-server
```

The server listens on `https://<host>:8090`. Containerlab is built in; there is nothing else to install. For containers, plain binaries, and Kubernetes, see [Install](https://srl-labs.github.io/clab-api-server/install/).

## Use

```bash
TOKEN=$(curl -sk -X POST https://localhost:8090/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<username>","password":"<password>"}' | jq -r .token)

curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8090/api/v1/labs
```

Next: the [quick start](https://srl-labs.github.io/clab-api-server/getting-started/quick-start/) deploys a lab end to end. A running server also serves Swagger UI at `/swagger/index.html` and ReDoc at `/redoc`.

## Develop

```bash
task          # tidy, generate the OpenAPI spec, build into dist/
task test     # integration tests against a running server
task docs     # preview the documentation site
```

See [Develop and test](https://srl-labs.github.io/clab-api-server/contributing/).

## License

[Apache 2.0](LICENSE)
