---
description: Build the server, run the tests, and work on these docs.
---

# Develop and test

## Build

You need Go, [Task](https://taskfile.dev/), and the PAM headers (`libpam-dev` on Debian and Ubuntu).

```bash
git clone https://github.com/srl-labs/clab-api-server.git
cd clab-api-server
task deps                 # libpam-dev, swag, test tools
cp .env.example .env      # set JWT_SECRET
task                      # tidy, generate the OpenAPI spec, build
sudo ./dist/clab-api-server-linux-amd64 -env-file .env
```

| Task | Does |
| --- | --- |
| `task build` | Build `dist/clab-api-server-linux-<arch>`. |
| `task swag` | Regenerate the OpenAPI spec in `docs/` from handler annotations. |
| `task test` | Run the integration tests and write an HTML report to `test-reports/`. |
| `task docs` | Preview this site. |
| `task docs:build` | Build this site into `site/`. |

## Test

The tests in `tests_go/` call a running server. Configure them in `tests_go/.env` (API URL, users, and `GOTEST_SIMPLE_TOPOLOGY_CONTENT`, a topology with a `{lab_name}` placeholder), then:

```bash
task test                                               # everything
go test -v ./tests_go/... -run TestAuthSuite/TestLoginSuccess   # one test
```

The test users must exist on the host, in `API_USER_GROUP` and `SUPERUSER_GROUP`.

## These docs

The site is built with [Zensical](https://zensical.org/) from `docs-site/`. You need [uv](https://docs.astral.sh/uv/).

```bash
task docs          # live preview on http://localhost:8000
task docs:build    # strict build into site/
```

- Pages are Markdown in `docs-site/`; the navigation is in `zensical.toml`.
- The [API reference](reference/api.md) is ReDoc reading `docs/swagger.json`. Run `task swag` after changing handler annotations.
- Topology diagrams are `clab` fences, rendered by the [Containerlab topology viewer](https://srl-labs.github.io/containerlab-app/docs/viewer/standalone/). Reference a file from `docs-site/diagrams/`, and its `.annotations.json` for a fixed layout:

    ````markdown
    ```clab file="diagrams/hello.clab.yml" view="split" height="300"
    ```
    ````

- Every push to `main` publishes the site to GitHub Pages.
