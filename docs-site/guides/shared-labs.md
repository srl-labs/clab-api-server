---
description: A workspace every API user can read, edit, deploy, and destroy labs in.
---

# Shared labs

A shared workspace is one folder that every signed-in user works in together. It appears as `@shared/` next to each user's own files.
{ .lead }

<figure class="diagram" markdown>

```clab file="diagrams/shared-labs.clab.yml" annotations="diagrams/shared-labs.clab.yml.annotations.json" title="Personal and shared labs on one API server" height="340" borderless="true" zoom="false" pan="false" fit-padding="0.1"
```

<figcaption>Alice and Bob each keep their own labs. Both can open, change, and run the labs in the shared folder.</figcaption>
</figure>

## Turn it on

Set a dedicated absolute folder, separate from personal workspaces, and restart the server:

```bash
CLAB_SHARED_LABS_ROOT=/var/lib/containerlab/shared-labs
```

Leave it empty to keep sharing off. A containerized server must mount the folder at the same path inside and outside.

## Who can do what

Every API user can read, edit, deploy, operate, and destroy labs in the shared folder. There are no per-user or per-group rules, and users need no extra Linux group memberships. Personal labs keep their usual access rules.

Terminal, SSH, and capture sessions stay private to the user who opened them; superusers keep their usual access.

## Use it

Create a directory, upload a topology, and deploy it by its `@shared/` path:

```bash
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"path":"@shared/demo"}' \
  $API/api/v1/labs/workspace/directory

curl -sk -X PUT -H "Authorization: Bearer $TOKEN" \
  --data-binary @demo.clab.yml \
  "$API/api/v1/labs/workspace/file?path=%40shared%2Fdemo%2Fdemo.clab.yml"

curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/labs/demo/deploy?path=%40shared%2Fdemo%2Fdemo.clab.yml"
```

Any other user can now reach `/api/v1/labs/demo`, its nodes, topology, and events.

## Rules

- Topology listings include shared files as `@shared/<dir>/<file>`, deployed or not. Keep using that `yamlFileName` for file and deploy calls.
- Redeploying or reconfiguring keeps the original owner. To reconfigure, deploy the same shared path with `reconfigure=true`.
- Deploys from JSON, an archive, or a URL always create personal labs.
- Lab names must be unique across all running labs.
- Destroy keeps the source. `purgeLabDir=true` also deletes the topology's directory, as long as it is below the shared root; the root itself cannot be purged.
- Files cannot be moved between personal and shared workspaces.

## Test it

With the server configured as above:

```bash
GOTEST_SHARED_LABS=true go test -count=1 ./tests_go -run TestSharedLabsSuite
```

The suite uses `tests_go/.env` and creates and removes a temporary second API user.
