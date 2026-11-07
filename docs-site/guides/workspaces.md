---
description: How topology files are found, addressed, edited, and deployed in a user's workspace.
---

# Workspaces and topology files

A user's workspace holds their topologies, annotations, and any other lab files. Keep several labs, or whole Git repositories, side by side.
{ .lead }

The workspace is `~/.clab/`, or `$CLAB_LABS_ROOT/<username>/` when that is set. [Shared labs](shared-labs.md) appear in it as `@shared/`.

## Discovery

`GET /api/v1/labs/topology/files` lists every topology in the workspace, in nested directories too:

- `*.clab.yml`, `*.clab.yaml`, and `*.clab.gotmpl` ([templates](templates.md)) are topologies.
- Hidden files and directories (including `.git`), `node_modules`, `__pycache__`, symbolic links, and runtime directories with `.state.clab.yaml` or `topology-data.json` are skipped.
- Repositories named `clab-*` are still found.

Two files in a repository show up as two entries:

```json
{
  "labName": "topology1",
  "yamlFileName": "repo/labs/topology1.clab.yaml",
  "annotationsFileName": "repo/labs/topology1.clab.yaml.annotations.json",
  "hasAnnotations": false,
  "deploymentState": "undeployed",
  "absolutePath": "/home/alice/.clab/repo/labs/topology1.clab.yaml"
}
```

The lab name is the YAML `name`, or the file name if there is none. `__gitBranch__` and `__gitHash__` in a `name` expand as containerlab does.

## Address a file by its path

`yamlFileName` is relative to the workspace root and identifies the document, even when two repositories use the same file name. Pass it as `path`:

```bash
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/labs/topology1/deploy?path=repo%2Flabs%2Ftopology1.clab.yaml"
```

Lab names still have to be distinct to run labs at the same time.

To tell which file a running lab came from, compare `absolutePath` with `absLabPath` in inspect output and `lab-path` in events.

## Endpoints

| Call | Purpose |
| --- | --- |
| `GET /api/v1/labs/topology/files` | List topologies. |
| `GET\|PUT /api/v1/labs/{lab}/topology/yaml` | Read or write the topology of a running lab, or the canonical `<lab>.clab.yml` of an undeployed one. |
| `GET\|PUT /api/v1/labs/{lab}/topology/annotations` | Read or write its annotations. |
| `GET\|PUT\|DELETE\|HEAD /api/v1/labs/{lab}/topology/file?path=…` | Work with one file by the path from the listing. |
| `POST /api/v1/labs/{lab}/topology/file/rename` | Rename a file. |
| `POST /api/v1/labs/{lab}/deploy?path=…` | Deploy a file from the workspace. |
| `GET /api/v1/labs/{lab}/topology/rendered?path=…` | Render a template without deploying it. |
| `GET /api/v1/labs/workspace/tree` | The whole workspace as a tree. |
| `GET\|PUT\|DELETE /api/v1/labs/workspace/file?path=…` | Any file in the workspace. |
| `POST /api/v1/labs/workspace/directory` | Create a directory. |
| `GET /api/v1/labs/workspace/events` | Stream changes to workspace files. |

Older flat and one-directory-per-lab workspaces keep their lab names, and lab-relative file paths keep working. An explicit workspace path wins when its first directory exists in the workspace.

## Browser clients

Browser apps on another origin need to be allowed:

```bash
CORS_ALLOWED_ORIGINS=https://localhost:5173,https://ui.example.com
```

The Containerlab web and desktop apps do not need this.
