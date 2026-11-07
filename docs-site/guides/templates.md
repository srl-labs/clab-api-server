---
description: Deploy Go-templated topologies and preview what they render to.
---

# Topology templates

Containerlab renders every topology as a Go template. Files named `*.clab.gotmpl` are listed like any other topology and take their variables from a file next to them.
{ .lead }

| File | Role |
| --- | --- |
| `lab.clab.gotmpl` | The template. |
| `lab.clab_vars.yml` (or `.yaml`, `.json`) | Its variables, found by name. |
| `clab_templates/*.gotmpl` | Subtemplates. |

## Preview

Render a template without deploying it:

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/labs/lab/topology/rendered?path=repo%2Flabs%2Flab.clab.gotmpl"
```

The response holds the rendered `content`, the rendered `labName`, and the `varsFiles` that were used. Template errors answer `422`.

## Another variables file

Pass `varsPath`, relative to the topology's directory, like `containerlab --vars`. It works with:

- `GET /api/v1/labs/{lab}/topology/rendered`
- `POST /api/v1/labs/{lab}/deploy`
- `PUT /api/v1/labs/{lab}` (redeploy)
- `DELETE /api/v1/labs/{lab}` (destroy)

Pass the same `varsPath` to redeploy and destroy that the lab was deployed with.
