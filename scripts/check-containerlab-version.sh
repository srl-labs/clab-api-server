#!/usr/bin/env bash
# Check that the selected module contains the source currently published by upstream.
set -euo pipefail

module=github.com/srl-labs/containerlab
selected=$(GOWORK=off go list -m -json "$module")
version=$(jq -er 'if .Replace then error("containerlab replacements are not supported by this check") else .Version end' <<<"$selected")

# A pseudo-version identifies a commit, not a Git tag. Fetch by hash so that a
# subsequently added tag cannot cause Go to reject the pseudo-version as noncanonical.
query=$version
if [[ $version =~ [.-][0-9]{14}-([0-9a-f]{12})$ ]]; then
  query=${BASH_REMATCH[1]}
fi

cached=$(GOWORK=off go mod download -json "$module@$version")
cached_dir=$(jq -er '.Dir' <<<"$cached")

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
go_bin="$(go env GOROOT)/bin/go"
# Use a clean module cache outside this repository. Disable the checksum database
# only for this independent Git download: its purpose is to compare upstream's
# current source with the normally verified, go.sum-pinned module above.
(
  cd "$tmp"
  GOMODCACHE="$tmp/modcache" GOPROXY=direct GOSUMDB=off GOWORK=off GOTOOLCHAIN=local GOFLAGS=-modcacherw \
    "$go_bin" mod download -json "$module@$query" > "$tmp/upstream.json" || {
      cat "$tmp/upstream.json" >&2
      exit 1
    }
)
upstream_dir=$(jq -er '.Dir' "$tmp/upstream.json")
upstream_revision=$(jq -er '.Origin.Hash' "$tmp/upstream.json")

if ! diff -qr "$cached_dir" "$upstream_dir" > "$tmp/differences"; then
  echo "::error::Containerlab $version does not match upstream revision $upstream_revision ($query). The tag or module content may have changed; pin an immutable revision or update to a new release." >&2
  head -n 30 "$tmp/differences" >&2
  exit 1
fi

echo "Containerlab $version matches upstream revision $upstream_revision ($query)."
