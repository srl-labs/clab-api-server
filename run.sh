#!/bin/bash

set -o errexit
set -o pipefail
set -e

function build-builder-image {
    docker build -t ghcr.io/srl-labs/clab-api-builder:latest -f build.dockerfile .
}

function build-with-builder-image {
    docker run --rm -i -t -v $(pwd):/app ghcr.io/srl-labs/clab-api-builder:latest
}

# -----------------------------------------------------------------------------
# Bash runner functions.
# -----------------------------------------------------------------------------
function help {
  printf "%s <task> [args]\n\nTasks:\n" "${0}"

  compgen -A function | grep -v "^_" | cat -n

  printf "\nExtended help:\n  Each task has comments for general usage\n"
}

TIMEFORMAT=$'\nTask completed in %3lR'
time "${@:-help}"