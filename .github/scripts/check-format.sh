#!/usr/bin/env bash
set -euo pipefail

files=$(git ls-files -z '*.go' | xargs -0 gofmt -l)
if [[ -n "$files" ]]; then
  printf 'Go files need formatting:\n%s\n' "$files" >&2
  exit 1
fi
