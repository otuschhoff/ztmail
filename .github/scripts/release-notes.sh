#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: release-notes.sh <vVERSION> <application-semver> <CHANGELOG.md>" >&2
  exit 1
fi

tag=$1
semver=$2
changelog=$3
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid release tag: expected vMAJOR.MINOR.PATCH with optional prerelease/build metadata." >&2
  exit 1
fi
version=${tag#v}
version=${version%%+*}
if [[ "${version%%-*}" != "$semver" ]]; then
  echo "Release tag $tag does not match application version $semver." >&2
  exit 1
fi
if [[ ! -f "$changelog" ]]; then
  echo "Missing changelog: $changelog." >&2
  exit 3
fi

awk -v version="$version" '
  { sub(/\r$/, "") }
  /^## / {
    active = 0
    prefix = "## [" version "]"
    if (substr($0, 1, length(prefix)) == prefix) {
      suffix = substr($0, length(prefix) + 1)
      if (suffix !~ /^ - [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) {
        invalid = 1
      }
      count++
      active = 1
    }
  }
  active {
    notes = notes $0 "\n"
    if ($0 ~ /^[[:space:]]*[-*] [^[:space:]]/) changes++
  }
  END {
    if (count != 1 || invalid) {
      print "Expected exactly one heading: ## [" version "] - YYYY-MM-DD." > "/dev/stderr"
      exit 1
    }
    if (!changes) {
      print "Changelog entry for " version " must contain at least one change bullet." > "/dev/stderr"
      exit 1
    }
    printf "%s", notes
  }
' "$changelog"
