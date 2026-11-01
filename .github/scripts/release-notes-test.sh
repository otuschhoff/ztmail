#!/usr/bin/env bash
set -euo pipefail

script=.github/scripts/release-notes.sh
input=$(mktemp)
output=$(mktemp)
errors=$(mktemp)
trap 'rm -f -- "$input" "$output" "$errors"' EXIT

expect_failure() {
  local tag=$1 semver=$2 message=$3
  if bash "$script" "$tag" "$semver" "$input" > "$output" 2> "$errors"; then
    echo "Expected failure for $tag: $message" >&2
    exit 1
  fi
  grep -Fq -- "$message" "$errors"
  test ! -s "$output"
}

cat > "$input" <<'EOF'
# Changelog
## [Unreleased]
### Added
- Do not publish this.
## [1.2.3] - 2026-11-01
### Fixed
- Preserve this exact release note.
## [1.2.2] - 2026-10-01
- Do not publish the previous version.
EOF
bash "$script" v1.2.3 1.2.3 "$input" > "$output"
expected=$'## [1.2.3] - 2026-11-01\n### Fixed\n- Preserve this exact release note.'
test "$(cat "$output")" = "$expected"
expect_failure v1.2.4 1.2.4 "Expected exactly one heading"
expect_failure v1.2.3 1.2.4 "does not match application version"
expect_failure not-a-tag 1.2.3 "Invalid release tag"

printf '%s\r\n' '## [1.2.3-rc.1] - 2026-11-01' '### Added' '- Prerelease note.' > "$input"
bash "$script" v1.2.3-rc.1+build.7 1.2.3 "$input" > "$output"
test "$(cat "$output")" = $'## [1.2.3-rc.1] - 2026-11-01\n### Added\n- Prerelease note.'

printf '%s\n' '## [1.2.3] - 2026-11-01' '### Fixed' > "$input"
expect_failure v1.2.3 1.2.3 "at least one change bullet"

printf '%s\n' '## [1.2.3]' '- Missing date.' > "$input"
expect_failure v1.2.3 1.2.3 "Expected exactly one heading"

printf '%s\n' '## [1.2.3] - 2026-11-01' '- First.' '## [1.2.3] - 2026-11-01' '- Duplicate.' > "$input"
expect_failure v1.2.3 1.2.3 "Expected exactly one heading"

if bash "$script" v1.2.3 1.2.3 "$input.missing" > "$output" 2> "$errors"; then
  echo "Missing changelog unexpectedly accepted." >&2
  exit 1
else
  test "$?" -eq 3
fi
grep -Fq "Missing changelog" "$errors"
test ! -s "$output"

echo "Release-note extraction tests passed."
