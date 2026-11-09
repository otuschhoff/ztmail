# Build, test and release

[README](../README.md) | [Advanced usage](advanced-usage.md) | [Diagnostics](diagnostics.md) | [Implementation](implementation.md) | [Go library](library.md) | [Build and release](build.md)

## Local builds

Requires Go 1.26 or later; the module selects toolchain Go 1.26.9.
Local Make targets also require Git, GNU Make and a POSIX shell. The private
AD SDK requires GitHub read access; configure Git credentials before fetching
dependencies. For example, with the GitHub CLI on Linux/macOS:

```sh
gh auth login
gh auth setup-git
export GOPRIVATE='github.com/otuschhoff/*'
go mod download
```

Authenticate with an account/token authorized to read the private dependencies;
do not embed credentials in source or build commands. On Windows, set
`GOPRIVATE` in your shell environment and use a POSIX Make environment or a
Go CLI build with the linker metadata described below. There is no local-path
module replacement.

`make build` produces all six combinations of Linux, Windows, and macOS
(`darwin`) with `amd64` and `arm64`:

- `dist/ztmail-linux-amd64`
- `dist/ztmail-linux-arm64`
- `dist/ztmail-windows-amd64.exe`
- `dist/ztmail-windows-arm64.exe`
- `dist/ztmail-darwin-amd64`
- `dist/ztmail-darwin-arm64`

To build just one target with the same CGO-free and version metadata settings:

```sh
make build-one TARGET_OS=linux TARGET_ARCH=amd64
make test
./dist/ztmail-linux-amd64 --version
# 0.3.1+20261101-110716.abcdef0
```

The semantic version is **0.3.1**. Every supported build includes UTC build time
and exactly seven characters of the checked-out commit SHA as SemVer build
metadata: `0.3.1+YYYYMMDD-hhmmss.<commitSha>`. A multi-target build uses one
timestamp/SHA for every binary. `BUILD_TIME` and `COMMIT_SHA` can be supplied to
Make for controlled rebuilds; otherwise they come from the UTC clock and Git HEAD.
The executable now lives in `cmd/ztmail`; `go build ./cmd/ztmail` builds the CLI,
while the repository root is an importable library. Raw CLI builds without
linker metadata have no trustworthy build timestamp:
`--version` reports an explicit error rather than inventing one. Use the
Makefile or inject `-X main.buildTime=... -X main.commitSHA=...` yourself.

## Validation

`make test` runs release-note extraction tests, `go test -race ./...`, and `go vet ./...`.

For Windows-specific compile/vet checks from a non-Windows host:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...
```

Documentation-only edits do not require compiling or running mail tests.

Tests cover argument validation, message privacy, Resent handling, domain
parsing, ordered principal probing, source configuration, canonical mail lookup,
sender rewriting and overrides, SDK GSSAPI delegation, and a local SMTP protocol
exchange. Default-sender management and Linux fallback tests use isolated
configuration directories and fake sendmail executables, never the host MTA.
Cryptographic and native credential operations belong to the SDK.
Tests do not replace an end-to-end check against your AD KDC, protected LDAP
service, and GSSAPI-enabled SMTP gateway.
Windows SSPI must also be exercised on a domain-joined Windows machine.

## GitHub Actions

The build workflow runs on main pushes, `v*` tags, pull requests, and manual
dispatch. Its official checkout, Go setup, and artifact actions use the Node.js
24 runtime rather than deprecated Node.js 20. Node.js 24 requires Actions Runner
2.327.1 or later; all jobs use GitHub-hosted `ubuntu-26.04` runners, pinning the
OS release to avoid automatic `ubuntu-latest` migrations. Runner images still
receive regular security and tool updates.
It shares one timestamp/SHA across its six-target matrix, sets
`CGO_ENABLED=0`, checks build metadata, runs Linux regression tests, and uploads
each binary as a separately named Actions artifact. macOS binaries are
cross-compiled, not signed or notarized; cross-compilation does not imply native
runtime testing on every target.

Version-tag pushes automatically publish a GitHub Release after all six builds
succeed, attaching the binaries and `SHA256SUMS`. The release is created as a
draft and published only after asset uploads succeed. Its release-page body is
the matching curated section of [CHANGELOG.md](../CHANGELOG.md), not GitHub-generated
PR notes. Reruns update both release notes and assets rather than failing on
duplicate releases; prerelease tags such as
`v0.2.0-rc.1` are marked as prereleases. Only the publication job receives
`contents: write`; build and pull-request jobs retain read-only permissions.

Before creating a new version tag:

1. Bump the semantic version and its tests/documentation.
2. Move the relevant `Unreleased` changes into a dated section such as
   `## [0.1.4] - 2026-11-01`, using headings like `Added`, `Changed`, and `Fixed`.
3. Include user-visible behavior changes, compatibility notes, and known
   limitations. Each entry must contain at least one change bullet.
4. Commit the changelog with the code, then tag that commit as `v0.1.4`.

CI validates the tag against the application version and extracts exactly one
matching changelog section before building a new release. Missing, duplicate,
undated, or empty entries fail explicitly. Prerelease tags use their complete
prerelease version in the heading (for example `[0.1.4-rc.1]`); optional tag
build metadata does not affect the changelog heading. The section is taken from
the tagged source, never a later revision on `main`.

To rebuild and publish an existing tag without moving it, manually dispatch:

```sh
gh workflow run build.yml --repo otuschhoff/ztmail -f release_tag=v0.1.0
```

Metadata and binary builds check out that tag, so its commit SHA and source are
preserved. The release-note extraction script comes from the workflow revision.
For a manual rebuild of a historical tag that predates `CHANGELOG.md`, CI
explicitly retains the existing published release notes; an unpublished tag or
a release with empty notes cannot use this exception. New tag pushes always
require their own curated entry. Existing published releases are not modified
merely by adding the changelog on `main`.
An empty manual `release_tag` performs a build only. Main pushes and pull requests
never publish releases.

The private AD SDK requires an Actions secret named `ADBIND_READ_TOKEN` with
repository read access. Prefer a read-only token scoped to that dependency.
The default `GITHUB_TOKEN` cannot read another private repository.
Missing credentials fail explicitly; fork PRs normally have no access to the
secret and cannot run the dependency build. The workflow deliberately does not
use `pull_request_target` to expose credentials to untrusted fork code.
Tags use plain SemVer, starting with `v0.1.0`; timestamps belong in binaries,
not release tags. Download binaries from the repository's GitHub Releases page;
Actions artifacts are also retained for individual builds. On Linux/macOS,
mark a downloaded bare executable as executable with `chmod +x`.
