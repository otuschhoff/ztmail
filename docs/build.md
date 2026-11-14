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
# 0.3.2+20261101-110716.abcdef0
```

The source semantic version is **0.3.2**, prepared but not tagged or published.
The latest published release remains 0.3.1 until a separately authorized release.
Every supported build includes UTC build time
and exactly seven characters of the checked-out commit SHA as SemVer build
metadata: `0.3.2+YYYYMMDD-hhmmss.<commitSha>`. A multi-target build uses one
timestamp/SHA for every binary. `BUILD_TIME` and `COMMIT_SHA` can be supplied to
Make for controlled rebuilds; otherwise they come from the UTC clock and Git HEAD.
The executable now lives in `cmd/ztmail`; `go build ./cmd/ztmail` builds the CLI,
while the repository root is an importable library. Raw CLI builds without
linker metadata have no trustworthy build timestamp:
`--version` reports an explicit error rather than inventing one. Use the
Makefile or inject `-X main.buildTime=... -X main.commitSHA=...` yourself.

## Validation

`make test` first fails on tracked Go files needing formatting without changing
them, then runs release-note extraction tests, `go test -race -shuffle=on ./...`
(including ordinary fuzz seeds), and `go vet ./...`. The shuffle seed is printed
by the test runner; replay it with `make test TEST_SHUFFLE=<seed>`.
`make fmt-check` runs only the non-mutating formatting gate.

Run mutation campaigns separately from the ordinary CI suite:

```sh
GOMAXPROCS=2 make fuzz FUZZ_TIME=20s
```

This runs four targets serially, each for the specified duration with at most
two fuzz workers: message/body/privacy/ownership, mailbox round trips, domain
escaping, and JSON v2 table shapes. Preserve any failing corpus input as a
regression fixture; do not dismiss it as an expected parse error. The default
campaign duration is 15 seconds per target. Bounded campaigns are sampling,
not proof of exhaustive input safety or a production capacity measurement.

### Offline native smoke and live-pilot separation

The separate `Native smoke` workflow runs on actual `windows-latest` and
`macos-latest` hosts, with CGO disabled as in distribution builds. It checks
native host/suffix outcomes, isolated configuration save/replace/read,
platform-specific console outcomes, system-root availability, and the
unsupported system/append expiry-grace combination (replace roots remain
supported). It vets/links a native binary and checks its metadata version.
The Windows runner has a console even though workflow steps are noninteractive;
its job requires successful open/close and separately tests explicit failure in
an isolated detached child that calls `FreeConsole` and verifies the missing
console before the adapter check. macOS requires the observed absence of a
controlling terminal. Tests never read a password or mutate parent console/
terminal modes, host DNS or trust.
It requires the same private SDK read token as the build workflow.

To run the focused smoke tests on a native host:

```sh
go test -tags=native_smoke -shuffle=on -count=1 -timeout=3m -v \
  -run='^TestNativeSmoke' ./cmd/ztmail ./internal/mail
```

Set `ZTMAIL_NATIVE_CONSOLE=absent` for an explicitly headless run, or `present`
to require a controlling terminal/Windows console. Leave it unset to record
availability without imposing topology. Even `present` opens/closes only:
interactive echo restoration/cancellation and domain-joined Windows SSPI still
require a separately authorized manual pilot. Use disposable accounts/test
relays, test no-email authentication before an expressly approved submission,
review reports for private topology, and never include passwords in logs.

Linux execution and Windows/macOS cross-vet/link checks are not native platform
certification. At Phase 5 closeout the new remote native workflow is implemented
but **not executed**: the user approved recording it as pending and committing
locally without push. Its success must be recorded after authorized CI execution;
live AD/KDC/LDAP/SMTP pilots remain unperformed and separate from offline CI.

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

### Refactoring baseline and offline benchmarks

The [refactoring review](refactoring-review.md#phase-0-establish-a-reproducible-baseline-and-decisions)
records the Phase 0 scope, approved later-phase policies, regression inventory,
and acceptance gates. Phase 0 adds test/measurement fixtures, not production
corrections. Do not treat an open finding as fixed because its reproduction or
benchmark passes.

Capture evidence outside the checkout. For example, create an empty directory
for this run and supply its absolute path as `EVIDENCE_DIR`:

```sh
: "${EVIDENCE_DIR:?Set an existing absolute evidence directory outside the checkout}"
go version > "$EVIDENCE_DIR/toolchain.txt"
go env GOOS GOARCH CGO_ENABLED >> "$EVIDENCE_DIR/toolchain.txt"
go test -json -race -shuffle=1794593178716668121 -count=1 \
  -coverprofile="$EVIDENCE_DIR/coverage.out" ./... > "$EVIDENCE_DIR/tests.json"
go tool cover -func="$EVIDENCE_DIR/coverage.out" > "$EVIDENCE_DIR/functions.txt"
go vet ./...
git ls-files '*.go' | xargs gofmt -l
bash .github/scripts/release-notes-test.sh
```

Check each command's exit status before continuing. `gofmt -l` is non-mutating;
any output needs review. Retain JSON skip events and the shuffle seed. Inspect
the actual touched functions/branches, not only package coverage. The ordinary
suite runs offline synthetic protocol fixtures; its privileged real-CLI DNS
subtest can skip when isolated port 53 is unavailable. Native platform and live
AD checks remain separate.

Discover and exercise every offline benchmark variant once:

```sh
go test -list='^Benchmark' ./internal/mail
go test -run='^TestBenchmark' -count=1 ./internal/mail
go test -run='^$' -bench='.' -benchmem -benchtime=1x ./internal/mail
```

The benchmarks cover complete-message preparation and sender rewriting, folded
headers/recipients, immutable TLS material preparation, runtime aggregation,
domain formatting, and report/MIME assembly. They use synthetic messages,
certificates, and observations, not credentials, AD, DNS, or SMTP connections.
Their ordinary fixture tests check successful output and input isolation.
They are not throughput certification or regression tests for the known defects.

Run measurements serially, after builds, tests, and other benchmark work have
finished. A bounded baseline capture on a shared machine can use:

```sh
GOMAXPROCS=1 go test -run='^$' -bench='.' -benchmem -count=10 \
  -benchtime=200ms ./internal/mail > "$EVIDENCE_DIR/benchmarks.txt"
```

Record CPU/VM identity, toolchain, commit, `GOMAXPROCS`, fixture sizes, and
measurement flags with the raw output. Shared-host noise limits interpretation.
For an optimization decision, rerun the affected targets on the same otherwise
idle host/toolchain for at least `-benchtime=1s -count=10` and compare distributions
with `benchstat`; the bounded capture alone does not establish materiality.
Do not compare race-enabled results to normal binaries or count fixture setup
as operation cost. `B/op` measures allocation, not retained heap or peak RSS.

Profiles can be collected for a selected target without leaving a test binary
in the checkout:

```sh
go test -run='^$' -bench='<target>' -benchtime=1s \
  -cpuprofile="$EVIDENCE_DIR/cpu.pprof" \
  -memprofile="$EVIDENCE_DIR/heap.pprof" \
  -o "$EVIDENCE_DIR/mail.test" ./internal/mail
go tool pprof -top "$EVIDENCE_DIR/cpu.pprof"
go tool pprof -top -alloc_space "$EVIDENCE_DIR/heap.pprof"
go tool pprof -top -inuse_space "$EVIDENCE_DIR/heap.pprof"
```

Only use profiles of the relevant operation as evidence. Keep raw profiles and
coverage local; do not upload private build/source information to new services.
Measure network latency, contention, concurrent retained memory, and native
TLS separately before claiming operational bounds.

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
   Confirm build/native CI for the selected commit and remove prepared/unpublished
   status text only when publication is authorized.
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

## Rollback without message replay

Rollback changes the deployed binary or consumer dependency, not message
acceptance. Do not resubmit a message with confirmed acceptance, an
accepted-but-status-output-failed error, or `ErrDeliveryUncertain` simply because
the deployment is being rolled back. Resolve uncertainty operationally with the
relay; neither version can make blind replay safe.

The immutable published fallback is `v0.3.1`, reviewed source
`1d08ad5c438fd940d9344fb7b061939523c2f773`. Prefer the published target-specific
binary and its checksums, or build that tag in a separate checkout using its
Makefile. Do not reset a shared worktree, rewrite the tag, replace published
assets, remove user configuration, or copy credentials into source.

For example, on Linux amd64, set `ROLLBACK_DIR` to an existing empty absolute
directory outside the checkout:

```sh
set -eu
: "${ROLLBACK_DIR:?Set an existing empty absolute rollback directory}"
gh release download v0.3.1 --repo otuschhoff/ztmail \
  --pattern ztmail-linux-amd64 --pattern SHA256SUMS --dir "$ROLLBACK_DIR"
(cd "$ROLLBACK_DIR" && sha256sum --check --ignore-missing SHA256SUMS)
chmod +x "$ROLLBACK_DIR/ztmail-linux-amd64"
"$ROLLBACK_DIR/ztmail-linux-amd64" --version
```

Stop on a download/checksum/version failure. `--ignore-missing` applies only
because the checksum file lists all six binaries but this example downloads
one. Choose the correct OS/architecture and its checksum tooling on other
platforms. Stage the verified binary, drain admitted operations and their owned
cleanup, then switch the deployment using the application's normal procedure.
For library consumers, pin `github.com/otuschhoff/ztmail@v0.3.1` in the consumer
module and rebuild/test it; do not alter this repository's dependency manifests.

Rollback restores the earlier behavior and **reintroduces the corrected
mailbox/header, cancellation/output and diagnostic defects**. It is not an
equivalent safety profile. Public API, JSON v2 and saved-sender paths were
preserved by the refactoring; no storage migration or configuration deletion is
required. Record the exact binary/dependency SHA, configuration and reason for
rollback, without recording secrets. Offline tests do not authorize a live
AD/SMTP submission or certify the production environment.
