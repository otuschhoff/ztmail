# Refactoring review and execution plan

**Review date:** 2026-11-13

**Baseline:** `1d08ad5c438fd940d9344fb7b061939523c2f773`, ztmail 0.3.1,
AD SDK 0.8.3, Go 1.26.9

**Method revision:** second review using `samber/cc-skills-golang`; production
baseline unchanged

**Disposition:** the original review changed no application code. Phases 0-4
are now complete; execution records below describe their approved
changes and verification. Remaining phases are not authorized by completion.

The executive assessment and finding evidence describe the review baseline,
not an assertion that already resolved defects remain in current code.

## Executive assessment

The codebase is small, substantially tested, and has sound ownership and
delivery-safety foundations. It does not need a rewrite. The strongest areas are
explicit AD ownership, shared CLI/library transport, defensive certificate
configuration, no automatic SMTP replay, and precise distinction between
authentication, DATA acceptance, and mailbox delivery.

The main maintenance risk is behavioral complexity concentrated in CLI
orchestration and diagnostic generation. High statement coverage does not fully
cover those boundaries. Several specific correctness gaps should be fixed
before structural or performance refactoring:

1. Envelope addresses are decoded by the standard parser but are not consistently
   serialized back into valid SMTP mailbox syntax.
2. Header field-name validation is weaker than the stated RFC 5322 contract.
3. Socket closure on cancellation can lose context-error identity.
4. EXTERNAL authentication time and changing DC address inventories can be
   misreported.
5. Arbitrary report writers are called under the report-state mutex, allowing
   a callback into report state to deadlock, not just slow rendering.
6. A typed-nil certificate signer can panic during construction, and a malformed
   PEM entry can be skipped when a later certificate block is valid.

Resource concerns are real in structure, but their production significance has
not been measured: complete-message copies, repeated folded-header concatenation,
quadratic runtime aggregation, repeated TLS preparation, and report rendering
under a mutex. Benchmark and profile the performance work before changing
behavior or adding caches/concurrency. Writer reentry and retained-input
ownership are correctness work and must not wait for a performance threshold.

**Recommended strategy:** small, independently testable changes; correctness
first, orchestration tests second, measurement third, selective optimization
last. Preserve the existing public API and operational contracts unless an
explicit decision below authorizes otherwise.

## Scope, method, and evidence

The review covers all 34 tracked production Go files, the associated test
inventory, the Makefile, release-note scripts, GitHub build/release workflow,
and current user/developer documentation. Detailed independent reviews covered
the public library/transport/TLS/message path and the diagnostics/rendering path;
CLI configuration, credentials, input, storage, fallback, and CI were reviewed
directly. Third-party SDK internals were not audited.

For the plugin-guided second pass, those implementation paths and their
relevant tests were read again, not merely relabeled with skill names. Two
bounded independent reviews covered transport/library and reporting; the CLI,
OS adapters, test isolation, build gates, and execution plan were reassessed
directly. The plugin's coverage-adaptive safety net and staged-refactoring
workflow informed the task gates below. This is a quality/refactoring review,
not a comprehensive vulnerability or dependency audit.

The repository contains 5,675 production Go lines and 9,141 test Go lines across
43 test files. These are physical line counts, not complexity or quality scores.
Existing unrelated local changes to the ignore file and editor configuration
were excluded and left unchanged. Generated binaries and local credential/key
material were not inspected.

### Validation performed

| Check | Result / interpretation |
| --- | --- |
| `go test -race -shuffle=on -count=2 -coverprofile=<temporary-file> ./...` | Passed in the second review; no races detected in executed tests |
| Public library statement coverage | 93.2% |
| CLI statement coverage | 70.0% |
| Internal mail statement coverage | 92.6% |
| Combined statement coverage | 85.1%, weighted by statements, not the mean of package percentages |
| `go vet ./...` | Passed |
| `gofmt -l` on tracked Go files | No output |
| Release-note extraction tests | Passed |
| Windows amd64 CGO-free build and vet | Passed; cross-validation, not native execution |
| Darwin arm64 CGO-free build and vet | Passed; cross-validation, not native execution |
| Focused CLI credential/password/fallback/version/storage tests, repeated three times | Passed in the first review; not repeated as that exact selector in the second review |
| Focused shuffled CLI flag/report/input/SIGINT tests | Passed in the second review; recorded shuffle seed `1794593178716668121` |
| Full JSON test run | First-review evidence: 571 passing test/subtest events and three skipped events; not 571 independent top-level tests |
| Benchmarks and fuzz targets | No `Benchmark...` or `Fuzz...` functions found |
| New targeted probes | Typed-nil signer panic, skipped malformed PEM, retained inventory alias, and both writer-reentry deadlocks reproduced; temporary probes removed |

Coverage, vet, formatting, release-note tests, and the two cross-platform
build/vet checks were refreshed in the second review and agree with the first
baseline. The focused mTLS end-to-end test was also rerun: the library/protocol
cases passed, including concurrent calls, while its real-CLI subtest skipped
again because isolated loopback DNS port 53 was unavailable.

The writer-reentry probes intentionally timed out separate test processes at
two seconds; their stacks showed `Write` calling `Value` blocked on the already
held report mutex. Those expected reproduction failures are not failures of
the existing baseline suite. The typed-nil probe captured the panic explicitly,
and the mixed PEM probe observed one accepted certificate with no error.
These probes establish the mechanisms, not production incident frequency.
Temporary test files and working directories were deleted after execution;
only this review document is a lasting task change.

The skipped real-CLI mTLS subtest is significant:
[the fixture](../mtls_test.go#L213) only runs on Linux and skips when binding
`127.0.0.2:53` is denied. It skipped in this environment. The two subprocess
helper tests skip intentionally outside their child processes and are not
missing coverage by themselves.

Coverage measures executed statements, not protocol correctness, race freedom
under arbitrary schedules, branch coverage, native platform behavior, throughput,
or peak memory. No live AD/LDAP/SMTP pilot, production load profile, or native
Windows/macOS execution was performed. Passing tests are not evidence that the
performance hypotheses below are already operational problems.

Neither `gopls`, `golangci-lint`, nor `staticcheck` was installed in this
environment. The editor reference query also returned no Go reference provider.
Source reads/searches, the compiler, vet, and tests supplied the evidence;
there is no claim of semantic call-hierarchy or additional linter analysis.
No new tools or dependencies were installed for this documentation-only task.
Before a rename or extraction, obtain semantic references for the actual
target/build tags, or stop and explicitly review a compiler-backed reference
inventory rather than treating a text search as equivalent.

### How the Go skills affected the review

| Loaded skills | Applied review criteria | Result in this plan |
| --- | --- | --- |
| `golang-how-to`, `golang-refactoring`, `golang-gopls` | Map callers and public contracts; gate transforms on touched-path coverage; separate structure from behavior | Coverage tiers, per-task inventory, approval and stop gates |
| `golang-code-style`, `golang-naming`, `golang-structs-interfaces` | Readable control flow, consistent vocabulary, consumer-owned seams, copy safety | Small CLI stages and per-command dependencies, not package proliferation |
| `golang-error-handling`, `golang-safety` | Preserve `errors.Is`/`As`; retain independent failures; do not hide output errors or mutable aliasing | R01-R04, R06, R10; outcome-aware error assertions |
| `golang-concurrency`, `golang-context` | Goroutine ownership and exit/join paths, cancellation propagation, lock scope, deliberate cleanup detachment | R03/R10/R14 and lifecycle acceptance matrix |
| `golang-testing` | Behavioral assertions, test isolation, characterization before extraction, fuzz invariants and deterministic synchronization | R08 and explicit red/green versus characterization workflow |
| `golang-cli`, `golang-spf13-cobra` | Fresh command per test, `RunE`, injected writers, validation before effects, signal/exit compatibility | Preserve existing good Cobra structure; R04/R07/R08 |
| `golang-benchmark`, `golang-performance` | Profile first; repeated controlled comparisons; distinguish allocations from retained memory | R09/R11-R13 and serial measurement protocol |
| `golang-documentation`, `golang-lint`, `golang-continuous-integration` | Accurate API/examples, actionable repository-owned gates, honest native-test evidence | R04/R14/R15; incremental gates without replacing release tooling |

Generic plugin recommendations are not automatic requirements for this
repository. In particular:

- Keep the existing Cobra flag-only design; do not add Viper, a DI framework,
  structured-logging dependencies, containers, or GoReleaser merely to match a
  template.
- Keep useful existing names and package layout. Mandatory boolean prefixes,
  blanket acronym lowercasing, receiver renaming, and file-size rules are not
  reasons for an API break or a style-only rewrite.
- Nil reports are deliberately supported; nil versus empty slices can affect
  JSON. Do not normalize all nil values or add serialization tags to public
  structs without an established wire contract.
- A borrowed signer need not be copied, but must be immutable/concurrency-safe.
  Keep that documented ownership condition rather than promising impossible
  deep copies of arbitrary signers.
- Detached, bounded cleanup is intentional. Do not replace every background
  context or create abandon-on-timeout goroutines to satisfy a generic rule.
- Use `testing/synctest` only for suitable in-memory time/concurrency tests.
  Real sockets, subprocesses, console reads, and OS signal delivery still need
  explicit fixtures and watchdogs.
- Keep offline protocol fixtures in the ordinary safety net; a loopback socket
  alone does not make a test a live-service integration test.
- Do not upload private source, coverage, profiles, or credentials to a new
  external service as part of quality-gate adoption.

### Changes from the first review

- R01-R03 and R05-R14 remain evidence-backed findings/trade-offs, with their
  scope qualifications retained.
- R10 is now a correctness-first item: executable writer callbacks reproduced
  self-deadlocks in both verbose events and nonverbose final output.
- R06 now explicitly separates historical-address loss from demonstrated
  retained-input aliasing; snapshot aliasing under a held lock is not
  mislabeled as an existing race.
- New R16/R17 capture reproduced typed-nil construction and mixed malformed
  PEM behavior. New R15 makes the missing quality gates actionable without
  claiming hypothetical linter findings.
- R04 adds the GSSAPI-only ownership-comment correction; R13 distinguishes
  repeated material validation from per-operation root-pool construction.
- The execution plan now distinguishes characterization from defect tests,
  gates extraction on actual touched-path coverage, separates S/B/M changes,
  and specifies controlled serial benchmark comparisons.

## Current architecture and quality

| Area | State | Main maintenance concern |
| --- | --- | --- |
| [Public library](../ztmail.go) | Validated options, immutable configuration intent, borrowed AD owner, operation-local results | Warning/timeout contracts need alignment with actual behavior; message preparation crosses several transformations |
| [CLI](../cmd/ztmail/) | Good early checks for many flag conflicts; explicit password opt-in and source policy | One options struct combines flags, derived configuration, secrets/material, and execution/report state |
| [Credential selection](../cmd/ztmail/kerberos.go) | Explicit candidate/source attempts, failure retention, cleanup before fallback | Nested error construction and operation orchestration are harder to test than the selection helpers |
| [Message handling](../internal/mail/message.go) | Strong Bcc stripping, Resent handling, body preservation, sender rewriting tests | Mailbox serialization and field-name validation gaps; whole-message buffering/copying |
| [SMTP transport](../internal/mail/smtp.go) | Explicit TLS/authentication/acceptance states and no DATA replay | Context identity, sequential connection latency, and a large stateful delivery function |
| [TLS implementation](../internal/mail/tls_policy.go) | Strong copying, chain selection, scoped exceptions, and evidence | Repeated preparation deserves measurement; native verifier limitations must remain explicit |
| [Diagnostics](../internal/mail/diagnostics.go) | Shared tables and conservative evidence; error-aware output | Mutable report collection, string-based operation classification, and rendering under locks |
| [Build/release](../.github/workflows/build.yml) | Six cross-build targets, metadata checks, curated release notes, publication after uploads | Linux-only runtime tests; no performance/fuzz evidence or automated formatting gate |

### Style, type design, and documentation assessment

Formatting is clean, ordinary Go names and concrete configuration/result types
are generally clear, and there is no reason to split the three-package layout.
The existing [command constructor](../cmd/ztmail/main.go#L71) uses `RunE`,
silences duplicate framework errors, and allocates fresh flag state.
[Tests](../cmd/ztmail/main_test.go#L29) normally construct a fresh command.
The [terminal interface](../cmd/ztmail/password.go#L17) is a useful existing
consumer seam; keep its concrete OS implementations rather than inventing a
general application service container.

The most valuable readability work is separating raw options from operation
state (R07) and making long policy predicates readable without changing their
truth tables. For example,
[fallback eligibility](../cmd/ztmail/local_sendmail.go#L21) encodes important
delivery-safety exclusions; do not simplify it to a short broad retry check.
Table-driven tests must pin every exclusion before any helper extraction.
Compatibility aliases in [the CLI adapter](../cmd/ztmail/shared.go) and
type-erased formatting at an actual display boundary are not, by themselves,
design defects.

The README, library guide, implementation notes, and compiled examples provide
substantial onboarding. The warning and timeout wording still need the precise
corrections in R04/R14; the library guide already describes the borrowed signer
and multiple warning kinds more accurately than some API comments.
There is no tracked license or standalone contributor guide. License selection
is an owner/legal decision, not something an LLM should infer from the plugin's
license; clarify intended reuse terms if distribution requires it. A short
contributor section in the existing build guide is preferable to duplicating
documentation solely to satisfy a template.

### Foundations to preserve

- CLI-owned versus library-borrowed AD lifetime, independent per-call credential
  leases, and owner-managed SDK DNS/KDC/LDAP routing.
- Liberal IPv4-first host resolution from the SDK. Do not reinstate strict
  dual-family failure or introduce an application resolver bypass.
- Complete canonical LDAP lookup, bounded candidate racing, negative-result
  election, naming-context confinement, and loser cleanup.
- No plaintext/mechanism/native fallback from certificate modes; no automatic
  password retries; no fallback after uncertain DATA or failed cleanup.
- Caller input immutability, blind-header removal, null-envelope semantics, and
  configured sender versus canonical own-recipient distinctions.
- Strict default TLS verification and explicit reporting of configured and used
  exceptions. Do not simplify custom verification into a global bypass.
- Confirmed DATA acceptance remains accepted after QUIT/cleanup warnings.
  Generated testmail remains a pre-DATA snapshot and cannot prove its own delivery.
- JSON schema v2, stable table IDs, escaping/styling isolation, UTC validity
  boundaries, and conservative unavailable/not-applicable evidence.

### Ownership and cancellation checklist for execution

| Resource/work | Current ownership and limitation | Verification before changing it |
| --- | --- | --- |
| Application AD owner | Borrowed by library; owned/closed by CLI attempts | Library closes no caller owner; every failed CLI attempt closes exactly once |
| GSSAPI lease/context | Operation-local borrowing and protocol context | Release/close counts on success, setup errors, AUTH errors, and cancellation; mTLS acquires neither |
| LDAP race view | Lookup-local children, bounded detached cleanup | All winners/losers close; independent cleanup allowance is reported, not treated as an unlimited leak |
| SMTP connection | Operation-owned; canceled work closes transport | Canceled greeting/TLS/AUTH/envelope/DATA; no surviving loser connections or replay |
| Message-read goroutine | Private one-shot CLI isolation, buffered result; arbitrary reader may outlive cancellation | Caller returns; owned test pipes close and workers terminate; do not expose this as reusable generic cancellable I/O |
| Terminal/password input | Synchronous OS adapter; context checked around reads | Characterize actual signal/terminal behavior; do not claim `ctx.Err` interrupts a blocked read |
| TLS signer | Borrowed immutable/concurrency-safe implementation | Reject typed nil; valid custom signers remain supported; blocking signer methods are outside generic cancellation guarantees |
| Report state/output | Synchronized state; arbitrary synchronous writer | Independently owned retained inputs/snapshots; no writer call under the state mutex; preserve output error identity and ordering |

## Findings

Priorities denote remediation order, not vulnerability severity.
**P1** means correctness/contract work before refactoring; **P2** means important
maintenance or operational work; **P3** means conditional optimization.
Confidence applies to the observed mechanism, not to unmeasured impact.

| ID | Priority | Classification | Finding |
| --- | --- | --- | --- |
| R01 | P1 | Resolved in Phase 1 | Quoted mailbox local-parts lose required envelope quoting |
| R02 | P1 | Resolved in Phase 1 | Invalid header field names pass local preparation |
| R03 | P1 | Resolved in Phase 1 | SMTP cancellation can lose context sentinel identity |
| R04 | P2 | Resolved in Phase 2 | Warning/output handling differs across CLI, library, and fallback |
| R05 | P2 | Resolved in Phase 2 | EXTERNAL auth duration is categorized as handshake time |
| R06 | P2 | Resolved in Phase 2 | DC inventory updates replace historical address evidence |
| R07 | P2 | Confirmed maintainability/UX issue | CLI orchestration mixes state and performs some configuration checks after input |
| R08 | P2 | Measured testing gap | Real orchestration and native paths are less covered than helper contracts |
| R09 | P2 | Resource-design concern; performance unmeasured | Message buffering, copying, and folded-header accumulation |
| R10 | P1 | Reentry resolved in Phase 2; measured optimization remains open | Arbitrary report output under the state mutex can self-deadlock |
| R11 | P2 | Confirmed algorithmic cost; impact unmeasured | Quadratic runtime aggregation and repeated formatting work |
| R12 | P2 | Connection-policy trade-off | Sequential address dialing delays later reachable addresses |
| R13 | P3 | Optimization hypothesis | Immutable TLS material is prepared repeatedly |
| R14 | P2 | Resolved in Phase 2 | Complete-call timeout wording exceeds enforceable guarantees |
| R15 | P2 | Confirmed quality-gate gap | Local review checks and test-isolation expectations are not enforced in CI |
| R16 | P1 | Resolved in Phase 1 | A typed-nil certificate signer can panic instead of returning an error |
| R17 | P2 | Resolved in Phase 1 | Strict CA-bundle loading can silently skip a malformed PEM block |

### R01. Envelope mailbox canonicalization

**Evidence:** [EnvelopeAddress](../internal/mail/message.go#L23) returns
`net/mail.Address.Address`, a decoded mailbox.
[Header recipient extraction](../internal/mail/message.go#L165) does the same.
[SMTP envelope commands](../internal/mail/smtp.go#L294) consume these strings.

For example, `"a b"@example.com` parses into `a b@example.com`. Explicit
recipients can reach an invalid `RCPT TO:<a b@example.com>` command; header
recipients can instead fail reparsing. An explicit sender may fail a later
rewrite after credential acquisition. These are inconsistent treatment of the
same valid mailbox syntax.

**Remediation:** centralize the supported envelope representation. Decide
whether to support quoted local-parts correctly or reject them explicitly at
initial validation. Do not strip quotes and assume the decoded value is
wire-ready. Do not use display-name serialization as an SMTP envelope.

**Acceptance:** table tests for spaces, escaped quotes, consecutive dots, simple
quoted local-parts, normal addresses, and null senders across argument/header
recipients and senders. Accepted cases produce exact valid envelope commands.
Rejected cases acquire zero credentials and open zero SMTP connections.
Existing From/Sender preservation and rewriting tests remain unchanged.

### R02. Header field-name validation

**Evidence:** [header scanning](../internal/mail/message.go#L111) verifies a
colon and nonempty name but not RFC 5322 `ftext`.
[Subsequent parsing](../internal/mail/message.go#L126) delegates to the
deliberately permissive standard mail parser. `Bad Header: value` and
`Bcc : value` can therefore pass the local validation layer; the latter does
not match the exact blind-header classification.

**Impact:** malformed headers are accepted despite the advertised RFC contract.
Differing downstream interpretation of noncanonical blind headers is a risk,
not a demonstrated disclosure in this review.

**Remediation:** validate each field name as ASCII bytes 33-57 or 59-126 before
classifying/copying it. Reject whitespace/control-character variants rather
than inventing normalization rules.

**Acceptance:** spaces, tabs, controls, non-ASCII names, empty names, and
whitespace before `:` fail locally before AD/SMTP work. Valid mixed-case
Bcc/Resent-Bcc and continuations remain completely removed. Preserve opaque body
bytes and existing latest-Resent-block behavior.

### R03. Cancellation identity at SMTP I/O boundaries

**Evidence:** [connection cancellation](../internal/mail/smtp.go#L155) closes
the socket. Subsequent errors, including
[EXTERNAL authentication failure](../internal/mail/smtp.go#L266), wrap the
resulting I/O error without consistently retaining `ctx.Err()`.
[Existing cancellation coverage](../internal/mail/smtp_mtls_lifecycle_test.go#L50)
checks interruption/evidence, not context identity.

**Remediation:** preserve the original socket/protocol cause and the applicable
context cause on failed operations terminated by cancellation/deadline.
Do not turn acknowledged acceptance into an error or classify every protocol
rejection as cancellation merely because cancellation happens later.

**Acceptance:** deterministic canceled/expired tests at greeting, AUTH, RCPT,
and DATA boundaries assert `errors.Is`. DATA uncertainty remains detectable
alongside cancellation when acceptance is unconfirmed; known acceptance remains
true with only subsequent warnings. Fallback eligibility tests must stay green.
Include canceled implicit TLS and STARTTLS fixtures, but do not assume that
every `HandshakeContext` error loses the sentinel; assert the actual boundary
behavior and retain the original TLS cause.

### R04. Warning and output semantics

**Evidence:** normal CLI cleanup/status output in
[the GSSAPI path](../cmd/ztmail/main.go#L365),
[submission status](../cmd/ztmail/main.go#L414), and
[certificate cleanup](../cmd/ztmail/mtls.go#L139) ignores writer errors.
[Native fallback](../cmd/ztmail/local_sendmail.go#L128) checks them and gives
post-submission output failure a no-retry classification.
[Result documentation](../ztmail.go#L110) and
[the compiled example](../example_test.go#L28) describe warnings too narrowly
as cleanup events, although TLS policy and certificate-only authorization
warnings can exist before acceptance and in tests/failed operations.
The [Mailer comment](../ztmail.go#L115) also says every call acquires a
lease/GSSAPI context, although certificate modes explicitly bypass them.

**Remediation:** first define and test a common outcome policy: operational
failure, confirmed acceptance with warnings, and successful submission with
failed status output. Then use a small shared CLI output helper rather than
silently dropping output errors. Update API comments/examples to distinguish
policy/authentication warnings from post-acceptance cleanup warnings, and
qualify lease/context ownership as applying to GSSAPI operations.

**Acceptance:** injected writers fail before and after acceptance in GSSAPI,
certificate, diagnostic, and native paths. Required pre-submission notifications
must not fail silently. Post-acceptance output failure never enables retry or
native fallback. Library warnings must not be interpreted as acceptance proof.
Do not add a general logging framework.

### R05. EXTERNAL authentication runtime attribution

**Evidence:** [runtime category matching](../internal/mail/debug_report.go#L280)
recognizes GSSAPI authentication specially, but other SMTP-prefixed operations
become handshake work. The transport records
[SMTP EXTERNAL authentication](../internal/mail/smtp.go#L265).

**Remediation:** explicitly classify both authentication operations. Keep
classification narrow rather than using a broad substring such as `auth`.

**Acceptance:** fixed-duration fixtures attribute GSSAPI and EXTERNAL solely to
SMTP auth, with empty and SMTP protocol labels. Terminal, plain, HTML, and JSON
representations agree. TLS-only mode must not invent an SMTP AUTH interval.

### R06. DC inventory address-history retention

**Evidence:** [inventory updates](../internal/mail/debug_report.go#L83) replace
same-endpoint entries when the new entry contains addresses.
[IP-based observation matching](../internal/mail/debug_report.go#L196) then
uses only the retained list. Sequential address A/B updates can lose previously
observed IP-only replies or distort their average.
For replies A=10 ms and B=30 ms, processing inventories A then B can report
one reply averaging 30 ms rather than two averaging 20 ms; reversing inventory
order can retain only A.

[Inventory ingestion](../internal/mail/debug_report.go#L45) also retains the
event shallowly. Endpoint/address slices therefore alias producer input.
Mutating an input slice can change later evidence without the report mutex;
this proves an ownership gap, not that current SDK producers actually perform
such mutations. It is separate from address-history replacement.

**Remediation:** merge/deduplicate independently owned address histories. Define
how current/retired metadata is selected; do not blindly let processing order
decide. Keep evidence history separate from claims about current availability.
Copy retained endpoint/address collections at ingestion, not only when rendering
a snapshot; a state mutex cannot protect external aliases.

**Acceptance:** sequential and reversed A/B inventory events, including
current/retired groups, produce one endpoint row containing both qualifying
replies and their correct average. Input slices remain unchanged. Canceled and
connection-only activity remains excluded from completed-response rows.
After ingestion, caller mutation must not alter retained results. Exercise
concurrent ingestion/rendering under the race detector, with independently
owned inputs rather than unsynchronized mutation of an input still in use.

### R07. CLI orchestration and validation ordering

**Evidence:** [options](../cmd/ztmail/main.go#L18) combines raw flags, derived
values, report state, credential material, and mode decisions.
[run](../cmd/ztmail/main.go#L227) handles configuration, input, credentials,
recipient policy, cleanup, delivery, and fallback in approximately 200 lines.
[Certificate submission](../cmd/ztmail/mtls.go#L103) duplicates parts of the
delivery lifecycle. Numeric DNS-server validation occurs in
[AD configuration](../cmd/ztmail/kerberos.go#L124), after normal message input.

A local probe using `--dns-server not-an-IP` and malformed message input produced
the message-structure error first, confirming this validation ordering without
contacting a gateway.

**Remediation:** extract a few cohesive stages: pure flag/config validation,
resolved target configuration, prepared message/envelope, and authenticated
submission. Keep execution-only fields separate from the flag configuration.
Move numeric DNS syntax checks ahead of stdin while reusing the same parser.
Do not move message reading before local fallback recipient handling or alter
the documented timeout exclusions.

**Acceptance:** invalid DNS syntax causes zero stdin reads, terminal prompts,
AD acquisitions, and network attempts. Existing explicit-default mTLS conflict
tests, saved sender precedence, no-input management modes, and fallback behavior
remain intact. Helpers should reduce duplication, not become a configurable
pipeline or introduce many tiny interfaces.

### R08. Coverage at orchestration and platform boundaries

**Evidence:** measured CLI coverage is 70.0%, compared with 93.2% and 92.6% in
the library and internal mail package. Key CLI function coverage:

| Function | Coverage |
| --- | --- |
| `run` | 51.7% |
| `openADAttempt` | 38.6% |
| `runCertificateSubmission` | 32.1% |
| `openADPassword` | 0.0% |
| `lookupDefaultSender` | 0.0% |
| Unix `platformDomain` and real terminal adapters | 0.0% |

Selection helpers and fake password reads are strongly covered, but they do
not exercise the complete real assembly. The
[CI test step](../.github/workflows/build.yml#L116) executes tests only on Linux
amd64; the other five targets are cross-builds.

**Remediation:** introduce narrow, per-command dependencies only at OS/AD/terminal
boundaries needed for deterministic orchestration tests. Avoid adding more
package-global mutable function hooks. Reuse existing protocol/AD fixtures.
Add pure resolver-configuration parsing tests and opt-in native smoke tests.

**Acceptance:** successful and failing full password-stage assembly, default-AD
sender lookup, GSSAPI/certificate cleanup, and pre-input validation are covered.
Tests assert call order, zero forbidden side effects, and exact cleanup counts,
not only error text. Native Windows/macOS validation is reported independently
of cross-compilation. The privileged CLI DNS fixture must either run in an
appropriate isolated environment or remain an explicitly documented skip.

**Plugin-guided safety-net assessment:** the percentages above are statement
coverage within functions, not branch coverage. Treat `run` as medium coverage,
`openADAttempt` and `runCertificateSubmission` as low coverage, and the zero
paths as characterization-first. A 92.6% transport package does not make the
CLI extraction safe. Before editing, list the specific branches touched and
prove the new tests execute them.

The existing [report-factory override test](../cmd/ztmail/diagnostics_test.go#L212)
restores its package-global hook with `t.Cleanup`; the
[signal helper](../cmd/ztmail/input_linux_test.go#L50) overrides parsing only
inside a terminating subprocess. These are not observed leaks or races.
They do constrain safe parallelism: do not add `t.Parallel` to tests mutating
globals or process environment, nor to tests sharing their consumers.
Prefer per-command function fields only where new coverage needs a seam.
The shuffled race rerun is evidence of the executed schedules, not a proof
that adding parallelism would be safe.

### R09. Message resource use and parsing work

**Evidence:** [input buffering](../internal/mail/message.go#L64),
[body copying](../internal/mail/message.go#L100), and
[sender rewriting](../internal/mail/message.go#L231) create complete-message
intermediates even when the library already owns input as `[]byte`.
[Folded-header accumulation](../internal/mail/message.go#L109) repeatedly
concatenates strings, giving quadratic copying as one folded value grows.
The reviewed paths do not enforce total-message, header, or recipient-count
limits before buffering/collection; callers or external infrastructure may
provide their own bounds.

**Impact:** large concurrent messages multiply memory pressure. Actual peak RSS
and CPU costs have not been measured; line counts and allocation sites are not
performance profiles.

**Remediation:** benchmark byte-slice and reader paths before changing them.
Consider an internal byte-slice preparation path, builder-based continuation
accumulation, and one final pass for privacy stripping plus sender rewrite.
Establish explicit message/header/recipient resource policies before claiming
bounded memory. Limits and their defaults are a product compatibility decision.

**Acceptance:** benchmark 1 KiB, 1 MiB, and 10 MiB messages; doubled folded-header
lengths; recipient lists; and multiple concurrent library calls. Record `ns/op`,
`B/op`, `allocs/op`, plus peak memory for concurrent runs. Preserve exact body
bytes, input immutability, and identical envelope/privacy semantics.
Any new limit fails explicitly before credentials and is documented/tested at
limit-minus-one, exactly-limit, and limit-plus-one.

### R10. Report snapshot ownership and locking

**Evidence:** [TestMessage](../internal/mail/testmail.go#L28) holds the report
mutex until it returns. Its [snapshot](../internal/mail/testmail.go#L52) aliases
mutable collections; that snapshot is currently protected against report-method
mutations by the held lock, so it is not itself a demonstrated race. Unlocking
prematurely without independent ownership would introduce one.
JSON, rendered bodies, multipart alternatives, and the final message use
[overlapping buffers](../internal/mail/testmail.go#L58).
Verbose [event output](../internal/mail/diagnostics.go#L70) and
[final output](../internal/mail/diagnostics.go#L234) also execute writer calls
under the report mutex. A blocking writer can stall observer callbacks.

There is also an unconditional reentry problem:
[Value](../internal/mail/debug_report.go#L20) acquires the same nonrecursive
mutex. If a supplied writer's `Write` records a `Value`, the call chain is
`Line` (verbose) or `Finish` (even nonverbose) -> lock -> `Write` -> `Value` ->
lock again. The callback cannot return to unlock the outer call, and context
cancellation cannot break the mutex cycle. This is a correctness defect,
independent of message size or measured contention.

Completed traces and inventory are retained without explicit collection caps
in [debug collection](../internal/mail/debug_report.go#L35); issue collections
are also uncapped. This is not evidence of a leak: normal CLI SDK trace/inventory
registration is debug-gated, reports are generally one-shot, and exchanges are
counted rather than retained as event objects. Large or unusually long
diagnostic invocations still need measurement and an explicit retention policy
before claiming bounded memory.

**Remediation:** first separate state synchronization from arbitrary output:
never call the supplied writer under the report-state mutex. Preserve output
ordering and retained writer errors. A separate output mutex alone does not
solve callbacks that recursively produce more output; define that reentry
contract explicitly instead of adding another undocumented lock cycle.
Then, as a separate measured optimization, capture an independently owned
snapshot under the state lock, render outside it, and reuse derived tables.
Do not replace the mutex with an asynchronous queue that loses events or
silently drops writer failures.

**Acceptance:** concurrent event recording and snapshot generation passes race
tests and preserves coherent pre-DATA snapshots. Original data cannot mutate a
captured snapshot. Decoded MIME bodies, JSON tables, and escaping remain
equivalent. A slow renderer must not unnecessarily serialize unrelated observer
updates after snapshot capture.
Callback-writer tests record `Value` from verbose `Line` and nonverbose `Finish`
and must complete under a bounded test-process timeout. Writer failures still
match via `errors.Is`, and output remains ordered. Keep deliberate-deadlock
reproductions in a timed subprocess rather than leaking an abandoned test
goroutine into the suite.

### R11. Diagnostic aggregation and formatting complexity

**Evidence:** [runtime aggregation](../internal/mail/debug_report.go#L301)
builds approximately two boundaries per span and scans all spans between
boundaries: O(N squared). Testmail computes overlapping table work for multiple
representations. [Domain formatting](../internal/mail/report_table.go#L349)
compiles a regular expression repeatedly, including technical-value fragments.

**Remediation:** benchmark first. If material, use sorted start/end events with
active category counts, retaining precedence and overlap accounting. Compile
domain formatting once per render context, not in an unbounded global cache.
Build shared snapshot tables once and adapt them to each output format.

**Acceptance:** 1,000/2,000/4,000-span benchmarks establish scaling and allocation.
An event-sweep implementation should approach O(N log N); a proposed target is
less than 3x runtime when doubling N, measured repeatedly rather than enforced
as a noisy CI wall-clock assertion. Nested/overlapping category totals, threshold
filtering, prompt exclusion, zero-duration observations, and HTML/text/JSON
selection remain equivalent.

These are primarily diagnostic/testmail costs; normal-send throughput impact
has not been established.

### R12. Sequential relay-address dialing

**Evidence:** [relay dialing](../internal/mail/smtp.go#L390) tries addresses
serially and gives each a share of the remaining deadline. Two candidates with
a 60-second remaining budget can let the first stalled address use roughly
30 seconds before the second is tried. This is a mechanism-based estimate,
not a measured production incident.

**Remediation:** first add a stalled-first/reachable-second fixture and measure
latency. Decide whether a per-attempt cap is sufficient or whether a bounded,
staggered connection race is justified. Preserve SDK-approved numeric endpoints.

**Acceptance:** an agreed latency target is met under the fixture, total deadline
is honored, concurrency is bounded, and every losing connection closes.
Failover stays strictly before authentication and DATA. No connection-racing
change may introduce SMTP replay or extra authenticated submissions.

### R13. Repeated TLS preparation

**Evidence:** [library construction](../ztmail.go#L214) prepares authentication;
[delivery configuration](../internal/mail/config.go#L43) prepares it again.
Certificate copying/parsing and [custom-root preparation](../internal/mail/tls_policy.go#L129)
repeat work for individual operations.
Distinguish DER/selector cloning and validation from root-pool assembly:
[TLS delivery setup](../internal/mail/tls_auth.go#L77) constructs server roots
during an operation, not during `New`. The review does not claim that
construction itself builds a reusable root pool.

**Remediation:** only if benchmark profiles show material cost, retain immutable
prepared material in the constructed mailer. Keep operation-local TLS configs,
callbacks, hostname/actual-time verification, and authentication evidence.
Do not cache acceptance, exceptions, certificate validity, or mutable signers.

**Acceptance:** repeated mTLS operation benchmarks demonstrate meaningful CPU or
allocation improvement. Existing configuration-copy isolation, alternate-chain,
expiration, and concurrent-call race tests remain unchanged.

### R14. Timeout and blocking-I/O contracts

**Evidence:** [Options.Timeout](../ztmail.go#L79) promises a complete-call bound.
[LDAP racing cleanup](../internal/mail/ad.go#L96) uses a separate,
cancellation-detached five-second allowance. Message preparation is synchronous,
and report output goes to an arbitrary writer.
An arbitrary borrowed signer's `Sign` implementation can also block; closing
the transport cannot interrupt arbitrary code executing inside that method.
[CLI input isolation](../cmd/ztmail/input.go#L23) intentionally returns on
cancellation without being able to stop arbitrary reader work.

**Remediation:** state the actual network/operation deadline, separate cleanup
allowance, synchronous CPU work, and arbitrary-reader/writer limitations.
Do not claim general cancellation of blocking Go interfaces. Keep CLI input
isolation private; repeated canceled calls with uninterruptible readers are not
a suitable reusable library service primitive.

**Acceptance:** delayed-cleanup fixtures demonstrate the documented allowance;
writer/input cancellation behavior is specified. If strict total latency is
required, agree on a context-aware I/O/ownership contract before implementing
it. Do not detach or abandon owned AD/racing sessions to make a timeout test pass.

The [CLI timeout help](../cmd/ztmail/main.go#L160) already correctly excludes
message/credential input and distinguishes per-stage password mode.
[Password reading](../cmd/ztmail/password.go#L147) calls a synchronous terminal
method; checking the context before/after it cannot interrupt that call.
The normal [SIGINT context](../cmd/ztmail/main.go#L48) and message-reader
isolation are separate mechanisms. Document and characterize principal/password
input and DATA/cleanup interruption before changing signal handling. SIGTERM
and distinct exit codes are policy decisions, not currently promised behavior.

### R15. Reproducible quality gates and maintainer workflow

**Evidence:** [make test](../Makefile) runs race tests, vet, and release-note
tests; [CI](../.github/workflows/build.yml#L116) reuses that target. Neither
enforces formatting, shuffled order, coverage reporting, or module tidiness.
There is no tracked repository-owned linter configuration. The
[build guide](build.md#L54) documents today's checks correctly, but not a
targeted-refactor safety net or benchmark comparison protocol.

**Impact:** the clean review baseline can drift without CI noticing formatting
or test-order dependence. This is an enforcement gap, not evidence that the
current code is misformatted, dependencies are untidy, or a missing linter
would necessarily find bugs.

**Remediation:** add a non-mutating formatting gate and reproducible shuffled
tests first. Emit local coverage/function reports where maintainers can inspect
them; do not gate on a blanket package percentage. If module-tidiness checks are
adopted, run them in an isolated clean checkout with the pinned toolchain and
private-dependency access, and fail on a changed manifest rather than silently
committing generated updates. Consider a pinned, minimal `golangci-lint` or
`staticcheck` baseline only after choosing actionable checks and measuring the
existing warning set. Keep current release machinery.

**Acceptance:** intentionally misformatted code fails the formatting gate
without modifying files; a captured shuffle seed can reproduce a failing run;
offline protocol tests remain ordinary CI tests; new linter suppressions are
specific and justified. Update the existing build guide with commands, native
versus cross-build limits, and the new maintainer workflow. Do not introduce
coverage-upload services or choose licensing terms without approval.

### R16. Typed-nil certificate signer safety

**Evidence:** [certificate preparation](../internal/mail/tls_credentials.go#L54)
checks whether `PrivateKey == nil` and whether it satisfies `crypto.Signer`.
A typed-nil `*ecdsa.PrivateKey` satisfies that interface and is not an empty
interface. Calling [signer.Public](../internal/mail/tls_credentials.go#L73)
then dereferences nil. [Public construction](../ztmail.go#L214) reaches this
preparation path, so invalid caller configuration can panic instead of returning
an error.

**Remediation:** reject nil underlying signer values before invoking their
methods, with a clear configuration error. Keep support for valid custom
signers and the documented borrowed-key contract. Do not recover arbitrary
panics to hide implementation defects, and do not hardcode support only for
two standard-library key types.

**Acceptance:** valid certificate DER paired with typed-nil RSA, ECDSA, and
custom pointer signers returns an error without panic or network I/O.
Valid custom signers, mismatched-key rejection, configuration-copy isolation,
and concurrent certificate operations remain supported.

### R17. Strict CA-bundle PEM parsing

**Evidence:** [CA-bundle decoding](../internal/mail/tls_credentials.go#L142)
checks the starting marker, then calls `pem.Decode`. That decoder can search
onward for a decodable block. A malformed certificate block followed by a valid
certificate can therefore be skipped rather than rejected, contrary to the
loader's explicit malformed-PEM policy. Existing invalid-input tests cover
standalone failures, not malformed blocks preceding valid ones.

**Remediation:** validate each successive PEM block without silently skipping
non-whitespace input or an undecodable block. Reuse the standard DER/x509 checks;
do not implement certificate parsing or relax trust policy.

**Acceptance:** invalid-base64 first/valid second, valid/malformed/valid,
unmatched end markers, unexpected block types, and malformed trailing material
fail explicitly. Whitespace-separated valid CA bundles continue to work.
Failures occur during local configuration, before credentials or SMTP work.

## Phased remediation plan for an LLM

Each task below is a bounded change, normally one commit. Run it against current
source, not blindly against the line numbers in this review. Do not implement
all phases as one large patch.

### Execution rules and approval gates

This document authorizes no production refactoring. Before starting a selected
task, present a short inventory containing the exact symbols/files/callers,
public contract impact, risk, verification commands, and whether each change
is **S** (structure-preserving), **B** (behavioral correction/policy), or
**M** (measurement/tests/docs/tooling, no production behavior change).
Obtain sign-off on that scope. Package
moves, exported API changes, deletion, new dependencies, resource defaults,
output/exit policies, and untested native paths require an explicit decision.
Do not manufacture a license or remove exported code based only on in-module
reachability.

One task/patch carries one change category. A bug fix and a helper extraction
are separate steps even when touching the same function. Correctness-first
means fixing a demonstrated defect before optional broad refactoring, not
using a bug fix as permission for an untested structural rewrite. A tiny seam
needed to reproduce a defect must be justified as part of its test harness.

| Coverage of actual touched functions/lines | Safety net before a structural change |
| --- | --- |
| High, roughly at least 80% | Read uncovered branches and contract assertions; semantic rename/extract where available; focused build/vet/tests after each step |
| Medium, roughly 40-80% | Add targeted tests first; confirm green on unchanged behavior and that coverage reaches the intended paths; then transform |
| Low, below 40%, or touched lines unexecuted | Characterize current behavior and side effects first using the smallest consumer-owned seam; no substantial extraction/package move until the net exists |

These are review tiers, not CI acceptance percentages. Contract assertions,
cleanup counts, and branch-specific fixtures take precedence over the number.
For a correctness fix, add a regression that fails for the known defect, then
fix it and return to green in that same bounded task. Do not commit a failing
baseline as if it were a completed safety-net phase. For a structural refactor,
characterization tests must pass on the old implementation before it changes.

Record dependencies per task, not just phase number. Shared files impose
serialization even on logically independent tasks; a tree-wide rename runs
alone. Independent, file-disjoint tasks may use separate worktrees only after
ownership and dependencies are agreed. Stop if current code invalidates a
finding, a compatibility decision is missing, or checks cannot reach the
claimed behavior; update the finding instead of forcing the planned patch.

### Phase 0: establish a reproducible baseline and decisions

**Dependencies:** none. **No production behavior changes.**

1. Re-run race tests, vet, formatting, and release-note tests; capture package
   coverage and explicit skips outside the repository.
2. Inventory regression cases for R01/R02/R03/R05/R06/R10/R16/R17 and the current
   orchestration characterization gaps. Reproduce defects locally; their
   failing tests belong with the corresponding correction task, not in a
   permanently red baseline commit.
3. Confirm the product decisions: quoted local-part support versus early
   rejection; message/header/recipient limits; output failure after acceptance;
   dial-latency target; timeout/cleanup guarantees.
4. Add benchmark fixtures for messages, folded headers, TLS preparation,
   runtime spans, domain formatting, and report assembly. Use synthetic
   fixtures without real credentials or network dependencies.

**Exit gate:** baseline reproducible; failures correspond to specific findings;
choices are recorded in related documentation/tests. Performance tasks remain
pending until measurements justify them.

#### Phase 0 execution record

**Scope authorized:** tests, synthetic benchmarks, and the existing review/build
documentation only. No production behavior, API, dependency, version, release,
or CI changes. The input baseline is review commit `293a326`; application source
remains the reviewed `1d08ad5` baseline. The user requested Phase 0 execution and
a detailed commit, not implementation of all open findings.

**Approved policy decisions (2026-11-13):**

| Decision | Approved later-phase contract | Verification needed when implemented |
| --- | --- | --- |
| Quoted mailboxes | Support valid quoted SMTP local-parts consistently; do not silently decode into invalid wire syntax | Exact `MAIL FROM`/`RCPT TO` for quoted spaces, escaped quotes, ordinary quoted text and dot cases, across explicit/header/canonical/saved sender paths; null-envelope semantics unchanged |
| Message/header/recipient bounds | Preserve existing unrestricted behavior; document caller-side size/concurrency/admission bounds | No new implicit default cap or rejection; fixtures include representative large messages, folded headers and recipient lists |
| Required output before acceptance | Return writer failures explicitly; do not proceed when a required notification fails | Inject failures before credentials/submission; assert no forbidden downstream effects |
| Status output after confirmed acceptance | Preserve known acceptance and return a detectable no-retry output error; never replay or fall back | Acceptance remains distinguishable from uncertain DATA; retain writer cause via `errors.Is`; exact CLI exit/report behavior covered across GSSAPI, mTLS, testmail and native fallback |
| Relay connection latency | In the deterministic stalled-first/reachable-second fixture, start the second attempt within one second, subject to the total deadline | Use a controlled admitted-address/dial fixture; choose the smallest sufficient cap or staggered policy in Phase 5; bound concurrency and close every loser before AUTH/DATA |
| Deadline and cleanup | Keep operation/network deadlines and the separate bounded five-second cleanup allowance; exclude arbitrary blocking reader/writer/signer code | Assert applicable context identities and owned cleanup counts; document the allowance and exclusions rather than promising strict complete-call wall-clock latency |

These decisions authorize later behavior corrections only within their selected
task. They do not introduce a new public error type, schema version, SIGTERM
policy, SMTP retry, or implementation-level dial algorithm during Phase 0.
The one-second dialing target refers to starting an attempt in the fixture,
not completing TLS/authentication or guaranteeing real-network delivery time.
Do not label a known accepted message as having uncertain DATA solely because
its status writer failed; preserve both outcome and no-retry classification.

**Regression inventory:** the correction task must first reproduce its defect
with a failing behavioral assertion, then fix it and return to green. Phase 0
retains an inventory and successful fixture tests, not a permanently failing
suite or tests that enshrine bugs as correct.

| Finding / target | Regression input and observed gap | Desired assertion / later task |
| --- | --- | --- |
| R01, shared mailbox preparation | `"a b"@example.test` decodes into an unquoted local-part; explicit/header recipient and later sender reparse differ | Supported mailbox produces valid exact envelope syntax at every surface; invalid syntax rejects before AD/SMTP (P1-A) |
| R02, header classification | `Bad Header: value`, `Bcc : hidden@example.test`, tabs/control/non-ASCII names | Reject invalid `ftext` before blind-header classification; valid mixed-case/folded Bcc and latest Resent behavior preserved (P1-B) |
| R03, transport errors | Cancellation closes a live socket; greeting/AUTH/envelope/DATA errors can wrap I/O without the context sentinel | Canceled/expired greeting, implicit TLS, STARTTLS, GSSAPI/EXTERNAL, RCPT and DATA assert `errors.Is`; DATA uncertainty and acknowledged acceptance stay independent (P1-C) |
| R05, runtime category | Exact operation `"SMTP EXTERNAL authentication"` with empty or SMTP protocol | Attribute only to SMTP auth, not handshake; TLS-only must create no AUTH interval; all output representations agree (P2-A) |
| R06, retained inventory | Same endpoint receives address A then B (and reversed); IP-only successful replies A=10 ms, B=30 ms; caller later mutates input | Both replies count, average is 20 ms, retained evidence owns its inputs; current/retired metadata policy is explicit; failed/canceled/connection-only observations excluded (P2-B) |
| R10, writer reentry | Writer `Write` calls `report.Value`; verbose `Line` or nonverbose `Finish` holds the same report mutex | Timed subprocess completes without deadlock; ordering and writer error identity remain; no dropped observer updates (P2-D) |
| R16, constructor | Valid certificate DER with typed-nil ECDSA/RSA/custom pointer signer | Constructor returns configuration error, never panics; valid custom signers and borrowed-key isolation remain (P1-D) |
| R17, CA loader | Invalid-base64 certificate block followed by a valid PEM certificate; valid/malformed/valid and malformed suffix variants | Reject every malformed/skipped block during configuration; valid whitespace-separated bundles succeed (P1-E) |
| R04, outcome/output policy | Inject required pre-submission and post-acceptance writer failures in every submission mode | Preserve writer cause and known acceptance, prohibit replay/fallback, and align warning/API/example wording (P2-C/P2-E) |
| R07, DNS validation order | `--dns-server=not-an-IP` with malformed message stdin | Fail numeric DNS syntax with zero stdin reads/prompts/AD/network; intentional order change isolated from structural extraction (P3-C) |

The current CLI DNS-order probe used an isolated saved-sender directory,
explicit `--domain`, disabled native fallback, and malformed input. It observed
two stdin reads and a local message-structure error before DNS validation, with
no submission. Its temporary test file was removed. This establishes order,
not a current credential or network side effect.

**Orchestration characterization backlog (R08):**

| Boundary / baseline function coverage | Existing safety net to preserve | Additional characterization before Phase 3 extraction |
| --- | --- | --- |
| `run`, 51.7% | Flag conflicts, test-mode no-input behavior, saved sender precedence and SIGINT message input | Stage order and output failures on successful GSSAPI/mTLS/testmail and every failed stage; exactly one owner close; zero forbidden fallback/replay |
| `openADAttempt`, 38.6% | Credential/source/principal helper behavior and protected LDAP/transport fixtures | Owner creation/acquire/identity/ticket/mail failure order, exact lease release/owner close counts, cleanup failures retained |
| `runCertificateSubmission`, 32.1% | Sender/recipient rejection and explicit credential-flag conflicts; mTLS protocol/library cases | DNS-only owner lifetime and cleanup success/failure, no Kerberos/LDAP/native work, post-acceptance output policy |
| `openADPassword`, 0.0% | Fake terminal read/write/cancellation and source-fallback selection tests | Full source configuration -> terminal -> prompt -> close/clear -> timed AD acquisition assembly, explicit principal pinning and exactly one terminal close |
| `lookupDefaultSender`, 0.0% | Injected lookup management/storage tests and precedence | Real adapter assembly without live AD: bounded owner cleanup, host-no-mail rejection and no save on lookup/cleanup/output failure |
| Native host/console adapters | Cross-compilation; real-CLI message SIGINT fixture on Linux | Opt-in native Windows/macOS host/config/terminal checks; do not claim platform coverage from a cross-build |

Use per-command consumer seams only when a fixture needs them. Existing tests
restore the global report-factory override with `t.Cleanup`; the parser override
is subprocess-local. Do not parallelize environment/global-mutating tests or
introduce a global hook merely to avoid constructing a local dependency.
The additional characterization belongs to Phase 3's safety-net step, not
untested production extraction during Phase 0.

**Fresh defect reproduction results:** temporary, explicitly labeled probes
were executed against the unchanged production source and removed afterward.
They observed defects rather than asserting that these behaviors are correct.

- R01: the explicit quoted recipient produced `a b@example.test` without an
  error; the equivalent `To` header failed reparsing with `mail: no angle-addr`.
  Explicit and canonical sender rewrite paths failed with
  `sender rewrite requires a single bare mailbox`.
- R02: `Bad Name`, `Bcc ` and `Bcc` followed by a tab were accepted and copied,
  including their continuation, when explicit recipients were supplied.
- R03: cancellation after a loopback connection opened but before its greeting
  returned `SMTP greeting: ... use of closed network connection`.
  `ctx.Err()` was `context.Canceled` and the error matched `net.ErrClosed`,
  but neither context sentinel matched; zero security contexts were created.
  The later regression must use the original socket error and context identity,
  not a fabricated successful result.
- R05: a 100 ms `"SMTP EXTERNAL authentication"` interval in a 200 ms snapshot
  was counted as 100 ms handshake plus 100 ms other, not authentication.
- R06: A/B inventory updates followed by 10/30 ms IP replies retained one reply
  averaging 30 ms. Mutating the producer's retained address slice also removed
  a previously matching 10 ms observation.
- R10: verbose `Line` and nonverbose `Finish` with a writer callback to `Value`
  each independently hit a two-second test-process watchdog. Stacks showed
  `Value` waiting on the outer call's already held state mutex. Both subprocesses
  terminated; no blocked probe goroutine remains in the ordinary suite.
- R16: a typed-nil RSA signer passed interface/nil checks and panicked in
  `Public`, reached from `cloneClientCertificate`. The probe explicitly
  recovered the panic to record it; no production recovery was added.
- R17: a `CERTIFICATE` PEM block containing `not-base64!`, followed by a valid
  synthetic CA, returned one accepted root and no error.

**Persistent offline benchmark fixtures:**

| Files / benchmark family | Dimensions | Ordinary fixture verification |
| --- | --- | --- |
| [Message fixtures](../internal/mail/message_bench_test.go): `PrepareMessage`, `PrepareLocalMessage`, `ApplySender` | Each: 1 KiB/1 MiB/10 MiB complete messages; 1/2/4/8/16 KiB folded continuation payload; 1/10/100/1000 recipient dimensions (36 variants total) | Body preservation, blind-header stripping, recipients/deduplication, sender rewriting, immutable inputs; valid bounded-length body lines |
| [TLS fixtures](../internal/mail/tls_credentials_bench_test.go): `PrepareAuthentication`, `ServerRoots` | Chain dimensions 0/1/2/4/8 crossed with bundle dimensions 0/1/8/32/128 (25); replacement pools 1/8/32/128 (4) | Deterministic synthetic Ed25519 keys/certificates, issuer signatures and distinct roots, selectors, input copy isolation |
| [Runtime fixtures](../internal/mail/debug_report_bench_test.go): `RuntimeBreakdown` | 1000/2000/4000 spans with nested/overlapping categories, varying timeline lengths and untracked gaps (3) | Category precedence, accounted totals and prompt/untracked separation on synthetic timestamps |
| [Formatting fixtures](../internal/mail/report_table_bench_test.go): `FormatDomain`, `ReportTableRender` | Plain, terminal-color, HTML crossed with 10/100/1000 fragments (18) | Shortening/render output, literal values and appropriate escaping/format behavior |
| [Report fixtures](../internal/mail/testmail_bench_test.go): `TestMessage` | Small/medium/debug-rich: 10/100/1000 warning observations; rich case includes 1000 spans and one DC (3) | MIME structure, independently readable JSON schema v2, coherent pre-DATA snapshot and output content |

All 89 variants use `b.Loop`, exclude fixture generation from timed work, check
errors/output shapes, and report allocation. Message benchmarks report byte
throughput. Sender rewrite uses pre-cleaned input rather than implicitly
measuring a second preparation pass. Recipient dimensions also contain a
deduplicated explicit argument and two blind recipients. Folded labels describe
continuation payload, not total header bytes. Plain domain formatting is an
identity path, not evidence that colored/HTML formatting has negligible cost.

TLS fixtures deliberately use replacement roots to avoid native/system-store
variability. They measure DER validation/cloning and root-pool preparation, not
PEM loading, TLS handshakes, or AD operations. Synthetic key material must not
be used as real credentials. `TestMessage` itself still creates current-time
snapshots, random MIME boundaries/message IDs and preparation timings; fixture
tests check structural/coherent output rather than byte identity. Preparation
trace accumulation is reset outside timing so repeated iterations do not
silently increase the measured workload.

**Baseline and verification evidence (2026-11-13):**

- Input baseline: `293a326`, Go 1.26.9, Linux amd64, QEMU Virtual CPU 2.5+,
  16 exposed virtual CPUs, Linux `6.12.113+deb13-amd64`. Measurements ran with
  `GOMAXPROCS=1`; this is a shared VM, not an isolated performance laboratory.
- Initial JSON race/coverage run used shuffle seed `1794593178716668121` and
  `-count=1`; 571 passing test/subtest events and three intentional/environment
  skips. Coverage: library 93.2%, CLI 70.0%, internal mail 92.6%, weighted
  combined 85.1%.
- Fixture validation (`-run='^TestBenchmark' -count=1`) passed 60 test/subtest
  events. Every benchmark variant passed a `-benchtime=1x` smoke run.
- After both implementation/probe tasks finished, all 89 variants were measured
  serially with `-run='^$' -bench='.' -benchmem -count=10 -benchtime=200ms`.
  All 890 samples completed; the variant inventory exactly matched the smoke
  run. No benchmark, profile, build, or race suite was run concurrently with
  this capture by this task.
- Final JSON race suite repeated the fixed seed twice (`-count=2`), passed
  1262 test/subtest events, and retained the same coverage. The two intentional
  subprocess helpers and privileged CLI DNS subtest each skipped once per
  repetition. There were no failed test events or observed races.
- Vet, native build, non-mutating formatting, release-note tests, Windows amd64
  and Darwin arm64 CGO-free build/vet passed. Cross-builds are not native tests.
  No live AD/KDC/LDAP/SMTP pilot was performed.
- Raw JSON, coverage/function reports, fixture validation and 890 benchmark
  samples were captured outside the checkout in the session evidence directory.
  Reproduction files were removed; no generated test binary, profile, or
  credential material is included in the commit.

Representative medians below are **baseline observations, not improvement
claims or CI thresholds**. Times are rounded; allocation can vary with
production-generated report metadata. See the
[build guide](build.md#refactoring-baseline-and-offline-benchmarks) for commands
to recapture every variant and for longer controlled comparison/profile runs.

| Target | Median time | Median B/op | Median allocs/op |
| --- | --- | --- | --- |
| Reader message, 1 KiB | 14.4 us | 15,712 | 117 |
| Reader message, 1 MiB | 1.99 ms | 4,261,068 | 13,910 |
| Reader message, 10 MiB | 27.4 ms | 55,089,418 | 138,088 |
| Reader folded payload, 4 KiB | 83.6 us | 221,320 | 324 |
| Reader folded payload, 8 KiB | 217 us | about 714,889 | 520 |
| Reader folded payload, 16 KiB | 635 us | 2,552,464 | 909 |
| Runtime, 1000 spans | 15.3 ms | 289,338 | 461 |
| Runtime, 2000 spans | 58.6 ms | 715,146 | 865 |
| Runtime, 4000 spans | 230 ms | 1,509,488 | 1671 |
| TLS preparation, chain=2/bundle=8 | 73.0 us | 34,632 | 366 |
| Replacement root pool, 32 CAs | 264 us | 102,848 | 1145 |
| Small report, 10 observations | 1.34 ms | about 495,556 | 3746 |
| Medium report, 100 observations | 7.88 ms | 3,489,444 | 25,661 |
| Rich report, 1000 observations/spans | 213 ms | 73,229,676 | 550,541 |

Runtime span doubling took about 3.83x and 3.92x in this bounded capture,
consistent with R11's structural quadratic concern. Folded-header allocations
also grow superlinearly. This prioritizes later controlled profiling, not an
optimization in Phase 0 or certification of normal-send throughput/peak memory.
There is no before/after candidate or `benchstat` significance claim, and no
tool/dependency installation was needed. Performance tasks remain pending
until representative materiality and functional-equivalence gates are met.

**Phase 0 completion re-evaluation:**

| Exit criterion | Evidence / disposition |
| --- | --- |
| Reproducible current baseline and explicit skips | Fixed-seed before/after JSON, function coverage, build/vet/format/release checks; outside-checkout evidence |
| Regression inventory and local reproductions | R01/R02/R03/R05/R06/R10/R16/R17 reproduced; R04/R07/R08 boundary cases and characterization backlog recorded; temporary probes removed |
| Product decisions confirmed | Quoted-mailbox support, unrestricted resource behavior, outcome-aware output errors, fixture dial target, and deadline/cleanup policy explicitly approved |
| All requested synthetic benchmark families present | Five fixture files, nine families, 89 variants; ordinary fixture assertions plus complete smoke and ten-sample serial capture |
| No premature production fixes or optimizations | No production source/API/dependency/CI/version changes; no red regression suite, silent policy assumptions, throughput claims or blanket linter additions |
| Persistent execution guidance | Approved decisions, inventory, dimensions, baseline results and recapture commands committed in existing documentation with the fixtures |

No Phase 0 exit criterion remains unresolved. At that phase's completion,
R01-R17 remained **open**, **pending
their selected correction**, or **pending measurement/accepted resource policy**
as described above; completing the baseline phase did not close those
production findings. In particular, R10/R16 were correctness-first later
tasks, not optional optimizations. The next task required a selected, independently
approved Phase 1 correction or Phase 2 diagnostic correction; do not infer
authorization to run the remaining phases from the Phase 0 commit.

### Phase 1: correct message and cancellation contracts

**Dependencies:** baseline and task-specific regressions. Only P1-A needs the
mailbox policy decision; P1-B and P1-C do not depend on that choice.

| Task | Findings | Allowed scope | Required verification |
| --- | --- | --- | --- |
| P1-A | R01 | Shared mailbox parsing/serialization and envelope tests | Exact SMTP command fixtures; no credentials/network for rejected input |
| P1-B | R02 | Header scanning/classification and message tests | Malformed-name rejection; Bcc/Resent/body preservation |
| P1-C | R03 | SMTP error boundaries and lifecycle tests | Context sentinels plus DATA uncertainty/known acceptance |
| P1-D | R16 | Certificate signer validation and constructor tests | Typed-nil errors; valid custom signers; zero network effects |
| P1-E | R17 | Strict local CA-bundle parser and loader tests | Malformed/valid mixed bundles rejected; valid bundles unchanged |

P1-A and P1-B touch shared parsing code: execute serially unless file ownership
is explicitly coordinated. P1-C can be independent. P1-D and P1-E share
certificate-loading code and run serially; neither needs the mailbox decision.

**Exit gate:** focused tests pass, then `go test -race ./...` and `go vet ./...`.
No sender, recipient, authentication, acceptance, or fallback changes outside
the explicitly tested corrections.

#### Phase 1 execution record (2026-11-13, completed)

**Starting commit:** `a5c3c09`; application 0.3.1, AD SDK 0.8.3 and Go 1.26.9
unchanged. The five-task inventory, including directly coupled canonical AD
mail, CLI/native/saved-sender and public-library surfaces, was explicitly
approved. No Phase 2 correction, exported signature, dependency, CI, version,
release or push change was made.

Each correction began with a failing regression against its original
implementation. The tests reproduced decoded quoted-mailbox output, accepted
invalid header names, lost SMTP context identity, a typed-nil signer panic and
malformed PEM blocks skipped before valid ones. Re-evaluation found two
additional coupled gaps: SDK 0.8.3 rejected quoted canonical AD mail entirely,
and EOF/timeout-shaped errors from local GSSAPI token callbacks could acquire
false cancellation identity. Both were corrected and covered before the final
phase check; they were not left as deferred findings.

| Exit criterion | Verified behavior and evidence |
| --- | --- |
| P1-A / R01, coherent mailbox representation | Shared bare-mailbox serialization preserves necessary local-part quoting/escaping and normalizes unnecessary quotes. Explicit/header recipients, sender rewrites, canonical/self-recipient fallback and saved/native paths agree. Exact library MAIL/RCPT commands cover spaces, quotes, backslashes, consecutive dots and quoted atoms; shared tests also cover edge dots, quoted `@`, IPv4 domain literals and existing UTF-8 local addresses. Null envelopes, aliases, input/body isolation and recipient deduplication retain existing tests. |
| Canonical AD coupling | Ordinary validation still uses SDK `directory.CanonicalMail`; an invalid-mail-only local extension handles supported quoted local-parts because SDK 0.8.3 cannot. Tests preserve primary/fallback selection, non-substitution of aliases, validation of all SMTP aliases and fallback values, complete/unique attributes, stored ASCII/length restrictions and untouched directory entries. SDK search/routing/ownership remain unchanged. |
| P1-B / R02, strict header names and privacy | Byte-oriented `ftext` validation precedes classification/copying in preparation and sender rewriting. Exhaustive non-CR/LF/colon byte tests distinguish allowed ASCII from controls/non-ASCII; separate cases cover empty names, embedded CR, whitespace before the colon and orphan continuations. Mixed-case/folded blind fields, quoted recipients in the latest Resent block and opaque bodies are preserved/stripped as intended. Public GSSAPI/mTLS/mTLS-EXTERNAL invalid-mailbox tests abort before acquisition or resolution; malformed CLI headers never invoke the fake native MTA. |
| P1-C / R03, stage-specific cancellation | Canceled/expired fixtures cover greeting, EHLO, implicit TLS, STARTTLS command/handshake/post-TLS EHLO, GSSAPI/EXTERNAL, MAIL/RCPT, DATA command/write/response and QUIT. Failed network boundaries retain original I/O causes plus applicable context identity. Deadline-timer lag is inferred only for a network timeout at an elapsed context deadline. Protocol/security/token errors remain independent of late cancellation, including EOF/timeout-shaped local token failures. Unconfirmed DATA remains uncertain; confirmed DATA remains successful with context-bearing QUIT warnings. |
| P1-D / R16, signer safety and ownership | Guarded reflection rejects underlying nil values before calling signer methods. Four signer shapes (RSA, ECDSA, Ed25519 slice, custom pointer) fail both preparation and public construction. Two valid-custom-signer cases and existing key-match/copy/concurrent certificate tests remain green. No panic recovery, type whitelist or key ownership change. |
| P1-E / R17, non-skipping PEM | Isolate each certificate entry and reject interior/nested markers before standard decoding. Eighty malformed-entry combinations cover prefix/interior/suffix placement, base64/DER failures, headers, mismatched/unmatched markers and trailing material; six valid LF/CRLF/whitespace/no-final-newline bundles succeed. Existing trust and file-permission/FIFO policies remain unchanged. |
| Integration, ownership and delivery safety | Combined focused corrections pass twice with race detection; the broader SMTP/GSSAPI/certificate lifecycle selector passes three repetitions after token-error re-evaluation. Full shuffled race/coverage suite passes twice, including existing acceptance/no-replay/fallback, lease/context cleanup, copy isolation, native fake-MTA and benchmark-fixture tests. |
| Build and documentation | Native build/vet/CLI link, CGO-free Windows amd64 and Darwin arm64 cross-build/vet/CLI links, Go formatting, diff whitespace and release-note extraction tests pass. Direct library/usage/implementation contracts and Unreleased changelog are updated. Cross-builds are not native Windows/macOS or live AD validation. |

The final full-suite command was:

```sh
go test -json -race -shuffle=1794593178716668121 -count=2 \
  -coverprofile="$EVIDENCE_DIR/coverage.out" ./... > "$EVIDENCE_DIR/tests.json"
go tool cover -func="$EVIDENCE_DIR/coverage.out" > "$EVIDENCE_DIR/functions.txt"
```

It recorded **2,428 passing test/subtest events**, zero failures and six skip
events (three distinct tests, each repeated twice): the intentional
`TestSMTPTestTLSHelper` and `TestSIGINTMessageHelper` subprocess helpers, and
`TestLibraryMTLSEndToEnd/cli` because isolated port 53 is unavailable.
Statement coverage is public library **93.2%**, CLI **70.0%**, internal mail
**93.4%**, weighted total **85.9%** (Phase 0: 85.1%). Function-level coverage and
the exact behavior matrix above were checked; aggregate coverage alone is not
the exit criterion. Raw JSON/coverage evidence is retained outside the checkout.

**Completion decision:** no Phase 1 exit criterion remains unresolved.
R01/R02/R03/R16/R17 are closed; R04-R15, including the correctness-first R10
writer reentry defect, retain their existing findings/policies and later-phase
gates. This phase makes no throughput, general blocking-callback cancellation,
live AD or native-platform certification claim.

### Phase 2: repair diagnostic fidelity and public wording

**Dependencies:** Phase 0 fixtures; independent of Phase 1 except shared tests.

1. P2-A: fix R05 with exact operation classification.
2. P2-B: fix R06 with address-history ownership and explicit metadata policy.
3. P2-C: align warning/timeout comments, compiled examples, and user docs
   (R04/R14). Keep the outcome policy explicit before changing CLI output errors.
4. P2-D: fix arbitrary-writer reentry under the report-state mutex (R10)
   independently of performance work; preserve output ordering and failure
   identity. This correctness task may precede Phase 1's unrelated parsing
   tasks and requires no benchmark threshold.
5. P2-E: implement the approved CLI output/outcome policy (R04) with injected
   pre-/post-acceptance writer failures. Keep it separate from P2-C's wording
   and Phase 3's structural consolidation.

**Exit gate:** terminal/plain/HTML/JSON tests agree; concurrent inventory tests
pass under race detection; no schema bump unless a deliberate schema change is
separately authorized.
P2-A/P2-B share diagnostic aggregation code and run serially. P2-D precedes
the snapshot-lock optimization P4-C; P2-B's input ownership also precedes that
optimization. P2-E requires the Phase 0 output-policy decision and P2-C's
matching contract wording.

#### Phase 2 execution record

**Approved scope:** P2-A through P2-E only. Writer callbacks may update report
state and enqueue finite recursive `Line` calls in synchronous FIFO order.
They must not finalize, flush or call the output barrier from inside `Write`.
No schema, dependency, timeout-budget, credential-selection, native-fallback
eligibility or later-phase orchestration/performance redesign was authorized.
The output policy intentionally changes previously swallowed failures into
explicit errors.

| Task | Implemented behavior and exact evidence |
| --- | --- |
| P2-A / R05 | Exact GSSAPI/EXTERNAL operation matching with empty/SMTP protocol labels; unrelated authentication-like names remain excluded. `TestRuntimeSMTPAuthenticationClassification` and `TestRuntimeSMTPAuthenticationRepresentations` cover terminal/plain/HTML/JSON and TLS-only absence. |
| P2-B / R06 | Ingestion copies advertised/current-candidate/retired endpoint collections and every nested address slice. Raw generation/health metadata is preserved. Aggregates use identity plus independently owned, deduplicated historical addresses, not arrival-selected health. `TestDCInventoryHistoryAcrossGroupsAndGenerationOrder` preserves A=10ms/B=30ms as two replies averaging 20ms in either order. Ownership, concurrent ingestion/rendering and immutable DNS unions have dedicated race regressions. |
| P2-C / R04/R14 | Public comments, compiled example and user/maintainer docs distinguish policy/authentication/cleanup warnings from acceptance and GSSAPI leases from DNS-only certificate ownership. Deadline wording excludes arbitrary blocking code and synchronous CPU work, describes awaited detached cleanup, and does not promise strict total-call latency. |
| P2-D / R10 correctness | State mutation/enqueueing occurs under the report mutex; one synchronous FIFO drainer writes outside it. The first writer/short-write error is sticky, subsequent writes stop, and independent operation errors survive. Timed subprocesses cover `Value` and finite recursive `Line` callbacks from verbose `Line` and concise `Finish`, plus a slow writer. Concurrent state/output ordering and the output barrier are race-tested. |
| P2-E / R04 | Shared tracked-output/check/join helpers enforce stage boundaries and retain distinct causes without repeating a shared writer failure. Known acceptance plus failed required output has an internal accepted/do-not-retry marker; output alone never creates uncertain DATA or permits replay/native fallback. Tests cover GSSAPI/mTLS/EXTERNAL, no-email test/testmail, configured/used TLS notices, QUIT/security/credential/DNS cleanup, direct short writers and native exit-zero/copy-error outcomes. |

**Re-evaluation and coupled corrections:**

- Confirmed both original writer deadlocks in bounded child processes before
  changing synchronization. No production output worker or abandoned goroutine
  was introduced. Render/testmail CPU work remains under the state mutex:
  P4-C snapshot optimization and retention/resource policy are still open.
  Final re-evaluation also reproduced reentry through writer/operation
  `error.Error` callbacks: wrapping/rendering those errors now happens outside
  the state mutex. Three additional timed subprocess cases retain error
  identity and prove callback state updates finish.
- Concise reports emit at finalization, not when initial checks are recorded.
  An initial hypothesis that a broken concise writer must prevent acquisition
  was rejected. No zero-byte probe writes or forced verbosity were added.
  Only a failure of actually emitted required output gates subsequent work.
  `TestLibraryConciseReportOutputFailurePreservesOutcome` retains both the
  already-performed operation failure and final writer failure in all modes.
- Followed the output policy through credential source/principal fallback,
  configuration, acquisition, tickets, LDAP and cleanup. New red/green
  credential fixtures prove failed setup output prevents acquisition, preserves
  independent source errors and stops further source/principal/password
  fallback. Direct skipped-identity warnings and every password prompt write
  detect short writes; a failed trailing newline clears the acquired password.
- Native `Wait` can return a stdout/stderr copy error despite process exit
  zero. That is known acceptance, unlike nonzero/unknown process outcomes.
  Regression tests assert DATA/native submission once, no replay/fallback,
  preserved genuine uncertainty, original writer causes and cleanup causes.
- Repeated checkpoints initially duplicated already-retained writer errors.
  Shared-cause and distinct-cause regressions now enforce one rendering of each
  failure without losing its `errors.Is` identity or accepted classification.
  Concise DNS credential summaries also leave output-classified failures
  intact, so DNS wording cannot hide a required-output failure or no-retry
  classification.
- `TestLibraryWarningsDoNotImplyAcceptance` covers both certificate modes,
  Send/Test, controlled resolver failure and `Accepted=false`.
  Deterministic fixtures prove a blocking final writer and synchronous lease
  cleanup are awaited past the operation deadline. DNS-owner cleanup receives
  a live detached five-second context after parent cancellation/expiry.
  An initial full run found a test-fixture scheduling ambiguity from equal
  parent/child deadlines, not a production failure. The cleanup fixture now
  deliberately uses a shorter parent deadline and passed 20 race repetitions.

**Final verification:**

- Focused diagnostic/history/writer and output/cleanup matrices passed repeated
  race runs; the integrated selectors passed twice after parent integration.
- Full `go test -json -race -shuffle=1794593178716668121 -count=2
  -coverprofile=<outside-checkout> ./...`: **2,688 passing test/subtest events**,
  zero failures and six existing helper/CLI-fixture skip events. These are
  events across two repetitions, not independent top-level test counts.
- Statement coverage: public library **93.1%**, CLI **70.2%**, internal mail
  **93.2%**, weighted total **85.8%**. Covered statements increased from
  2,609/3,037 in Phase 1 to 2,788/3,251; new guarded error/cleanup and CLI/AD
  branches change the denominator. The 0.1-point weighted decrease is not
  treated as proof of a missed phase gate or hidden by removing code/tests.
  Inventory cloning, runtime classification, report draining/barriers, output
  check/join helpers and accepted/DNS cleanup helpers have 100% function
  coverage. Real credential/native orchestration coverage remains Phase 3 work.
- Native build/vet/link and version smoke, Windows amd64 and Darwin arm64
  CGO-free build/vet/link, Go formatting, whitespace and release-note checks
  passed. Cross-builds are not native-platform/live-AD certification.
- Raw JSON, coverage/function reports and red evidence remain outside the
  checkout. Dependencies, public signatures, JSON schema v2, normal concise
  report timing and application version remain unchanged.

**Completion decision:** no approved Phase 2 exit criterion remains unresolved.
R04/R05/R06/R14 and R10's writer-reentry correctness defect are resolved.
R07-R09/R11-R13/R15 and R10's measured snapshot/resource work remain open.
Later phases are not implicitly implemented or authorized.

### Phase 3: simplify CLI orchestration with boundary tests

**Dependencies:** agreed output/timeout policy from Phases 0/2.

1. P3-A (**S**, after an **M** characterization step): create minimal per-command OS/terminal/AD seams and characterize
   currently weak orchestration branches (R08).
2. P3-B (**S**, requires P3-A coverage of affected paths): extract pure
   target/config validation, reusing existing endpoint parsing without changing
   error/side-effect order.
3. P3-C (**B**, requires P3-B and pre-input regression): move numeric DNS
   validation before stdin (R07). Test the intentional error-order/UX change.
4. P3-D (**S**, requires P3-A and agreed R04 policy): separate raw options from
   operation state and extract a few cohesive stages. Consolidate duplicated
   cleanup/status policy only after the corresponding behavioral task is green.

Avoid a wholesale rewrite of `run`, new global hooks, or a separate abstraction
for every branch. Maintain direct, readable ownership and control flow.

**Exit gate:** full success/failure stage-order tests, exact owner/lease/terminal
cleanup counts, and unchanged password timeout/fallback policy. Package coverage
should not regress without explaining moved or removed statements; prioritize
assertions on actual effects over a blanket coverage percentage.

#### Phase 3 execution record (2026-11-13, completed)

**Starting commit:** `570d8bb`. The P3-A through P3-D inventory, narrow
per-command dependency boundaries, intentional DNS-validation order change
and separate structural/behavioral commits on the current branch were
explicitly approved. Application 0.3.1, AD SDK 0.8.3, Go 1.26.9, public library
signatures and JSON schema v2 are unchanged. No push, tag, release, CI change
or later-phase optimization is part of this phase.

| Step | Persisted implementation and verification |
| --- | --- |
| P3-A, `08c4991` | Add a private per-command dependency value for host discovery, current user, controlling terminal, AD acquisition, DNS-only owner, shared delivery and native fallback. Keep real source/password/default-sender/certificate assembly on the exercised path. Bind lease release and owner close callbacks when resources are acquired so tests execute the production `Close` path and count each resource exactly. |
| P3-B, `c78b0af` | Extract pure target normalization and numeric endpoint parsing without changing the existing validation/effect order. Preserve defaults, normalization, error wording and endpoint order; reject partial endpoint success. |
| P3-C, `ba4dd6d` | Move numeric DNS validation to pre-effect command/runtime/default-AD-lookup entry points. Red regressions reproduced stdin reads and host discovery before invalid-DNS errors. The green matrix covers send/test/testmail/default-AD/mTLS/EXTERNAL and hostname, unspecified, multicast and zero-port endpoints, with zero stdin reads and zero boundary calls. Local show/set/unset actions still ignore unused AD DNS. |
| P3-D, `112be25` | Separate raw `commandFlags` from fresh `operationOptions` containing execution-only report/own-mail/management state and prepared certificate/trust. Use a syntax-tree migration for private callers and fixtures. Extract `preparedSubmission`, target/message preparation and GSSAPI submission; retain direct control flow and the distinct AD/DNS-only cleanup policies rather than adding a generic pipeline. |

The gopls CLI was unavailable. Editor symbol references mapped the existing
`options` callers before migration; compiler, repeated characterizations,
native vet/build and cross-vet/build checked the resulting private type change.
No new dependency or editor/project instruction file was needed.

**Re-evaluation against the exit gate:**

- Complete Cobra executions cover GSSAPI, mTLS and EXTERNAL send/test/testmail,
  source/owner/delivery failures, known acceptance and genuine DATA uncertainty,
  cleanup errors/warnings, eligible relay and host-discovery fallback, and
  cleanup failure prohibiting native fallback. Tests assert ordered effects
  and exact lease release, AD owner, DNS owner and terminal close counts.
- Password tests run real configuration/principal/secret assembly with injected
  user/terminal/acquisition boundaries. Cases include ordinary send, successful
  default-AD persistence, user/terminal-open/prompt/password/terminal-close/
  owner-close failures and cancellation during credential input. Read password
  bytes are cleared; failed lookups do not persist a sender. Windows source
  ordering includes SSPI before password without claiming native SSPI execution.
- Deterministic `testing/synctest` tests verify the exact one-second operation
  budget after three seconds of message input, and a fresh password-acquisition
  budget after expired source attempts plus two seconds of prompt time.
  Existing native fallback eligibility and parent-context behavior remain
  covered; no deadline is moved across the input boundary.
- Additional final regressions distinguish independent delivery and cleanup
  errors in all authentication modes, preserving both `errors.Is` causes and
  prohibiting replay after cleanup failure. Required-output failures before/
  after host discovery, before/after AD acquisition, before delivery, at test
  cleanup and after known acceptance assert exact remaining effects/cleanup.
  The original output cause appears once; accepted output is not uncertain DATA.
- Saved sender versus explicit/null sender, authenticated own-recipient policy,
  host accounts without canonical mail, host testmail recipient fallback and
  rejected host-default persistence are exercised through the complete command.
  Existing explicit-default certificate conflicts and local no-input management
  tests remain green.
- Two independent commands execute concurrently under the race detector, each
  with its own dependencies/domain/report/trust; each reuses its parsed flags
  for another execution and receives a fresh report and prepared trust state.
  The test preserves Cobra's repeatable-flag semantics: reparsing a StringArray
  flag appends by design, so the second execution reuses the already parsed
  inputs instead of treating intentional append behavior as state leakage.
- Final assertion re-evaluation also confirmed that accepted-output and
  pre-acceptance output use distinct markers. The new tests assert that existing
  contract rather than incorrectly requiring both markers for accepted output.
  These fixture corrections required no production behavior change.

**Final verification:**

```sh
go test -json -race -shuffle=1794593178716668121 -count=2 \
  -coverprofile="$EVIDENCE_DIR/phase3-final.cover" ./... \
  > "$EVIDENCE_DIR/phase3-tests.json"
go tool cover -func="$EVIDENCE_DIR/phase3-final.cover"
```

- **2,934 passing test/subtest events**, zero failures, six skip events across
  the two repetitions. The three distinct skipped tests are unchanged:
  `TestSIGINTMessageHelper` and `TestSMTPTestTLSHelper` are subprocess helpers;
  `TestLibraryMTLSEndToEnd/cli` requires unavailable isolated DNS port 53.
- Statement coverage: public library **93.1%** (148/159), CLI **83.6%**
  (910/1,088), internal mail **93.2%** (1,906/2,045), weighted total **90.0%**
  (2,964/3,292). Phase 2 reported CLI 70.2% and weighted total 85.8%.
  The new seams/stages change statement totals; this is not branch coverage.
- Actual dependency-backed function coverage is orchestration `run` **91.4%**,
  `prepareSubmission` **87.9%**, `runGSSAPISubmission` **91.5%**,
  `openADPassword` **90.6%**, `lookupDefaultSender` **76.2%**,
  `runCertificateSubmission` **91.2%** and `loadAuthenticationOptions` **82.6%**.
  Thin system-backed wrappers are separate functions and some remain uncovered;
  wrapper percentages are not presented as coverage of the real assembly.
  `openADAttempt` is **47.5%**: injected acquisition boundaries do not certify
  real KDC/ticket/LDAP exchange or native terminal/domain adapters.
- Full CLI shuffled race tests passed twice before the structural extraction
  commit. Additional ownership/output/sender/isolation selectors passed twice;
  the final repository suite above includes them. Native vet/build/CGO-free CLI
  link and linked `--version`, Windows amd64 and Darwin arm64 CGO-free
  cross-vet/build/link, formatting, whitespace and release-note checks passed.
- JSON/coverage/function reports and DNS red evidence are retained outside the
  checkout. Temporary linked binaries and the one-off syntax-tree actuator
  are removed at closeout; unrelated ignore/editor changes are preserved.

**Completion decision:** all approved Phase 3 exit criteria are satisfied.
R07 is resolved; R08's CLI boundary characterization is complete, while its
native-platform/real-terminal/live-AD validation remains explicitly Phase 5
work. R09/R11-R13/R15 and R10's measured snapshot/resource work remain open.
No scalability/performance improvement or live-environment certification is
claimed, and Phase 4 or later work is not implicitly authorized.

### Phase 4: implement only measured resource improvements

**Dependencies:** Phase 0 benchmarks; stable Phase 1 message semantics.

| Task | Findings | Trigger | Scope / stop condition |
| --- | --- | --- | --- |
| P4-A | R09 | Material message allocation or folded-header cost | Byte-slice path/builder; preserve public input and body semantics |
| P4-B | R11 | Superlinear runtime rendering confirmed | Event sweep and render-scoped domain formatter; no global cache |
| P4-C | R10/R11 | Lock time or overlapping buffers material, after P2-B/P2-D correctness | Owned snapshot and table reuse; no dropped observations |
| P4-D | R13 | TLS preparation material in repeated-operation profiles | Immutable prepared material only; per-call verification unchanged |

Use `-benchmem`, repeated runs, and CPU/heap profiles when appropriate.
Record actual before/after results, environment, and message/trace sizes.
Do not merge an optimization merely because it allocates fewer objects on one
tiny fixture. Avoid `sync.Pool` for secrets or messages without a demonstrated
need and explicit ownership/clearing rules.

#### Measurement protocol

1. Introduce deterministic synthetic benchmarks using `b.Loop` on the pinned
   Go toolchain. Construct fixtures outside timing, check error/results, and
   ensure outputs are consumed. Keep parsing/report benchmarks separate from
   network/TLS handshake fixtures.
2. Capture baseline and candidate serially on the same otherwise idle host,
   CPU/toolchain, `GOMAXPROCS`, build flags, and fixture sizes. Do not compare
   numbers from parallel agents, race-enabled binaries, or different Go
   versions. On a shared/busy host, report the limitation and rerun rather than
   declaring a marginal improvement.
3. For selected targets use, for example,
   `go test -run='^$' -bench='<target>' -benchmem -count=10 -benchtime=1s <package>`.
   Compare distributions with `benchstat` when the measurement task provides
   that tool; ten samples are a starting point, not proof of significance.
   Record uncertainty and both relative and absolute changes.
4. Profile CPU/allocation hotspots before changing algorithms or adding
   caching. Distinguish `alloc_space` from retained `inuse_space`; `B/op` is
   not peak RSS. Measure concurrent-message retained memory/peak RSS and
   operation latency separately at agreed concurrency and SDK capacity.
5. For locks, measure representative observer latency and use mutex/block
   profiles where applicable; a long noncontended render may not appear in
   a contention profile. Preserve arbitrary-writer correctness independent of
   whether a latency optimization is warranted.
6. Define materiality before optimization: representative sizes, scaling
   target, acceptable small-input regression, memory ceiling, and required
   functional output. R11's suggested doubling ratio is a repeated benchmark
   assessment, not a flaky CI timer assertion. If there is no stable/material
   benefit, keep the existing simpler implementation and close with evidence.

**Exit gate:** agreed improvement on representative workloads, no substantial
regression on small messages, byte/decoded-MIME equivalence, and full race suite.
If profiles show negligible cost, close the task with evidence and keep the
simpler existing implementation.

#### Phase 4 execution record (2026-11-14, completed)

The user authorized all four Phase 4 targets and confirmed **four concurrent
calls**. Application 0.3.1, AD SDK 0.8.3, public options/APIs, JSON schema v2,
delivery semantics and unrestricted input/observation limits remain unchanged.
This phase does not authorize a release, push/tag, Phase 5 connection policy or
new resource limits.

**Approved gates and measurement conditions**

- At least **20% representative time** or **25% allocated-byte improvement**;
  no statistically supported **greater than 10% small-input slowdown**.
- Four-call peak-RSS increase at most **10%**. RSS and retained heap are separate
  measurements, not inferred from allocated bytes or added across processes.
- Runtime doubling below **3x** in repeated measurements, not a CI timer
  assertion. If rendering contention is material, observer wait falls at least
  **75%**.
- Linux amd64, QEMU Virtual CPU 2.5+, kernel 6.12.113+deb13-amd64, Go **1.26.9**,
  `GOMAXPROCS=1`. Benchmarks/profiles/builds were run serially on a shared VM;
  external load was not controllable. Four goroutines do not establish
  four-core throughput. Repeated comparisons use ten samples and `benchstat`.
- Fresh baseline binaries and profiles were captured before editing. Each
  target is compared with its isolated preceding implementation, not credited
  with another target's gain. Memory samples use five isolated processes per
  case and Linux `wait4` maximum RSS in KiB. Original-source overlays use the
  canonical checkout path; distinct build IDs were checked. An alias-path
  overlay that silently selected candidate source was rejected.
- Public message benchmarks execute actual `Client.Send` preparation and stop
  at an explicit offline resolver failure before relay I/O. Report fixtures
  generate actual MIME/JSON and retain returned messages at a four-call barrier.
  TLS fixtures execute complete loopback mTLS submissions, optional EXTERNAL,
  exact received message, one DATA and QUIT. Their server allocations/crypto
  are included; they do not certify corporate DNS/AD or production SMTP latency.

**Implemented changes and measured results**

| Target / isolated workload | Before -> after | Interpretation |
| --- | --- | --- |
| P4-A reader, 10 MiB | 24.81 -> 16.20 ms; 52.54 -> 42.01 MiB/op | Time -34.71%; 138,096 -> 122 allocations |
| P4-A folded value, 16 KiB | 594.3 -> 130.1 us; 2,492.9 -> 341.8 KiB/op | Time -78.11%, bytes -86.29%; linear accumulation |
| P4-A public preparation, 1 KiB / 1 MiB / 10 MiB | 18.82 -> 13.91 us / 2.576 -> 0.573 ms / 25.364 -> 7.003 ms | Time -26.07 / -77.76 / -72.39%; 10 MiB bytes -60.40% |
| P4-A reader, 1 KiB | 15.42 -> 14.38 us | No small-input regression |
| P4-B runtime, 1,000 / 2,000 / 4,000 spans | 15.337 -> 0.536 ms / 59.951 -> 1.107 ms / 230.832 -> 2.281 ms | Time -96.50 / -98.15 / -99.01%; bytes -65.75 / -72.42 / -73.93% |
| P4-B runtime doubling | Ten paired maximum ratios 2.185 and 2.096 | Every measured doubling below 3x |
| P4-B runtime, 0 / 5 / 10 / 100 spans | Time -69.31 / -11.82 / -24.35 / -77.03% | Empty/untracked fast path avoids event storage |
| P4-B formatting, small / medium / rich MIME | 1.241 -> 0.785 ms / 7.651 -> 4.361 ms / 156.75 -> 87.48 ms | Time -36.78 / -43.00 / -44.20%; bytes -48.18 / -52.98 / -51.15% |
| P4-C observer mean / maximum wait | 45,152.39 -> 27.10 us / 45,190.5 -> 106.8 us | -99.94 / -99.76%, exceeding the contention gate |
| P4-C owned snapshot, small / medium / rich Finish | Time +7.01 / +2.68 / +2.78% | Required ownership has a measured cost, below 10% |
| P4-C owned snapshot, small / medium MIME | Time +2.61 / +5.64% | No substantial small-input regression |
| P4-C table/buffer reuse, small / medium / rich MIME | 253.1 -> 188.0 KiB/op / 1.571 -> 1.397 MiB/op / 34.08 -> 27.06 MiB/op | Bytes -25.71 / -11.05 / -20.61%; rich saves about 7 MiB/call |
| P4-C table/buffer reuse, small / medium / rich MIME | Time -6.93 / -9.10 / -4.36% | Savings are not merely an allocation-count change on a tiny input |
| P4-D repeated TLS, 32 roots, 1 KiB, mTLS / EXTERNAL | 2.836 -> 2.376 ms / 2.870 -> 2.426 ms | Time -16.24 / -15.45%; time alone is not the materiality proof |
| P4-D same complete operations | 372.7 -> 184.7 KiB/op / 372.8 -> 184.7 KiB/op | Bytes -50.46 / -50.45%; material repeated-operation benefit |
| P4-D one root, 1 KiB | No supported time change; bytes about -4% | Client-certificate-only cost does not justify additional caching |
| P4-D 32 roots, 1 MiB | Allocated bytes -5.17%; time changes -3.72 / +2.30% | No claim of a comparable large-message or network speedup |

Material rows above are supported by repeated distributions, not one-shot
smoke timings. `benchstat` reports `p=0.000` for the key message, runtime,
formatter, observer, table-allocation and TLS-allocation gains (`p<0.001` at
its display precision). The small standalone formatting paths were sampled
longer when noise made the first comparison inconclusive: coloured ten-fragment
formatting had no supported change (`p=0.853`), HTML was +1.14%, and the other
small/no-op helpers did not show a supported slowdown greater than 10%.

**Four-call maximum-RSS evidence**

| Case | Before -> after median KiB | Change |
| --- | --- | --- |
| Public preparation, 1 MiB | 31,912 -> 28,708 | -10.04% |
| Public preparation, 10 MiB | 222,940 -> 126,192 | -43.40% |
| Snapshot rendering, separate reports | 60,784 -> 61,488 | +1.16% |
| Snapshot rendering, shared report | 51,496 -> 54,656 | +6.14% |
| Final table/buffer reuse, separate reports, versus original locking | 60,784 -> 61,752 | +1.59% |
| Final table/buffer reuse, shared report, versus original locking | 51,496 -> 52,420 | +1.79% |
| TLS, one root, 1 KiB | 17,684 -> 17,740 | +0.32% |
| TLS, one root, 1 MiB | 36,456 -> 36,444 | -0.03% |
| TLS, 32 roots, 1 KiB | 20,272 -> 19,848 | -2.09% |
| TLS, 32 roots, 1 MiB | 38,692 -> 40,876 | +5.64% |

Every case meets the agreed RSS gate. These are distributions on synthetic
inputs, not production memory ceilings. Returned/retained data still scales
with message and observation sizes; this phase introduces no truncation,
collection caps, asynchronous drops or pools for secret/message buffers.

**Correctness and repeated re-evaluation**

1. Reader and byte preparation share parsing/validation/privacy logic.
   Long buffered fragments cannot turn a line's final dot into an unintended
   terminator; byte input retains dots and independent output ownership.
   Data-plus-EOF/error, no-progress readers, dot handling, folded values,
   bidirectional ownership and actual public preparation regressions pass.
   A proposed bulk `io.Copy` lost the former no-progress failure and was
   rejected. Buffer-growth hints without material benefit were removed.
2. Runtime categories are classified once; sorted tied endpoint groups update
   fixed active-category counts. An independent former-scan oracle compares
   exact durations for irregular timestamps, overlaps, future/past endpoints
   and empty/reversed spans. Existing precedence and unusual boundary semantics
   remain intact. Re-evaluation caught and fixed a 22% empty-report slowdown;
   an intermediate double-classification allocation regression was discarded.
3. Domain matching is lazy and local to a table/render, never client/global.
   Goldens, literal-domain/suffix boundaries, escaping, empty tables and
   cross-mode helpers remain unchanged. A standalone no-op helper regression
   was corrected before committing.
4. Snapshot capture clones maps, issue/trace/end-time slices, every nested
   advertised/current/retired inventory/address group, both TLS-row levels,
   validity and client-certificate metadata. Ticket metadata is detached scalar
   data. Output workers/errors/queues/writers/mutexes are not copied.
   Per-report `renderMu` preserves same-report serialization; observers use the
   separate state mutex. Controlled render gates prove live Value/Trace/
   Inventory/ticket updates proceed and do not change captured output.
5. Output failure arriving during MIME generation returns no usable bytes.
   A loopback SMTP regression proves it stops before MAIL/RCPT/DATA, matches
   its cause once, and is neither accepted nor uncertain. Existing `JoinOutput`
   supplies classification without redundant transport error wrapping.
   All controlled-gate/output workers are released and awaited on failure.
6. The typed snapshot table bundle is passed explicitly to JSON/plain/HTML.
   Plain header/cryptography adaptations do not mutate it; repeated cross-format
   tests preserve columns, rows, ordering and notes for all authentication modes.
   Alternatives stream through the outer body part; quoted-printable framing
   uses chunks. An extra nested-builder-sharing layer had negligible benefit
   and was removed. An observer experiment that completed before arrival
   failed explicitly and was replaced, not relabeled as successful evidence.
7. Private TLS material owns CA DER independently of returned mutable trust
   bytes. Exact current bytes/order/count authorize parsing reuse; changed
   inputs revalidate. Replacement pools are immutable, and root-mode changes
   never mutate shared material. System/append pools are requested per operation,
   preserving the standard library's platform/runtime trust-loading behavior.
   Mutation, malformed/non-CA input, reorder/count/replacement, mode/selector
   changes and concurrent calls pass. Changed signer keys and deterministic
   post-expiry client/server checks prove decisions are not cached. CA-policy
   denial after earlier acceptance fails closed with fresh evidence.

CPU/allocation and mutex/block profiles corroborate the chosen targets.
Post-snapshot contention profiles no longer attribute observer blocking to
report-state rendering. Complete TLS allocation attribution drops repeated
CA/root parsing after reuse; TLS cryptography, socket work and server fixture
parsing remain real costs. Do not add overlapping cumulative profile percentages
as if they were disjoint work.

**Final validation**

```bash
go test -race -shuffle=733420 -count=2 -coverprofile="$EVIDENCE_DIR/final.cover" \
  -json ./... > "$EVIDENCE_DIR/final-tests.json"
go tool cover -func="$EVIDENCE_DIR/final.cover"
GOMAXPROCS=1 go test -run='^$' -bench=. -benchmem -benchtime=1x -count=1 ./...
```

- **3,014 passing test/subtest events**, zero failures, six existing skip
  events across two runs. The three distinct skips remain the two subprocess
  helpers and the isolated-DNS-port-dependent real-CLI library subtest.
- Coverage: public library **93.1%** (148/159), CLI **83.7%** (911/1,089),
  internal mail **93.7%** (2,057/2,195), statement-weighted total **90.5%**
  (3,116/3,443). This is not branch coverage or platform certification.
- All **118 benchmark variants** passed a final fixture smoke; those one-shot
  timings are not used for materiality. Focused new ownership/runtime/MIME/
  cache/TLS/output suites were run twice under shuffled race before commits.
- Native vet/build, CGO-free linked CLI `--version`, Windows amd64 and Darwin
  arm64 CGO-free cross-vet/build/link, tracked-Go formatting, whitespace and
  existing release-note extraction tests pass. Cross-builds do not establish
  native terminal/OS trust behavior.
- Raw benchmark distributions, RSS samples, profiles, JSON and coverage remain
  session-local, outside the checkout. Temporary binaries/overlay source are
  removed after verification; unrelated ignore/editor changes are not staged.

**Execution commits:** `be40aa7` (public preparation/memory fixtures),
`0acb6f2` (message path), `b53bc78` (runtime sweep), `849f4a1` (formatter),
`f3e8b1d` (observer/report fixtures), `8fd72be` (owned snapshots),
`fa8eaa5` (table/buffer reuse), `e79d824` (repeated TLS evidence/CA reuse).
Each optimization commit records its own measurements, re-evaluation and
verification; this execution record is the phase closeout.

**Completion decision:** all approved P4-A/B/C/D gates are satisfied. R09's
measured preparation work, R10's snapshot/resource optimization, R11 and R13
are complete. R09/R10's resource-policy questions remain intentionally coupled
to R15 and Phase 5: memory/observation caps were not authorized. R12 dialing,
native platform/real terminal/live AD checks and operational-limit decisions
remain Phase 5 work. Further certificate/signer caching is not justified by
the one-root operation measurements and is not included.

### Phase 5: connection policy, platform checks, and operational bounds

**Dependencies:** timeout decision and R12 latency fixture; resource-limit
decision for any new bounds.

1. P5-A: implement the smallest validated connection-policy change, if needed
   (R12). Explicitly test losing connection closure and bounded concurrency.
2. P5-B: add native Windows/macOS smoke checks for host/console/config and TLS
   limitations, with live AD pilots separate from offline CI (R08).
3. P5-C: implement approved message/header/recipient bounds, or document
   unrestricted behavior and caller-side admission control (R09).
4. P5-D: add focused fuzz targets for header/mailbox parsing and formatting
   invariants. Run ordinary seed tests in CI and bounded fuzz campaigns
   separately. Seeds include quoted local-parts, invalid field names, folded
   blind headers, binary bodies, HTML escapes, and schema fixtures. Assert
   panic freedom, preserved body/input, and privacy/round-trip invariants,
   not merely that random input returns some error.
5. P5-E (R15, independent of connection/native/resource tasks): add formatting
   and shuffled-test gates; introduce other linters only for agreed,
   actionable rules rather than generating a style-only cleanup wave.

**Exit gate:** native versus cross-build evidence recorded honestly, no new
unbounded connection workers, no SMTP replay, and explicit limit/cancellation
errors. Document caller concurrency/admission guidance for service use.

### Phase 6: release and closeout

**Dependencies:** only the remediation tasks actually selected for release.

1. Run the repository's release checks and six-target build workflow.
2. Exercise authorized no-email AD/TLS/SMTP tests; perform a small explicitly
   authorized submission pilot if required. Never infer production readiness
   solely from synthetic tests.
3. Summarize resolved findings, deferred measurements, unsupported/native
   combinations, compatibility changes, and rollback instructions.
4. Update the changelog and version only under release authorization. Do not
   rewrite a published release tag to ship refactoring.

## Reusable task prompt

> Execute task `<phase-task>` from this review only. Revalidate its source
> anchors against the current commit. Read the listed implementation and tests,
> map semantic references/build tags, and present the S/B/M inventory for
> approval. Use the touched-path coverage tier: green characterization before
> structure changes, or a failing regression followed by its exact correction
> for behavior changes. Preserve public API, input immutability, owner lifetime, authentication
> isolation, no-replay semantics, error identity, and report schema unless the
> task explicitly authorizes a change. Use existing helpers and fixtures.
> Make one cohesive patch; do not clean unrelated code. Run focused tests, then
> the specified phase exit checks. For optimization tasks, provide measured
> serial before/after results on the same toolchain/host or stop with evidence
> that optimization is not warranted. Do not add dependencies or silently make
> product-policy decisions to satisfy generic plugin templates.
> Report changed behavior, validation, remaining limitations, and the next
> unblocked task. Do not commit, release, or push unless authorized.

## Scalability and efficiency position

The CLI is a one-message process, not a queue or a high-throughput MTA. The
library supports concurrent operations but deliberately creates fresh SMTP/TLS
connections. SDK credential/LDAP capacity, DNS/discovery, authentication, message
size, and caller concurrency all influence capacity. No production throughput
or peak-memory ceiling can be certified from this review.

For service consumers, first bound concurrent calls and input size at the
application layer, and measure the workload. Do not add implicit SMTP pooling,
credential duplication, unbounded address races, shared mutable TLS evidence,
or message replay to chase throughput. The highest-value likely improvements
are avoiding large-message copies and superlinear diagnostic work, not replacing
the existing network/cryptographic stack.

## Definition of done

A finding is resolved only when its exact behavior has a regression test or
measured evidence, related documentation matches, validation passes, and the
change is persistent. A phased refactor is not complete merely because files
are smaller, interfaces are added, or coverage increased.

Track each finding as **open**, **resolved with evidence**, **deferred pending
measurement/decision**, or **accepted limitation**. Keep correctness fixes
separate from optional optimization and platform certification. The current
baseline is healthy enough for incremental remediation; the findings do not
justify a rewrite.
