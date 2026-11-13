# Refactoring review and execution plan

**Review date:** 2026-11-13

**Baseline:** `1d08ad5c438fd940d9344fb7b061939523c2f773`, ztmail 0.3.1,
AD SDK 0.8.3, Go 1.26.9

**Method revision:** second review using `samber/cc-skills-golang`; production
baseline unchanged

**Disposition:** review only; no application changes, commits, or releases.

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
| R01 | P1 | Confirmed correctness gap | Quoted mailbox local-parts lose required envelope quoting |
| R02 | P1 | Confirmed validation gap | Invalid header field names pass local preparation |
| R03 | P1 | Confirmed error-contract gap | SMTP cancellation can lose context sentinel identity |
| R04 | P2 | Confirmed consistency/documentation gap | Warning/output handling differs across CLI, library, and fallback |
| R05 | P2 | Confirmed diagnostic defect | EXTERNAL auth duration is categorized as handshake time |
| R06 | P2 | Confirmed diagnostic defect | DC inventory updates replace historical address evidence |
| R07 | P2 | Confirmed maintainability/UX issue | CLI orchestration mixes state and performs some configuration checks after input |
| R08 | P2 | Measured testing gap | Real orchestration and native paths are less covered than helper contracts |
| R09 | P2 | Resource-design concern; performance unmeasured | Message buffering, copying, and folded-header accumulation |
| R10 | P1 | Confirmed reentry defect plus resource concern | Arbitrary report output under the state mutex can self-deadlock |
| R11 | P2 | Confirmed algorithmic cost; impact unmeasured | Quadratic runtime aggregation and repeated formatting work |
| R12 | P2 | Connection-policy trade-off | Sequential address dialing delays later reachable addresses |
| R13 | P3 | Optimization hypothesis | Immutable TLS material is prepared repeatedly |
| R14 | P2 | Confirmed contract mismatch | Complete-call timeout wording exceeds enforceable guarantees |
| R15 | P2 | Confirmed quality-gate gap | Local review checks and test-isolation expectations are not enforced in CI |
| R16 | P1 | Confirmed construction safety gap | A typed-nil certificate signer can panic instead of returning an error |
| R17 | P2 | Confirmed validation gap | Strict CA-bundle loading can silently skip a malformed PEM block |

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
