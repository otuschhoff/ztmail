# Design: mutual TLS authentication for SMTP submission

[README](../README.md) | [Implementation](implementation.md) | [Go library](library.md) | [Diagnostics](diagnostics.md) | [Build](build.md)

**Status:** Phases 0–4 complete: prerequisites, configuration and shared mTLS/
EXTERNAL transport and end-to-end CLI/library certificate dispatch established.
Method-aware diagnostics and JSON v2 are established; final documentation and
platform/regression matrix (Phase 5) remain.
Baseline: ztmail v0.2.17.
This document defines a bounded implementation plan for an LLM coding agent.
The authentication/trust flags and API fields below are implemented.

### Approved platform scope amendment

The operator additionally approved continuing with deterministic SDK DNS,
CLI validation, shared transport and library tests when the real-CLI DNS
fixture or authorized gateway pilot cannot run here. The real-CLI test needs
an isolated loopback DNS listener on port 53 because the SDK qualifies
discovered AD DNS endpoints on that port. This environment denies that bind;
the Linux integration subtest explicitly skips only that permission failure.
No successful real-CLI submission or production relay-policy pilot is claimed
on the basis of the remaining tests. Pilot and native runtime checks remain
operator actions, reported separately from offline completion.

On 2026-11-03 the user authorized implementing supported behavior and omitting
features limited by the OS environment or Go APIs. Unsupported combinations
must return explicit errors, never silently ignore configuration.

Go 1.26.9 Windows/macOS system verification consumes signed certificate DER,
not an adjusted parsed leaf. Accordingly, expiry grace with system/append roots
is unsupported there; PEM replacement roots use the Go verifier. Linux also
supports grace with system/append roots. The verifier may adjust only a private
parsed leaf's NotAfter after proving its original expiry lies within grace;
signed DER, verification time and every other certificate remain unchanged.
Reports always use the original certificate metadata.

An opaque caller root pool cannot be enumerated/merged through public Go APIs.
The library therefore supplies copied DER root certificates in typed trust
configuration instead of an opaque pool, enabling identical append/replace
semantics without global root changes.

Native runtime/pilot checks unavailable in this environment must be identified
as not performed, with runnable fixtures/operator steps retained; no production
policy verification may be claimed from cross-compilation or loopback tests.

### Frozen implementation contract

- Authentication uses `AuthMode` with `AuthGSSAPI`, `AuthMTLS`,
  `AuthMTLSExternal`; empty resolves to GSSAPI.
- Shared/public configuration uses `Auth`, `ClientCertificate` (in-memory
  `*tls.Certificate`) and `ServerTrust`. The CLI loads PEM into those types.
- `ServerTrust` contains `Mode`, copied DER `Certificates`, typed `Allow`/`Deny`
  selectors, `ExpiredServerCertificateGrace`, and
  `InsecureAllowUnverifiableIssuer`. Empty mode selects system without supplied
  certificates and append otherwise. Explicit system plus certificates is an error.
- `CASelector` contains `Kind` and a 32-byte `Digest`. Supported kinds are
  complete certificate SHA-256 and SPKI SHA-256. Hex is case-insensitive and
  colons may be omitted; all other invalid input is rejected.
- A resolver capability is independent of security-context creation. DNS-only
  CLI owners use explicit empty SDK credential/principal method allow-lists.
- EXTERNAL uses the existing SMTP client's text-protocol sequencing API, sends
  literal `AUTH EXTERNAL =`, allows at most one empty `334` challenge answered
  by literal `=`, and requires `235`.
- Results/report schema v2 carry `Authentication` with method, safe client
  certificate metadata, request/presentation evidence, SMTP AUTH confirmation,
  and server verification/exception evidence. No TLS certificate/private-key
  object is serialized.
- GSSAPI-specific CLI options are detected by explicitly changed Cobra flags;
  the same restrictions are applied to non-zero library options. Manual local
  sender management and version reporting remain side-effect-free.

## Objective

Allow the CLI and Go library to submit mail using a client certificate and
private key instead of Kerberos credentials. Support verified STARTTLS and
implicit TLS on Linux, Windows and macOS without CGO.

This enables services with an organization-issued client certificate to use
ztmail without a keytab, credential cache, Windows logon, password prompt,
SMTP SPN, KDC exchange or canonical LDAP mailbox lookup. Retain AD-aware DNS
through `github.com/otuschhoff/adbind/ad/adclient`; certificate authentication
does not authorize introducing another DNS implementation.

Preserve the existing sendmail interface, message validation and privacy,
recipient handling, cancellation, diagnostic test modes and acceptance/error
semantics. Kerberos GSSAPI remains the default, unchanged authentication path.

### Success criteria

- Explicitly selected certificate authentication works with both TLS modes and
  never silently changes to GSSAPI, plaintext or native sendmail.
- No Kerberos credential acquisition, SSPI, password prompting or LDAP lookup
  occurs on the certificate-authentication path, including on failure.
- Server certificate verification is strict by default; hostname verification
  is always mandatory. Only the explicitly scoped insecure exceptions below
  may relax server leaf expiry or issuer trust.
- Authentication evidence is accurately distinguished from SMTP authorization
  and confirmed DATA acceptance.
- CLI and library share transport and protocol logic, with deterministic tests
  for success, rejection, cancellation, missing capabilities and uncertain DATA.
- Diagnostics contain safe certificate metadata, never private keys or tokens.

### Non-goals for the first implementation

Certificate enrollment, renewal, revocation infrastructure, ACME, PKCS#12,
encrypted-key prompting, Windows certificate-store discovery, PKCS#11 integration,
LDAP certificate mapping, inferred sender addresses, GSSAPI plus a client
certificate, arbitrary caller-provided `tls.Config` callbacks, opportunistic
authentication selection and a new SMTP queue are out of scope.

The relay administrator owns client-CA trust, certificate-to-account mapping,
sender/recipient authorization, revocation policy and relay configuration.
Client-side validity checks are not a replacement for those policies.

## Current architecture and required seams

| Surface | Current behavior | Required change |
| --- | --- | --- |
| [CLI entry point](../cmd/ztmail/main.go) | Validates flags, prepares input, discovers target and chooses credentials | Explicit authentication selection; branch before credential acquisition |
| [CLI AD session](../cmd/ztmail/kerberos.go) | Acquires an AD lease, obtains the SMTP ticket and optionally canonical mail | Preserve for GSSAPI; do not enter for mTLS |
| [CLI/shared adapter](../cmd/ztmail/shared.go) | Passes configuration and a combined DNS/GSSAPI backend | Carry certificate/authentication settings and support a DNS-only path |
| [AD adapter](../internal/mail/ad.go) | `ADBackend` combines DNS with lease-backed security-context creation | Separate the resolver capability from the GSSAPI capability |
| [SMTP transport](../internal/mail/smtp.go) | Builds a verified TLS config, then unconditionally creates a GSSAPI context and calls AUTH | Shared verified TLS setup; explicit authentication branch before the unchanged envelope/DATA tail |
| [Public library](../ztmail.go) | `New` requires an AD owner; every Send/Test acquires a lease; Result identity is Kerberos-specific | Keep borrowed AD DNS, acquire leases only for GSSAPI, add method-specific result evidence |
| [Report JSON](../internal/mail/report_json.go) | Schema v1; snapshot phase assumes SMTP AUTH; crypto/validity assume Kerberos | Method-aware evidence, certificate diagnostics and an explicit schema migration |
| [Native fallback](../cmd/ztmail/local_sendmail.go) | Eligible Linux credential/domain/relay failures can execute sendmail | Preserve GSSAPI eligibility; prohibit fallback in mTLS modes |

Reuse the existing message/sender helpers and test SMTP fixtures. Do not build
a second delivery implementation or duplicate the DATA acceptance state machine.

## Key decisions

### 1. Explicit authentication modes; no negotiation between modes

Proposed CLI flag: `--auth gssapi|mtls|mtls-external`, default `gssapi`.
Proposed library enum: `AuthGSSAPI`, `AuthMTLS`, `AuthMTLSExternal`; its zero
value resolves to `AuthGSSAPI`.

| Mode | Required evidence | SMTP AUTH | No-email test claim |
| --- | --- | --- | --- |
| `gssapi` | Existing mutual GSSAPI exchange, signed SASL negotiation and relay success reply | GSSAPI | Existing authenticated-principal result |
| `mtls` | Server TLS passed the configured trust policy, with any exceptions disclosed; server requested a client certificate; a compatible configured certificate was selected; handshake completed | None | Client certificate presented; relay authorization not independently confirmed |
| `mtls-external` | The same TLS evidence, plus post-TLS EXTERNAL advertisement and a successful SMTP AUTH reply | EXTERNAL | Relay confirmed SMTP authentication; sender/recipient permission remains untested |

Use `mtls-external` when the gateway supports it: its explicit SMTP reply
provides stronger protocol evidence. Retain `mtls` for gateways that authorize
submission directly from a TLS client certificate without offering AUTH.
Neither mode may retry using the other when it fails.

#### EXTERNAL is not GSSAPI

The current application implements only AUTH GSSAPI. AUTH EXTERNAL is a
**new mechanism proposed by this design**, not another name for that code.
EXTERNAL uses authentication already established outside SASL, here the TLS
client certificate; its SMTP exchange asks the relay to map that identity.
It does not acquire a Kerberos ticket or send GSSAPI tokens.

`mtls-gssapi` would instead mean presenting a TLS client certificate **and**
performing the existing Kerberos AUTH GSSAPI exchange. It would need both
certificate credentials and a Kerberos lease/SPN, and the relay would need
policies for both identities. That combination remains a separate, deferred
feature; it cannot be obtained by renaming `mtls-external`.

A relay advertising only AUTH GSSAPI cannot use `mtls-external`. Check the
relay's actual post-TLS capabilities before implementation/rollout. Such a
relay can use certificate-only `mtls` only if its administrator independently
configures certificate-based submission without SMTP AUTH; otherwise retain
ordinary `gssapi` or commission the separate combined mode. Never silently
substitute one mechanism for another.

A successful TLS handshake alone does **not** prove that the server requested,
validated or authorized a client certificate. Even a server that requests and
receives one can have permissive client-verification policy. ztmail must not
claim otherwise. In `mtls`, `--test` succeeds only for the documented TLS checks
and emits the authorization limitation prominently; it sends no envelope.
Positive DATA acceptance remains the only submission-acceptance proof.

### 2. Certificate material and server trust are separate

Proposed CLI inputs:

- `--client-cert PATH`: PEM client leaf certificate followed by intermediates.
- `--client-key PATH`: matching unencrypted PEM private key.
- `--tls-ca PATH`: optional PEM CA bundle for SMTP **server** verification.
- `--tls-ca-mode system|append|replace`: root-store policy, default `system`
  without a bundle and `append` with one, unless explicitly overridden.

| Root-store mode | Trust anchors | Validation |
| --- | --- | --- |
| `system` | OS/system roots only | Reject an accompanying PEM bundle rather than silently ignoring it |
| `append` | System roots plus certificates from the PEM bundle | Require a bundle; do not remove existing system trust |
| `replace` | Only certificates from the PEM bundle | Require a non-empty valid bundle; do not consult or silently restore system roots |

These options do not configure the relay's client-CA trust. Server trust controls
apply to every SMTP authentication mode, including GSSAPI, and both STARTTLS and
implicit TLS. LDAP trust and TLS client-certificate validation are unaffected.

Require the certificate/key pair for both mTLS modes. Load it once per CLI
invocation using standard Go TLS/X.509 helpers. Validate parsing, chain presence,
leaf/private-key matching and supported signing capability. At each operation,
reject an expired/not-yet-valid leaf or restrictive EKU/key-usage extensions
that exclude TLS client authentication. Absence of an EKU extension is not,
by itself, a client-auth exclusion.

Reject group/world-readable private-key files on Unix; report file/parse/permission
errors explicitly. On Windows document restrictive filesystem ACLs rather than
treating Unix mode bits as an ACL check. Do not discover credentials from ambient
certificate stores or prompt to decrypt keys.

Keep TLS 1.2 minimum, normal hostname verification and the relay hostname as
SNI/`ServerName`, even though dialing uses SDK-resolved numeric addresses.
STARTTLS and implicit TLS use the same certificate/trust helper. Reject
`--tls off` for mTLS and reject server-trust/exception options with TLS disabled.
There is no blanket "skip all verification" flag.

Root-pool construction and bundle parsing errors are failures, not reasons to
silently create an empty pool or disable verification. Trust customization
applies only to SMTP; existing LDAP trust settings are independent.

#### CA allow-list and deny-list policy

Add repeatable allow-list (whitelist) and deny-list (blacklist) selectors for
SMTP server trust:

- `--tls-ca-allow-cert-sha256 HEX` / `--tls-ca-deny-cert-sha256 HEX`:
  SHA-256 of the complete DER CA/anchor certificate.
- `--tls-ca-allow-spki-sha256 HEX` / `--tls-ca-deny-spki-sha256 HEX`:
  SHA-256 of DER SubjectPublicKeyInfo, identifying the public key across
  certificate renewals using that same key.

Accept exactly a SHA-256 digest, with documented case/colon normalization;
reject malformed selectors. Subject/issuer DN and CN are useful diagnostic
labels, but are not unique cryptographic identities and are not allow-list
credentials. Serial numbers alone and authority/subject key identifiers are
also insufficient as trust selectors. More selector kinds require a separate
typed policy and tests, not arbitrary substring matching.

Policy semantics:

1. Construct/validate candidate server chains under the selected root policy.
2. A non-empty allow-list requires the candidate's **trust anchor** to match
   at least one allowed certificate or SPKI digest. This restricts existing
   trust; a selector alone never adds trust.
3. A deny-list match on any CA certificate or trust anchor in that candidate
   rejects it, including an otherwise allowed anchor. Deny wins over allow.
4. Accept only if an available valid candidate chain satisfies all policies.
   A rejected alternative path need not invalidate a separate acceptable path.
   Never match policy against arbitrary extra certificates sent by the peer
   but not participating in the selected chain.
5. Failure to establish/evaluate the required anchor or chain fails closed.
   Explicit insecure exceptions never bypass allow/deny policy.

Empty lists add no restriction. CLI flags may be combined; contradictory
selectors may be rejected early or produce an explicit no-acceptable-chain
error, never silently discarded. Report the selected anchor fingerprint and
policy outcome. Do not claim this is revocation checking: denied keys/certificates
are local exclusions, not CRL/OCSP status.

#### Deliberately long, narrowly scoped insecure options

Both options are disabled by default, opt-in for each invocation/library
configuration, and independently controlled:

| Proposed flag | Exception | Checks that remain mandatory |
| --- | --- | --- |
| `--insecure-tls-allow-expired-server-cert-for DURATION` | Accept an expired **server leaf** only when `0 < now - NotAfter <= DURATION` | Hostname, NotBefore, issuer/path validation, CA/intermediate validity, constraints, permitted usages, algorithm/signature checks and CA allow/deny policy |
| `--insecure-tls-allow-server-certificate-with-unverifiable-issuer` | Allow an otherwise valid server chain anchored outside the configured trusted CA store | Hostname, validity except separately enabled leaf grace, supplied-chain signature/constraint checks, permitted usages and CA allow/deny policy |

Use **seven days (`168h`)** as the recommended grace-period example. The duration
option requires an explicit positive finite value; zero means disabled in the
library, negative/invalid values are rejected, and omission does not enable a
seven-day exception. There is no unlimited-expiry form. The exact grace boundary
is inclusive; one nanosecond beyond it fails. Not-yet-valid server certificates
and expired CA/intermediate certificates are not covered.

The longer issuer flag addresses unknown/untrusted anchors, including a
self-signed certificate; it does not mean "accept any malformed chain." Build
and validate a supplied chain to a provisional CA anchor, or a self-signed leaf
whose own signature validates. Do not accept an unsigned/uncheckable leaf by
arbitrarily making it its own trust anchor. Missing issuer material needed to
validate the available path, broken signatures, incompatible constraints,
unsupported critical extensions or other non-trust failures remain errors.
Record a provisional anchor as **untrusted/explicitly permitted**, never as a
normal trusted CA. It must still satisfy configured CA selectors.

Use a single shared verification/policy helper. If these exceptions require
internal `InsecureSkipVerify` plus `VerifyConnection`, install the custom
verifier atomically and perform all non-exempt checks explicitly on every
connection. Do not expose `InsecureSkipVerify` as public configuration.
Do not accept errors by message substring, ignore every X.509 error, or rewind
the verification clock: that could accidentally permit future/expired CAs or
otherwise change path constraints. Phase 0 must prove the chosen approach
preserves all non-exempt checks on the pinned Go version and supported platforms.
If this cannot be established, block the exception rather than broaden it.

Emit a prominent local WARN when an insecure option is configured, even if
ordinary verification succeeds. Record separately whether an exception was
actually exercised, its reason, certificate fingerprint and grace age/limit.
Carry those facts into testmail and raw JSON; never display a plain "verified"
transport status when verification was relaxed. Warn before presenting a client
certificate to an issuer-untrusted server: this deliberately weakens server
identity assurance and can disclose the client certificate to an impostor.

The two flags compose only their named exceptions. Neither disables TLS,
changes client-certificate checks, authorizes plaintext/native fallback,
permits a hostname mismatch or proves SMTP relay authorization.

### 3. Observe certificate use, not just certificate configuration

Use a per-connection client-certificate selection callback to record the
CertificateRequest and selected certificate. Check compatibility using Go's
`CertificateRequestInfo` facilities. An absent request, no compatible certificate,
empty selection or handshake failure is fatal before MAIL FROM.

Keep observation state local to one operation; do not mutate shared certificate
objects or global callbacks. Disable client-session caching/resumption initially
so that diagnostic evidence never depends on a previous connection's certificate
exchange. Do not enable renegotiation.

Record request/selection evidence only as successful presentation after the
handshake succeeds. It still does not expose the relay's verification policy.

### 4. AUTH EXTERNAL needs its own bounded protocol handling

For `mtls-external`, inspect AUTH capabilities only after TLS and the post-TLS
EHLO. Require EXTERNAL, case-insensitively, and a final SMTP `235` reply.
Do not create a GSSAPI security context or reuse its token state machine.

Initially use an empty authorization identity: the relay maps the authenticated
certificate. Non-empty authorization identities and impersonation are deferred.
SMTP represents an empty initial response as the literal `=`; this is not a
base64-encoded equals sign. If the server instead issues an empty continuation,
send the protocol-correct empty response and require final success.

Before implementing, inspect the pinned Go `net/smtp` code and test exact wire
bytes. Its generic `smtp.Auth` encoding must not be assumed to handle this case.
If necessary, add one narrowly scoped EXTERNAL helper using the existing SMTP
client's command/response facilities, with proper response sequencing, deadlines,
bounded challenge handling and cleanup. Do not replace the entire SMTP client.
Unexpected non-empty challenges, repeated challenges, malformed replies and
failure replies are errors; never accept a reply merely because the connection
remained open.

Protocol references: [SMTP STARTTLS, RFC 3207](https://www.rfc-editor.org/rfc/rfc3207),
[SMTP AUTH, RFC 4954](https://www.rfc-editor.org/rfc/rfc4954),
and [SASL EXTERNAL, RFC 4422 Appendix A](https://www.rfc-editor.org/rfc/rfc4422#appendix-A).

### 5. Keep AD DNS, but remove the credential dependency

The CLI still derives the host domain or uses `--domain`; relay defaults remain
`mailgw.<domain>:25`. DNS bootstrap overrides continue through adclient.
The library still requires a caller-owned AD-aware DNS client and explicit
domain; ztmail does not close it.

In mTLS modes, do not acquire a credential lease just to resolve the relay.
Prove that the pinned SDK can initialize/use this DNS path without initiating
Kerberos, SSPI or LDAP. If not, stop at Phase 0 and specify the smallest required
upstream SDK change. Do not silently use `net.DefaultResolver`, external commands,
or a success-shaped fake credential session.

Split the resolver interface from security-context creation. Retain the existing
combined GSSAPI backend where useful for compatibility, but type the mTLS transport
path so it does not require a dummy `NewSecurityContext` implementation.
Any future Kerberos/LDAP operation must still use adclient.

### 6. Sender and recipient policy must not invent an AD identity

For mTLS normal submissions:

- Sender is explicit `-f`, then the CLI saved default. The library uses explicit
  `Message.From`; it does not read CLI configuration.
- Require a configured sender; do not infer one from Subject CN, SAN email/UPN,
  the certificate filename, the host account or unverified directory data.
- Use the existing sender rewriting helpers for a non-null sender.
  Preserve null-envelope `-f '<>'`/`Message.From: "<>"` behavior and original
  sender headers.
- Recipients come from arguments or existing header extraction. Missing
  recipients are an error; there is no canonical-own-mail fallback.

No-email `--test`/library `Test` needs neither a sender nor recipients and performs
no canonical lookup. `--testmail` needs a non-null configured sender and explicit
recipients; unlike the host-mailbox exception, the sender is not an implicit
recipient. It still does not read stdin and still attaches JSON.

Manual saved-sender management remains local and unchanged. Fetching a saved
sender from AD remains its separate existing GSSAPI-based management action;
reject combining that action with mTLS-specific authentication/certificate flags.

### 7. Preserve defaults, ownership and failure boundaries

Reject contradictory options before input/network work: mTLS with explicit
keytab/cache/SSPI/source selection, password prompting, principal/realm/SPN
overrides or LDAP-only overrides; GSSAPI with client-certificate/key flags.
Check whether Cobra flags were explicitly changed rather than rejecting ordinary
defaults. Keep domain/DNS, relay, EHLO, TLS and timeout options available.

No native-sendmail fallback applies in either mTLS mode, including DNS/TCP
failures. Explicit native executable selection is contradictory and rejected.
Preserve existing GSSAPI fallback and no-fallback test/testmail behavior.

Before DATA, TLS/certificate/EXTERNAL failures must prevent any envelope command.
After DATA begins, retain `ErrDeliveryUncertain`; never automatically retry.
After confirmed DATA acceptance, QUIT/cleanup problems remain warnings, not
instructions to resend. Retain cancellation and total operation deadlines.

Certificate rotation is explicit: a new CLI invocation loads the new pair;
library applications construct a new mailer. No file watcher, hidden reload,
credential export or new mailer `Close` method is needed.

### 8. Public API and diagnostics represent the actual method

Add typed authentication configuration to `Options`, with in-memory client
certificate material and typed SMTP server-trust policy; do not make the library
load paths, environment variables or OS stores. Do not accept an unrestricted
`tls.Config` that could bypass validation.

`New` remains network-free. Copy certificate DER slices, parse independent leaf
metadata, clone supplied root pools and copy CA selector slices. Represent
system/append/replace explicitly so a replacement pool cannot accidentally be
treated as an append operation. Use a duration-valued leaf-expiry grace and a
separate explicitly named issuer-exception boolean, both strict by default.
Validate these typed options against the same policy as the CLI.
A caller-owned signer must remain
immutable and safe for concurrent use; do not try to export/clone its private
key. Each Send/Test gets fresh TLS config and observation state.

Retain `Result.Identity` for GSSAPI; leave it empty for mTLS instead of fabricating
a `kerberos.Identity`. Add a method-specific authentication result with selected
method, safe client-certificate identity/fingerprint, certificate-presentation
evidence and SMTP-AUTH-confirmed evidence. `Accepted` retains its meaning.

Reports should show the selected method, certificate subject/issuer, SHA-256
fingerprint, validity, client public-key/signature metadata and presentation
evidence. Distinguish local client-chain metadata from a server-verified chain.
Also report root-store mode, selected anchor, CA allow/deny outcomes, configured
insecure options and actually used verification exceptions. Distinguish trusted
verification from a signature-valid path to an explicitly permitted untrusted
anchor; cryptographic key-strength estimates do not restore missing issuer trust.
Never include PEM, private-key bytes, tickets, SASL payloads or passwords.
Credential paths and certificate identities are sensitive topology information;
retain the existing sharing warning.

Use explicit not-applicable values for Kerberos principal/SPN/ticket fields;
do not label them failed or derive overall strength using an imaginary Kerberos
component. Adapt crypto notes conservatively for TLS plus the observable client
certificate, without claiming relay-side mapping or policy strength.

Reuse the frozen snapshot and shared validity formatter, including the strict
48-hour threshold, progressive UTC date greying and `now`/grey `new` below five
seconds. Include client-certificate validity with clear provenance. Preserve
monospace technical values and unstyled raw table rows.

Introduce report JSON schema v2 for method-specific authentication evidence.
Retain existing table IDs/columns where meaningful and document migration from
v1, including not-applicable Kerberos values. Use a method-neutral snapshot phase
such as `after_transport_authentication_before_data`, explicitly noting that
TLS-only mode has no SMTP AUTH confirmation. Never mix ANSI/HTML into JSON.

## Phased implementation for an LLM

Execute phases in order. Each phase must leave buildable code and passing focused
tests. Do not implement later phases to work around a failed prerequisite.
Use existing patterns, no unrelated refactors, and no dependency additions
without a demonstrated need. Do not inspect real credential files.

### Phase 0: prove prerequisites and freeze the protocol/API contract

**Tasks**

1. Read the source anchors above and existing SMTP, library, CLI validation,
   native fallback, diagnostic and ownership tests.
2. Prove SDK DNS-only use without credential acquisition, KDC/LDAP traffic,
   SSPI or prompting using injected hooks/fakes and the pinned dependency.
3. Inspect `net/smtp` and prototype/test EXTERNAL empty-response wire handling,
   including immediate `235` and one empty `334` continuation.
4. Prove append/replace root handling, chain/anchor selector evaluation and
   narrowly scoped expiry/issuer exceptions against Go X.509/TLS behavior.
   Include seven-day boundary tests and rejection of every non-exempt error.
   Confirm relay operators understand EXTERNAL differs from current GSSAPI.
5. Finalize the enum/config/result field names, schema v2 shape and flag conflict
   matrix according to these decisions. Record concrete APIs, not guesses.

**Exit criteria:** runnable prerequisite tests, exact wire transcript assertions,
verification-policy proofs and a frozen contract. Unsupported SDK DNS-only
behavior, an exception that cannot preserve required checks, or incompatible relay
requirements block implementation; report the required upstream/operator change.

### Phase 1: authentication-aware configuration and shared seams

**Tasks**

1. Add auth mode/types and validation to shared configuration and public options.
   Preserve the zero-value GSSAPI behavior.
2. Separate resolver and GSSAPI capabilities; carry typed TLS client credentials
   and trust configuration through the shared adapters.
3. Add deterministic PEM loading/validation and safe copying for in-memory
   library inputs. Reject malformed, mismatched, incomplete and contradictory
   inputs explicitly. Include typed root modes, CA selectors and independent
   duration/issuer exceptions, with strict zero-value defaults.
4. Add option tests proving construction makes no network calls and defaults
   still match v0.2.17. Do not advertise mTLS as usable before later phases.
   Until an mTLS path is fully wired, reject its submission explicitly rather
   than allowing it to fall through to the existing GSSAPI implementation.

**Exit criteria:** existing GSSAPI tests pass unchanged except intentional new
coverage; configuration errors occur before stdin/credential/network side effects.

### Phase 2: verified TLS client authentication and SMTP branches

**Tasks**

1. Share the TLS config builder and server verification/policy helper between
   STARTTLS and implicit TLS, including GSSAPI's server TLS.
2. Add operation-local certificate request/selection evidence and validation.
3. Implement explicit GSSAPI, TLS-only and EXTERNAL branches after the server
   TLS verification/policy checks.
   Keep the common MAIL/RCPT/DATA/QUIT tail and uncertainty behavior.
4. Extend loopback SMTP/TLS fixtures with a test CA and client certificates
   generated in memory. Keep `RequireAndVerifyClientCert` for positive and
   rejection fixtures; add a permissive/no-request fixture for evidence tests.
5. Add alternative-chain, denied-anchor/intermediate, append/replace, expiry-grace,
   issuer-exception and combined-exception fixtures. Prove non-exempt failures
   still prevent authentication/envelope commands.

**Exit criteria:** all three branches work with the expected protocol evidence;
rejected/missing certificates and failed EXTERNAL never reach the envelope.
Strict defaults and CA policies cannot be overridden implicitly; exception
warnings and actual-use evidence distinguish permitted insecurity from trust.
Wire tests assert exact AUTH commands, no GSSAPI tokens in mTLS, and no cleartext
authentication before STARTTLS.

### Phase 3: wire CLI and library end to end

**Tasks**

1. Add Cobra flags/help and explicit-flag conflict checks.
2. Branch before credential probing/acquisition, service-ticket requests and LDAP.
   Initialize only the SDK DNS path for mTLS; preserve owner cleanup.
3. Implement the specified sender/recipient rules for Send, Test and testmail,
   including saved defaults, null envelope and missing-input errors.
4. Update library dispatch/construction guards so a DNS-only mTLS client is valid
   without a credential-acquisition function. Add method-specific results.
5. Disable native fallback on mTLS and test all early-failure/cancellation paths.

**Exit criteria:** runnable CLI and library mTLS submissions/tests with zero
credential/LDAP calls, borrowed owner left open, unchanged GSSAPI sender/fallback
semantics, and no test-mode stdin/envelope activity.

### Phase 4: method-aware diagnostics and JSON v2

**Tasks**

1. Populate authentication evidence only from the actual connection.
   Include server-trust policy and configured/used exceptions.
2. Add client-certificate details/validity, applicable crypto calculations and
   explicit absent Kerberos fields. Differentiate TLS-only checks from confirmed
   EXTERNAL authentication in every report surface.
3. Implement/document JSON v2 and the method-neutral pre-DATA snapshot.
4. Extend MIME, raw JSON, terminal colour, HTML escaping/monospace and snapshot
   tests. Preserve the date-prefix and fresh-age boundary tests.

**Exit criteria:** terminal, HTML, plain text and JSON agree on evidence and raw
values; no private material leaks; no AUTH success or delivery proof is invented.

### Phase 5: regression, platform validation and operator documentation

**Tasks**

1. Complete the test matrix below with shared fixtures, not separate transport
   implementations.
2. Run focused tests first, then `make test`, Windows cross-vet and `make build`.
   Verify Linux version metadata and all six existing build targets.
3. Update README, advanced usage, implementation, library and diagnostics guides.
   Clearly document relay prerequisites, EXTERNAL versus GSSAPI, root replacement,
   CA selectors, seven-day grace examples, insecure-option risks and schema
   migration; add an Unreleased
   changelog entry. Do not bump/tag/push unless separately requested.
4. Arrange an authorized pilot against one EXTERNAL gateway and, if deployed,
   one certificate-only gateway. Record actual relay policy and observed evidence.

**Exit criteria:** offline automated validation passes; live checks are reported
separately, with no claim that loopback tests prove production AD/relay policy.

## Required regression matrix

| Area | Cases and required assertions |
| --- | --- |
| Configuration | Default GSSAPI; unknown mode; missing one/both credential files; malformed PEM/key; mismatch; invalid/empty CA bundle; explicit root-mode conflicts; malformed selectors; invalid/negative grace; TLS-off rejection; explicit conflicting flags; mode-independent version/local management |
| TLS modes | STARTTLS and implicit TLS, TLS 1.2/1.3; system/append/replace roots; replaced system root no longer trusted; hostname mismatch; missing STARTTLS; expired/untrusted server; untrusted/expired/not-yet-valid client; unsuitable EKU/key use; incompatible certificate request |
| CA policy | Certificate/SPKI digests; normalization; anchor allow-list; anchor/intermediate deny-list; deny beats allow; renewal with same SPKI; alternate acceptable paths; irrelevant peer certificates; missing policy evidence fails closed; policies enforced under insecure exceptions |
| Server exceptions | Strict default; configured versus used warnings; expired leaf inside/exactly at/just beyond 168h grace; future leaf and expired CA still fail; unknown anchor only; malformed/broken/incomplete path still fails; hostname/usages/constraints/signatures always enforced; both options together waive only their two predicates |
| Presentation | No CertificateRequest fails even if handshake succeeds; request/selection evidence resets per call; permissive server policy never becomes claimed verification/authorization |
| EXTERNAL | Post-TLS capability only; missing EXTERNAL; case-insensitive advertisement; literal `=`; immediate success; empty continuation; rejection; unexpected/repeated challenges; malformed response; disconnect; deadline/cancellation |
| Isolation | No keytab/cache reads, lease/ticket acquisition, SSPI, password prompt or LDAP in mTLS; all relay DNS via SDK; GSSAPI lease/security cleanup unchanged; no native fallback |
| Message semantics | Explicit/saved sender precedence; missing sender; null sender/header preservation; Bcc/Resent-Bcc removal; deduped/header recipients; missing recipients; sender not inferred from certificate; inputs not mutated |
| Test modes | No stdin for test/testmail; no MAIL/RCPT/DATA for Test; testmail needs configured non-null sender and explicit recipient; JSON attachment always present |
| Delivery lifecycle | Every RCPT must succeed before DATA; write/final-reply failure is uncertain; confirmed DATA plus QUIT failure is accepted with warning; no retry/replay |
| Ownership | Network-free New; copied mutable TLS inputs; immutable concurrent signer contract; fresh connection evidence; concurrent Send/Test; cancellation; borrowed AD owner not closed or reconfigured |
| Diagnostics | Method-correct identity/authentication evidence; root mode/anchor/policy outcome; configured versus used insecure exceptions; untrusted anchor never labelled trusted; schema v2 migration; no PEM/key/token leak; escaped monospace values; certificate validity provenance; strict 48-hour/5-second boundaries; UTC date prefix greying; raw JSON/plain text |

## Proposed usage after implementation

```sh
# Certificate plus explicit SMTP AUTH EXTERNAL confirmation:
ztmail --auth mtls-external --domain corp.example.com \
  --client-cert /etc/ztmail/client-chain.pem --client-key /etc/ztmail/client.key \
  -f automation@example.com -oi recipient@example.com < message.eml

# Replace system server roots with an organization-controlled PEM bundle:
ztmail --auth mtls-external --domain corp.example.com \
  --tls-ca /etc/ztmail/server-roots.pem --tls-ca-mode replace \
  --client-cert /etc/ztmail/client-chain.pem --client-key /etc/ztmail/client.key \
  -f automation@example.com -oi recipient@example.com < message.eml

# Scope trust to an allowed anchor key; deny an obsolete CA certificate:
# CA_SPKI_SHA256 and OLD_CA_CERT_SHA256 stand for actual SHA-256 digests.
ztmail --auth mtls-external --domain corp.example.com \
  --tls-ca /etc/ztmail/server-roots.pem --tls-ca-mode append \
  --tls-ca-allow-spki-sha256 "$CA_SPKI_SHA256" \
  --tls-ca-deny-cert-sha256 "$OLD_CA_CERT_SHA256" \
  --client-cert /etc/ztmail/client-chain.pem --client-key /etc/ztmail/client.key \
  -f automation@example.com -oi recipient@example.com < message.eml

# Explicitly insecure: tolerate only a server leaf expired within seven days.
ztmail --auth mtls-external --domain corp.example.com \
  --insecure-tls-allow-expired-server-cert-for 168h \
  --client-cert /etc/ztmail/client-chain.pem --client-key /etc/ztmail/client.key \
  --test --debug

# Verify that path without reading stdin or sending an envelope:
ztmail --auth mtls-external --domain corp.example.com \
  --client-cert /etc/ztmail/client-chain.pem --client-key /etc/ztmail/client.key \
  --test --debug

# Gateway configured for certificate-only TLS authorization:
ztmail --auth mtls --domain corp.example.com \
  --relay submission.corp.example.com --tls implicit --port 465 \
  --client-cert /etc/ztmail/client-chain.pem --client-key /etc/ztmail/client.key \
  -f automation@example.com -oi recipient@example.com < message.eml
```

File paths are examples, not discovery locations. Windows uses the same flags
with Windows paths. For testmail, explicitly provide both a non-null sender and
a recipient; successful diagnostic authentication is not mailbox-delivery proof.
