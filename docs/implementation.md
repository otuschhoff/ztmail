# Implementation

[README](../README.md) | [Advanced usage](advanced-usage.md) | [Diagnostics](diagnostics.md) | [Implementation](implementation.md) | [Go library](library.md) | [Build and release](build.md)

The [mTLS design](mtls-design.md) records the certificate-authentication contract,
phases and approved platform/validation limits. GSSAPI remains the default.

## Package layout

| Location | Responsibility |
| --- | --- |
| [ztmail.go](../ztmail.go) | Public library options, messages, results and application-owned AD integration |
| [cmd/ztmail/](../cmd/ztmail/) | Cobra CLI, host discovery, stdin handling, credential selection, password prompts, saved sender and native fallback |
| [internal/mail/](../internal/mail/) | Shared message parsing, sender rewriting, AD adapters, SMTP/GSSAPI transport and diagnostic rendering |
| [docs/build.md](build.md) | Build metadata, validation and release automation |

The CLI owns its selected AD client; the library borrows an application-owned
client. CLI-local configuration and process execution stay out of the public
library API. See [library ownership](library.md#ownership-defaults-and-concurrency)
for the concurrency and lifetime contract.

## CLI orchestration boundaries

The CLI binds Cobra flags only to `commandFlags`. Each execution copies those
inputs into fresh `operationOptions`, which separately holds its report,
canonical-own-mail requirement, prepared client certificate/server trust and
explicit management-action selection. No report or prepared credential/TLS
material is stored in the flag bindings.

| Location | Responsibility |
| --- | --- |
| [main.go](../cmd/ztmail/main.go) | Flag dispatch, report lifetime, host-discovery fallback and operation timeout |
| [configuration.go](../cmd/ztmail/configuration.go) | Pure target normalization and shared numeric DNS-endpoint parsing |
| [submission.go](../cmd/ztmail/submission.go) | Prepared message/envelope and GSSAPI acquisition, submission and cleanup |
| [command_dependencies.go](../cmd/ztmail/command_dependencies.go) | Per-command host/user/terminal/AD/DNS/delivery/native boundaries |
| [password.go](../cmd/ztmail/password.go), [mtls.go](../cmd/ztmail/mtls.go) | Real password assembly and the distinct DNS-only certificate lifecycle |

`preparedSubmission` carries normalized operation options, recipients and
message bytes between the input and authentication stages. Numeric DNS syntax
is checked before discovery or stdin; local-only saved-sender actions do not
validate unused AD DNS settings. The special host-discovery fallback still
prepares local recipients without assuming an AD domain.

The ordinary operation timeout starts after message input. Password mode
retains separate source and post-prompt acquisition budgets; credential input
does not consume the fresh password-acquisition allowance. Native fallback
uses the parent context. Report finalization remains outside authenticated
submission so owner cleanup is recorded before final output. AD lease/owner
and DNS-only cleanup retain their different outcome policies; there is no
configurable stage pipeline or new package-global dependency hook.

Offline complete-command tests inject only boundary effects, not the password
or message assembly being characterized. They assert stage order, exact
release/close counts, error identities, output failure gates, concurrent
command isolation and fresh state when reusing parsed flags. They are not a
substitute for native terminal/SSPI or live KDC/LDAP/SMTP validation.

## Certificate branch and shared TLS policy

Cobra validates explicit mode conflicts before input/network work. The CLI
loads/copies certificate material and SMTP trust configuration once. Both
certificate modes branch before credential selection, configure an inert
DNS-only SDK owner with explicitly empty source/principal methods and use
`ADResolver`, which implements only `Resolve`. The library borrows that same DNS
capability without acquiring a lease, reconfiguring or closing its owner.
Sender/recipient validation and shared message rewriting/privacy remain active;
certificate modes never execute native sendmail.

`tls_credentials.go` validates immutable copies and signer matching;
`tls_policy.go` constructs system/append/replace roots, selects acceptable
chains and enforces anchor allow/chain-CA deny policy. Scoped expiry and issuer
exceptions use the same verifier at actual time, never a global bypass.
Native-root expiry limitations explicitly fail configuration.
`tls_auth.go` builds a fresh TLS config/evidence per operation, records
compatible certificate requests/selection and implements exact
`AUTH EXTERNAL =` / optional empty `=` continuation / mandatory 235 behavior
using the existing SMTP client's sequenced command interface.

The shared SMTP transport handles STARTTLS with post-TLS EHLO or implicit TLS.
TLS completion, certificate presentation, SMTP AUTH and DATA acceptance remain
independent. TLS-only mode sends no AUTH; EXTERNAL never runs GSSAPI.
Operation deadlines/cancellation close the connection; no mechanism fallback,
automatic replay or DATA-uncertainty changes are introduced.
JSON v2 and MIME reports freeze method-aware evidence before DATA, exclude
private material and final acceptance, and use local-client validity provenance.

## Default GSSAPI CLI submission flow

1. Validate options, including numeric DNS bootstrap endpoints before input or
   discovery; load the saved sender unless `-f` overrides it, and derive
   the host domain, realm, relay and SPN. Host-domain inference uses local
   configuration, not ambient DNS lookups.
2. Read and validate the RFC 5322 message, extract/deduplicate recipients and
   strip Bcc/Resent-Bcc before credential acquisition. Diagnostic modes never
   read message stdin.
3. Configure an AD owner for a credential candidate, acquire a lease and
   identify its principal. Keytab auto-selection tries distinct single-component
   user/machine-account names in the selected realm, ignoring service-form
   principals unless `--principal` explicitly selects one. Failed attempts
   close their owners before proceeding.
   Optional password fallback is controlled by the CLI.
4. Obtain an SMTP service ticket and, when needed, perform canonical AD mailbox
   lookup. The AD-default-sender management action skips the SMTP ticket and
   performs only the lookup needed to save the address.
5. Apply the sender policy and require canonical own-mail if no recipients were
   supplied. A saved sender is not a substitute for the authenticated recipient.
6. Resolve the relay through the selected AD client's DNS path and connect to a
   returned numeric IP. Verify TLS according to the selected transport mode,
   perform EHLO and complete mutual GSSAPI/SASL authentication.
7. Send MAIL FROM and RCPT TO, require every recipient to be accepted, then
   transmit DATA. Diagnostic testmail is generated from a shared snapshot after
   authentication but before DATA; no-email test mode stops without an envelope.
8. Close the SMTP security context/connection and release credentials. The CLI
   closes its owner; the library releases only its borrowed lease. Confirmed
   acceptance is not undone by a later QUIT/cleanup warning.

On eligible GSSAPI Linux pre-submission failure, the CLI can delegate prepared bytes
to native sendmail. An acquired AD owner must close successfully before relay
fallback. This path does not replay SMTP DATA and does not guess an AD sender
when credentials are unavailable. See
[native fallback](advanced-usage.md#linux-host-sendmail-fallback) for eligibility,
recursion guards, executable discovery and uncertain-outcome behavior.

## AD SDK and ownership

All DNS, Kerberos, and LDAP queries use the combined
[`github.com/otuschhoff/adbind/ad/adclient`](https://github.com/otuschhoff/adbind)
SDK. The application owns one selected AD client and borrows its DNS and
credential lease; SMTP connections are made only to numeric IPs returned by
that client. GSSAPI setup, mutual authentication, signed SASL negotiation, and
Windows SSPI are delegated to the SDK. It uses
`github.com/otuschhoff/gokrb5/v8`, not the former v7 replacement.

The SDK is pinned to `v0.8.3`, which includes liberal, IPv4-first host resolution
with partial-family failures retained in lookup metadata. CLI-owned clients
retain these default host policies across DNS purposes; borrowed library
clients retain their owner's configured policies. This release also includes complete LDAP read racing,
authenticated-principal directory selectors, read-only discovery inventory,
correlated attempt/stage observations, optimistic DNS qualification,
explicit bounded failure diagnostics, opt-in per-question DNS summaries,
server-attributed
DNS/LDAP/Kerberos exchange diagnostics, password-based TGT acquisition,
external credential sources, and OS DNS bootstrap. It also handles unpaged
RootDSE/base-object LDAP responses while preserving strict subtree paging, and
provides explicit per-search naming-context confinement.
The debug report reads safe ticket metadata from the actual SMTP GSSAPI
security context after authentication, not from the TGT or a separately
acquired service ticket. The SDK snapshot distinguishes ticket encryption
from the ticket session key and reports authoritative validity, availability,
and provenance without exporting key bytes, tickets or tokens. Reading these
diagnostics performs no extra credential-file reads or DNS/KDC/LDAP/native
queries and does not change the borrowed owner's policies.
The CLI's `NewAD` path automatically uses bounded, owner-local discovery
caching: fresh DC lists and address answers are reused across sequential
operations, with shared DC address questions across LDAP and Kerberos.
TTL expiry, DNS topology changes and explicit refresh invalidate reuse.
Cache hits do not replay DNS wire observations, so debug reply counts continue
to reflect actual traffic. Direct `DNS()` queries, including the SMTP relay
lookup, remain cache-free. Borrowed library clients retain their owner's policy.
Private dependency setup is documented in the [build guide](build.md#local-builds).

## Canonical sender lookup and rewriting

The CLI's sender precedence is explicit `-f` > saved default sender >
the selected principal's canonical AD address. Without a configured override,
the selected principal is looked up through authenticated,
certificate-verified LDAP TLS. The base comes from
verified RootDSE `defaultNamingContext`, never from an assumed DN.
The shared helper builds `directory.UserByPrincipal` and calls the SDK's
`FindUnique` through an immutable `SingleNamingContext: true` search view.
RootDSE is read without that scope policy; the subsequent canonical-user search
uses the critical naming-context control. This asks
AD to suppress continuation referrals and confines the search to that naming
context without changing the shared client's policy or observation hooks.
It is not referral chasing or forest-wide lookup: "not found" means absent in
the selected naming context. An unsupported critical control or an unexpected
referral remains an error; ztmail never retries without the policy or accepts
partial results. The same shared helper serves the CLI and Go library.
The CLI creates a single-use `RaceClient` for each required lookup, with a
maximum of eight candidate DCs by default and one concurrent operation per
view. The Go library opts in with `Options.LDAPRaceCandidates`; zero uses
ordinary SDK reads. Both paths keep RootDSE and user search on one candidate
connection, rather than independently racing the two queries. The first
complete positive, absent or ambiguous result wins; negative results are not
retried to find a favorable replica. SDK cancellation drains losing work.
Each racing view is explicitly closed with a live, five-second cleanup context,
including after caller cancellation. Cleanup errors are joined with the
lookup error, and no mailbox is returned if view cleanup fails. The view does
not close the borrowed AD owner, mutate its hooks or change its ordinary
LDAP routing/session policy. There is no retained racing pool or new public
mailer lifetime requirement.

The search matches `userPrincipalName` plus `sAMAccountName` for simple
principals, or `servicePrincipalName` for service principals. LDAP filter values
are escaped; supplied identity casing is preserved. The SDK selector now
validates fully qualified principals, matching realms, UTF-8, length limits
(1024 principal bytes and 254 realm bytes), controls and Kerberos component
syntax before LDAP I/O. This intentionally rejects malformed identities that
the former local filter accepted. SDK `FindUnique` also validates entry DN
metadata. Absent, ambiguous, incomplete, or failed searches are errors.

The SDK's `directory.CanonicalMail` selects exactly one uppercase `SMTP:`
primary from `proxyAddresses`, falling back to the single `mail` value if no
primary exists. Lowercase `smtp:` aliases are not substituted. Ambiguous or
malformed mail remains an error, not a guessed `user@domain` address.
SDK 0.8.3 rejects quoted local-parts. For that invalid-mail boundary only,
ztmail applies a local mailbox-validation extension using the shared bare
mailbox serializer. It preserves the same primary/fallback, complete/unique
attribute, alias-validation, ASCII and 254-byte stored-value policies, while
allowing supported quoted local-parts (including spaces and escaped
quotes/backslashes). A primary never hides a malformed fallback or alias.
The extension does not alter the SDK's search, routing or AD ownership, mutate
directory entries, retry LDAP or replace other directory failures.
The same scoped read also requests `objectClass`. Only a matched computer
object with missing mailbox attributes returns an explicit `HostWithoutMail`
result. AD computer objects inherit `objectClass=user`, so the authenticated
principal selector covers them without broadening the filter.
Computer classification requires complete, non-repeated class metadata;
principal suffixes and service-name spelling are not treated as proof of type.
User/unknown-object mailbox absence and all directory/cleanup failures remain
strict. Racing-view cleanup failures clear both the address and host metadata.

CLI and library no-email diagnostics report a warning and retain host
credentials when that result is returned. CLI testmail requires a configured
non-null sender for a mailbox-less host; absent recipients then use that sender
with an explicit warning. Normal submission still requires a configured sender
and explicit/header recipients in this case. AD-based default-sender setting
cannot save a nonexistent mailbox and instructs the user to set one manually.

The chosen mailbox becomes both SMTP `MAIL FROM` and the message `From`.
An existing `Sender` field is also rewritten to avoid retaining a different
sender identity. Old folded/duplicate From/Sender fields are removed; the MIME
body and unrelated headers remain unchanged. Resent headers remain unchanged.
Rewriting invalidates signatures that cover changed headers; sign the resulting
message downstream rather than relying on a preexisting DKIM header.

`-f address` explicitly overrides both envelope and From/Sender, takes precedence
over the saved default, and skips canonical mail lookup when recipients are
already known (useful for service accounts without mailboxes).
`-f '<>'` retains a null envelope sender and preserves the original sender
headers. Override addresses are still validated, and gateway relay permissions
still apply. Use `--ldap-ca bundle.pem` to add enterprise LDAP trust anchors;
there is no LDAP certificate-verification bypass.

## SMTP and authentication safety

Verified STARTTLS is the default, with TLS 1.2 as the minimum. Implicit TLS is
supported; disabling TLS requires an explicit option. TLS uses system trust
and verifies the relay hostname/SANs. The LDAP CA bundle option applies to
LDAP, not as a bypass for the SMTP certificate.

The relay must advertise AUTH GSSAPI. Authentication is complete only after
mutual Kerberos authentication, signed SASL negotiation, and final SMTP `235`
acceptance. A GSSAPI step with no output still sends an empty continuation;
it must not prematurely terminate AUTH. The selected SASL layer is no-layer,
so TLS protects the subsequent message and envelope. Relays requiring a
separate SASL integrity/confidentiality layer are unsupported. Windows SSPI
receives verified SMTP TLS state for channel binding and never uses NTLM.

Message bodies and unrelated headers are preserved by sender rewriting, but
signatures covering changed headers can be invalidated. Bcc fields and folds
are stripped while their extracted recipients remain in the envelope. SMTP
performs wire line-ending normalization and dot-stuffing.

Reader inputs retain buffered EOF, input-error and interactive dot-termination
behavior without allocating a separate slice for every body line. Long-line
fragments cannot be mistaken for standalone dot terminators. Library byte-slice
inputs use the same parser without first copying the input into a reader buffer;
the prepared message and envelope still have independent ownership. Folded
header values accumulate linearly. Both paths retain standard-library message
validation, blind-recipient stripping and byte-for-byte MIME body preservation.

Before acceptance, failures remain errors. Loss of acknowledgement during
DATA can leave delivery uncertain; no automatic SMTP replay is attempted.
Native process failure after startup is also conservatively uncertain.
Required output failure before acceptance aborts further submission stages.
After positive DATA acknowledgement (or known native exit zero), failed
status/warning output is a distinct internal no-retry outcome, not uncertainty
introduced solely by output. Library warning presence is independent of
acceptance; only the separate `Accepted` result proves confirmed DATA.
Operational details are in
[transport and failure behavior](advanced-usage.md#transport-and-failure-behavior).

## Diagnostic data and limits

Terminal tables, text/HTML diagnostic mail and JSON attachments share table
builders. Testmail uses one snapshot timestamp and stable schema/table IDs,
so its representations describe the same pre-DATA state. Final delivery and
cleanup cannot appear in the message that is itself being submitted.

The debug report distinguishes discovery advertisements from actual exchanges.
It reads detached, availability/provenance-tagged ticket metadata from the
actual SMTP security context rather than exporting tickets or keys. Cached
work is not presented as fresh network traffic, and Windows-managed KDC
details remain unavailable rather than being inferred.

Timing intervals can overlap; runtime attribution counts elapsed intervals
once using sorted endpoint events and fixed-category active counts, whereas
detailed step durations must not be summed. Tied endpoints are applied together;
the existing category precedence, clipping, row order and display thresholds
are unchanged. Empty or wholly untracked reports need no event storage.
Crypto estimates
describe observable classical key strength, not certification or a complete
authentication-security assessment. See the [diagnostics guide](diagnostics.md)
for exact reporting, threshold and JSON semantics.

Inventory callbacks retain independently owned endpoint/address slices in all
three advertised/current/retired groups. Raw events preserve their original
generation and health metadata; aggregation unions historical addresses for
response matching, not for claims about current availability. Endpoint history
and DNS-derived matching must not mutate retained events through shared slices.

Report-state mutation and output ordering are separate. A single synchronous
FIFO drainer writes outside the state mutex; concurrent/reentrant `Line` calls
enqueue in recorded order. Writer callbacks may update state or enqueue finite
`Line` calls, but must not call `OutputError`, `Finish` or `TestMessage`: those
methods wait for output completion. The first writer error (including a
nil-error short write) is retained, no further writes are attempted, and
operational error causes survive finalization. There is no background output
worker to abandon on cancellation.

Rendering and testmail preparation still hold the state mutex while reading
report state; the measured snapshot-lock optimization remains Phase 4 work.
Operation deadlines cannot preempt arbitrary writers/signers, synchronous CPU
work or arbitrary synchronous cleanup methods. Owned AD/racing cleanup gets
its own detached five-second context and is awaited, not abandoned.
