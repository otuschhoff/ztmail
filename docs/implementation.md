# Implementation

[README](../README.md) | [Advanced usage](advanced-usage.md) | [Diagnostics](diagnostics.md) | [Implementation](implementation.md) | [Go library](library.md) | [Build and release](build.md)

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

## CLI submission flow

1. Validate options, load the saved sender unless `-f` overrides it, and derive
   the host domain, realm, relay and SPN. Host-domain inference uses local
   configuration, not ambient DNS lookups.
2. Read and validate the RFC 5322 message, extract/deduplicate recipients and
   strip Bcc/Resent-Bcc before credential acquisition. Diagnostic modes never
   read message stdin.
3. Configure an AD owner for a credential candidate, acquire a lease and
   identify its principal. Keytab auto-selection tries distinct principals in
   the selected realm; failed attempts close their owners before proceeding.
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

On eligible Linux pre-submission failure, the CLI can delegate prepared bytes
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

The SDK is pinned to `v0.8.1`, which includes complete LDAP read racing,
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
primary exists. Lowercase `smtp:` aliases are not substituted. Missing,
ambiguous, or malformed mail is an error, not a guessed `user@domain` address.

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

Before acceptance, failures remain errors. Loss of acknowledgement during
DATA can leave delivery uncertain; no automatic SMTP replay is attempted.
Native process failure after startup is also conservatively uncertain.
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
once, whereas detailed step durations must not be summed. Crypto estimates
describe observable classical key strength, not certification or a complete
authentication-security assessment. See the [diagnostics guide](diagnostics.md)
for exact reporting, threshold and JSON semantics.
