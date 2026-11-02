# ztmail

A sendmail-style SMTP submission client written in Go, using Cobra and
Kerberos **SASL GSSAPI** (RFC 4752). Builds for Linux, Windows, and macOS without CGO.
Password authentication is available only through an opt-in terminal prompt.
It does not use NTLM, HTTP Negotiate, or anonymous SMTP fallback.

## Build

Requires Go 1.26 or later; the module selects toolchain Go 1.26.9.
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
make build-one TARGET_OS=darwin TARGET_ARCH=arm64
make test
./dist/ztmail-linux-amd64 --version
# 0.2.0+20261101-110716.abcdef0
```

The semantic version is **0.2.0**. Every supported build includes UTC build time
and exactly seven characters of the checked-out commit SHA as SemVer build
metadata: `0.2.0+YYYYMMDD-hhmmss.<commitSha>`. A multi-target build uses one
timestamp/SHA for every binary. `BUILD_TIME` and `COMMIT_SHA` can be supplied to
Make for controlled rebuilds; otherwise they come from the UTC clock and Git HEAD.
The executable now lives in `cmd/ztmail`; `go build ./cmd/ztmail` builds the CLI,
while the repository root is an importable library. Raw CLI builds without
linker metadata have no trustworthy build timestamp:
`--version` reports an explicit error rather than inventing one. Use the
Makefile or inject `-X main.buildTime=... -X main.commitSHA=...` yourself.

## Go library with an application-owned AD client

Import `github.com/otuschhoff/ztmail`. The application supplies an existing
`*adclient.Client` created with `adclient.NewAD`; ztmail does not create another
AD owner or duplicate its DNS, discovery, credential, or LDAP state.

```go
import (
    "context"
    "errors"
    "fmt"

    "github.com/otuschhoff/adbind/ad/adclient"
    "github.com/otuschhoff/ztmail"
)

func sendNotification(ctx context.Context, appAD *adclient.Client) error {
    mailer, err := ztmail.New(ztmail.Options{
        AD:       appAD,
        Domain:   "corp.example.com",
        Relay:    "mailgw.corp.example.com", // optional: this is the default
        Hostname: "worker.corp.example.com", // optional EHLO override
    })
    if err != nil {
        return err
    }

    result, err := mailer.Send(ctx, ztmail.Message{
        Recipients: []string{"recipient@example.com"},
        Data:       []byte("Subject: Notification\r\n\r\nHello.\r\n"),
    })
    if err != nil {
        if errors.Is(err, ztmail.ErrDeliveryUncertain) {
            return fmt.Errorf("check relay acceptance before retrying: %w", err)
        }
        return err
    }
    for _, warning := range result.Warnings {
        // The relay already accepted DATA; log this without resending.
        fmt.Printf("SMTP cleanup warning: %v\n", warning)
    }
    return nil
}
```

### Ownership, defaults, and concurrency

- `New` validates options without network I/O. `Domain` is required and must
  describe the borrowed client's AD domain. `Realm` defaults to uppercase
  `Domain` and must match the acquired identity. The library does not inspect
  host configuration, credentials files, environment variables, or terminals;
  credential sourcing remains entirely with the supplied AD owner.
- The default relay is `mailgw.<Domain>`, port 25, EHLO `localhost`, and SPN
  `smtp/<Relay>`. TLS defaults to verified STARTTLS (`TLSRequired`). Use
  `TLSImplicit` with an explicit appropriate port, or deliberately opt out with
  `TLSOff`. `Timeout` defaults to 60 seconds for the complete operation; caller
  context cancellation/deadlines also apply.
- Each `Send` borrows a separate credential lease, uses AD DNS for relay
  resolution, and creates a fresh SMTP connection and TLS-bound GSSAPI context.
  The lease is released on every outcome and the security context is closed.
  Shared tickets and LDAP sessions remain managed by the application's SDK.
- A mailer supports concurrent calls, subject to SDK credential/LDAP capacity
  limits. Do not modify message slices until the call returns. There is no
  mailer `Close`: the application closes the shared AD client only after all
  in-flight operations complete. No credentials fallback or interactive
  password prompting is initiated by the library.
- The CLI and library share message validation, sender rewriting, canonical
  LDAP lookup, AD DNS/GSSAPI adapters, TLS and SMTP transport code. Cobra,
  sendmail stdin handling, source probing and password prompts belong to the
  CLI, not the public library API.

### Message and result semantics

`Message.Data` is a complete RFC 5322 message, not a dot-terminated SMTP stream.
Dot-only body lines are preserved. `Recipients` supplies envelope recipients;
`ReadRecipients: true` also reads To/Cc/Bcc (or the latest Resent block).
Bcc/Resent-Bcc headers are always stripped, and duplicate recipients are
deduplicated. Message structure and envelope addresses are validated before
credential acquisition.

By default, the canonical AD mail address becomes the envelope sender and
From/Sender headers. `Message.From` explicitly overrides them and skips the
mail lookup. `Message.From: "<>"` uses the null envelope and preserves sender
headers. Input byte/slice contents are not mutated.

`Result` contains the acquired `Identity`, selected envelope `From`, recipients,
`Accepted`, and post-acceptance `Warnings`. A nil error with `Accepted: true`
means the relay confirmed DATA acceptance, not ultimate mailbox delivery.
QUIT/context-cleanup failures after acceptance are warnings, not send failures.
Before acceptance, errors are returned normally. An error matching
`ErrDeliveryUncertain` means DATA started but acceptance could not be confirmed;
do not blindly retry. Neither API performs automatic SMTP retries.

`mailer.Test(ctx, reportWriter)` checks canonical mail and SMTP authentication
without sending email; it always leaves `Accepted` false. It returns cleanup
and report-writing failures as errors. It writes only to the supplied writer.
For AD exchange-level endpoint diagnostics, configure observation hooks when
constructing your application's AD client; borrowing a client does not replace
its hooks. Normal `Send` does not write to stdout/stderr.

### GitHub Actions

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
the matching curated section of [CHANGELOG.md](CHANGELOG.md), not GitHub-generated
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

All DNS, Kerberos, and LDAP queries use the combined
[`github.com/otuschhoff/adbind/ad/adclient`](https://github.com/otuschhoff/adbind)
SDK. The application owns one selected AD client and borrows its DNS and
credential lease; SMTP connections are made only to numeric IPs returned by
that client. GSSAPI setup, mutual authentication, signed SASL negotiation, and
Windows SSPI are delegated to the SDK. It uses
`github.com/otuschhoff/gokrb5/v8`, not the former v7 replacement.

The SDK is pinned to revision `1a78ba528554`, which includes server-attributed
DNS/LDAP/Kerberos exchange diagnostics, password-based TGT acquisition,
external credential sources, and OS DNS bootstrap. It also handles unpaged
RootDSE/base-object LDAP responses while preserving strict subtree paging.
The repository is private: configure GitHub
access and `GOPRIVATE=github.com/otuschhoff/*` before fetching dependencies.
There is no local-path module replacement.

## Defaults and discovery

For a machine named `worker.corp.example.com`:

| Setting | Default |
| --- | --- |
| Host DNS domain | `corp.example.com` |
| AD Kerberos realm | `CORP.EXAMPLE.COM` |
| Relay | `mailgw.corp.example.com` |
| Port | `25` |
| Service principal (SPN) | `smtp/mailgw.corp.example.com` |
| TLS | Required STARTTLS, certificate/hostname verified, TLS >= 1.2 |
| Envelope sender and From | Authenticated principal's canonical AD mail address |
| DNS bootstrap | OS DNS servers, discovered by adclient |
| DNS recursion probe zone | `example.com` (must be outside the AD domain) |

Domain inference uses local host configuration, without ambient DNS queries.
Discovery uses the host FQDN. Linux and macOS additionally
uses the first suffix from the last `search`/`domain` directive in
`/etc/resolv.conf`; Windows reads the machine's primary DNS suffix using
`GetComputerNameExW`, not the logged-in user's domain. Search suffixes
are heuristics: specify `--domain` on multihomed hosts, containers, or
machines whose resolver search domain differs from their AD domain.
Discovery fails explicitly if no domain is available.

Override with `--domain`, `--realm`, `--relay`, `--port`, `--hostname` (EHLO),
and/or `--spn`. The relay must be a DNS hostname, not a URL, IP literal, or
`host:port`. The SPN must be registered to the relay's AD service account;
an alias may require an explicit `--spn`.

The SDK discovers and qualifies AD DNS servers from OS resolver configuration,
then uses that DNS path for DC/KDC and relay resolution. There is no application
`net.DefaultResolver`, alternate LDAP client, or direct Kerberos network client.
Override bootstrap with repeatable `--dns-server IP[:port]` (IPv6 ports require
brackets); this disables OS bootstrap fallback. Configure an external
`--dns-probe-zone` if `example.com` is in your AD domain or unsuitable for your
DNS policy. The SDK uses bounded random-name probes under that zone to qualify
recursive capability. Bootstrap servers are discovery hints, not automatically
trusted AD data servers.

## Authentication test (no email)

```sh
./dist/ztmail-linux-amd64 --test --keytab /etc/ztmail/mailer.keytab
./dist/ztmail-linux-amd64 --test --ccache /tmp/krb5cc_1000 \
  --domain corp.example.com --relay mailgw.corp.example.com
# Use Windows SSPI, with optional password fallback:
ztmail-windows-amd64.exe --test --password-prompt
```

`--test` does not read message stdin and does not accept recipient arguments.
It follows the normal credential-selection and AD discovery path, obtains the
SMTP service ticket, and performs the canonical AD mail lookup (unless `-f`
explicitly bypasses that lookup). It then resolves and connects to the relay,
verifies TLS according to `--tls`, exchanges SMTP greetings/EHLO, completes
GSSAPI mutual authentication and signed SASL negotiation, and sends `QUIT`.
It never sends `MAIL FROM`, `RCPT TO`, `DATA`, or message content.

The step report is written to stderr without requiring `--verbose`. It shows:

- Local host, AD domain, realm, relay hostname/port, EHLO name, and SMTP SPN.
- Credential attempts, the selected principal and actual keytab/ccache/SSPI/
  password source, and the canonical mail address where applicable.
- SDK operation results and observed DNS, LDAP, and Kerberos exchanges,
  including the logical server, actual connected peer, request kind, transport,
  outcome, and duration.
- Relay DNS addresses, the connected SMTP peer, TLS, GSSAPI, and cleanup results.

Only real SDK exchanges identify used AD servers; discovered candidates are not
presented as contacted servers. Cached DNS results/TGTs/service tickets emit no
new network exchange. Windows SSPI manages its own KDC traffic, so the SDK
cannot report its used KDC endpoint. An exchange marked `SUCCESS` means a
response was received, not necessarily successful authentication: a KDC
preauthentication challenge or error reply is still a completed exchange.
The separate credential and SMTP authentication steps establish success.
Passwords, security tokens, LDAP filters, DNS query names, and payloads are
not included in exchange diagnostics. The report does contain account and
internal routing information; review it before sharing.

Authentication failures stop the test with a nonzero exit status and retain
step diagnostics; configured credential/principal fallback may first try other
identities. QUIT, security/credential cleanup, and diagnostic-output failures
also fail test mode rather than claiming that a message was accepted.
Normal submission semantics, TLS requirements, authentication flags, and
password-prompt timeout behavior remain unchanged. `--test` does not check
sender/recipient acceptance or permission to submit message data.

## Credentials

### Linux, macOS, or Windows: keytab

```sh
./dist/ztmail-linux-amd64 \
  --keytab /etc/ztmail/mailer.keytab \
  --domain corp.example.com -oi -t < message.eml
# Restrict selection to one identity and explicitly override the sender:
./dist/ztmail-linux-amd64 \
  --keytab /etc/ztmail/mailer.keytab --principal mailer@CORP.EXAMPLE.COM \
  -f automation@corp.example.com -oi -t < message.eml
```

Without `--principal`, distinct keytab principals in the selected realm are
tried in file order. Multiple encryption keys for one identity count as one
candidate. Selection requires credential acquisition and an SMTP service
ticket; by default it also requires an authenticated LDAP lookup with a valid,
unique canonical mail address. Failed attempts are cleaned up before trying
the next candidate. Skipped identities produce warnings; if all fail, the
error retains every failure. Capacity, owner-close, cleanup failure, or the
overall deadline stops probing. SMTP submission itself is never replayed.

An explicit principal disables probing other identities. Its realm must match
`--realm` or the inferred realm. Principals in other realms are not tried:
the combined AD client is scoped to one domain/realm. Use AES-enabled AD
accounts; software SMTP contexts support AES128/AES256 RFC 4121 wrap tokens,
not legacy RC4/DES tokens.

**No krb5.conf is required or read.** `KRB5_CONFIG` is ignored and the former
`--krb5-config` flag is removed. The SDK discovers KDCs through its AD DNS path
and owns its in-memory ticket configuration and cache. ztmail never launches
external `kinit` commands, writes a keytab, exports a TGT, or writes an external
credential cache. DNS and Kerberos clock synchronization must work.

### Linux, macOS, or Windows: existing FILE credential cache

```sh
./dist/ztmail-linux-amd64 --ccache /path/to/existing.ccache -oi -t < message.eml
```

`--ccache` is an alternative to `--keytab`, not an output file. Optional `FILE:`
prefixes are accepted; relative paths are resolved before passing them to the
SDK. Linux and macOS default to `KRB5CCNAME` or `/tmp/krb5cc_<uid>` when no keytab is
specified. Explicit cache mode on Windows requires `--ccache` or `KRB5CCNAME`.
Only FILE caches are supported, not DIR, KCM, or KEYRING. An external provisioner
must supply a valid cache with an unexpired TGT. It is read-only and is not
renewed. Its default principal is the authenticated identity; an optional
`--principal` constrains that identity rather than switching it.

Protect keytabs and caches as credentials. The SDK applies bounded private-file
reads; on Linux use owner-private regular files (for example mode `0600`).
Cache/keytab identities must match the selected AD realm; arbitrary cross-realm
and directory referral routing are not inferred.

### Windows: integrated SSPI

Windows defaults to the logged-in user's credentials, with no keytab or cache:

```powershell
Get-Content -Raw .\message.eml | .\dist\ztmail-windows-amd64.exe -oi -t
Get-Content -Raw .\message.eml | .\dist\ztmail-windows-amd64.exe `
  --auth sspi --domain corp.example.com --relay relay.corp.example.com -t
```

For byte-preserving file redirection on Windows, use Command Prompt:

```bat
dist\ztmail-windows-amd64.exe --auth sspi -oi -t < message.eml
```

The SDK obtains the current Windows logon principal through SSPI and uses it
for both LDAP and SMTP Kerberos authentication. `--principal`, if supplied,
must match that identity. `--realm` constrains the identity/domain rather than
switching Windows identities or overriding Windows ticket routing.
Verified SMTP TLS state is passed to the SDK for SSPI channel binding.
No NTLM fallback occurs. Windows SSPI requires an appropriate domain logon,
reachable domain controllers, and the registered SMTP SPN.

`--auth auto` chooses an explicit keytab first, then an explicit cache, then
Windows SSPI or the non-Windows default FILE cache. Use `--auth keytab|ccache|sspi` to
require a backend. Explicit backends never silently fall back on failure.

### Opt-in password fallback

```sh
./dist/ztmail-linux-amd64 --password-prompt -oi -t < message.eml
# Pin the password identity instead of accepting an editable guess:
./dist/ztmail-linux-amd64 --password-prompt \
  --principal alice@CORP.EXAMPLE.COM -oi -t < message.eml
```

`--password-prompt` requires `--auth auto`. It first tries the configured keytab
(including its principal candidates), then a configured/default FILE cache,
then Windows SSPI. Only if those methods fail does it prompt for a password.
Successful earlier methods never prompt. With this flag, both `--keytab` and
`--ccache` may be provided to try them in that order; without it, the original
mutually exclusive, no-fallback source policy remains unchanged.

The prompt shows a guessed `current-user@REALM` principal. Press Enter to accept
it or type a replacement account, optionally including `@REALM`. An explicit
`--principal` is shown and enforced without offering interactive replacement.
The password principal must remain in the configured/discovered realm; use
`--realm` to select a different AD realm before starting the program.

Credentials are read from the controlling terminal (`/dev/tty` on Linux/macOS,
`CONIN$`/`CONOUT$` on Windows), never from message stdin. Password echo is disabled;
passwords are not accepted in command-line flags or printed in logs. A missing
terminal, EOF, an empty password, or failed authentication produces an explicit
error. There are no automatic password retries, avoiding repeated lockout-prone
attempts. Fatal cancellation, credential-capacity, or cleanup errors stop fallback.

The AD SDK obtains a TGT from the supplied password, then obtains SMTP/LDAP
service tickets and performs the same canonical-mail lookup and SMTP GSSAPI
authentication. No external commands or credential-cache writes are used.
The prompt byte buffer is cleared after use. The SDK retains an in-memory Go
password string for on-demand TGT reacquisition until its credential owner closes;
Go does not guarantee zeroization of immutable strings or runtime copies.

Interactive input does not consume the network timeout. With
`--password-prompt`, `--timeout` applies separately to each existing credential
source stage, the password-based AD stage, and SMTP submission. Cancellation is
checked before and after terminal reads; an already-blocked terminal read may
need input/EOF to return. Without the flag, the existing overall AD/SMTP timeout
is unchanged.

## Canonical sender

By default, the selected principal is looked up through authenticated,
certificate-verified LDAP TLS using `adclient.Search`. The base comes from
verified RootDSE `defaultNamingContext`, never from an assumed DN.
The search matches `userPrincipalName` plus `sAMAccountName` for simple
principals, or `servicePrincipalName` for service principals. LDAP filter values
are escaped; absent, ambiguous, incomplete, or failed searches are errors.

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

`-f address` explicitly overrides both envelope and From/Sender, and skips
canonical mail lookup (useful for service accounts without mailboxes).
`-f '<>'` retains a null envelope sender and preserves the original sender
headers. Override addresses are still validated, and gateway relay permissions
still apply. Use `--ldap-ca bundle.pem` to add enterprise LDAP trust anchors;
there is no LDAP certificate-verification bypass.

## Sendmail compatibility

Input is a complete RFC 5322 message on stdin, with a blank line separating
headers and body. `Date`, `Message-ID`, and MIME content must be supplied by the
caller. From/Sender rewriting follows the policy above.

For interactive input, press Enter twice after the last header to insert that
blank line, then type the body and finish with a line containing only `.`:

```text
Subject: test

This is a testmail
.
```

Without the blank line, body text is interpreted as another header. A formatting
error reports the offending line and how to correct it; the message is rejected
locally before any AD authentication or SMTP submission.

```sh
printf 'From: Alice <alice@corp.example.com>\nTo: bob@corp.example.com\nSubject: Test\n\nHello\n' |
  ./dist/ztmail-linux-amd64 -oi -t
```

- Positional arguments are envelope recipients; unqualified CLI addresses
  such as `bob` are qualified with the host domain.
- `-t` adds recipients from `To`, `Cc`, and `Bcc`. When Resent fields exist,
  only the newest contiguous Resent block's recipients are selected.
  Header recipient syntax must use complete RFC mailbox addresses.
- All `Bcc` and `Resent-Bcc` fields, including folded continuation lines, are
  removed from the transmitted message even without `-t`. Other header bytes
  (except From/Sender) and body content are preserved, apart from SMTP
  line-ending normalization.
- CLI and header recipients are combined and exact duplicates are removed.
- `-f address` overrides both the envelope sender and message From/Sender.
  `-f '<>'` sends a null envelope sender without rewriting sender headers.
- `-i` or legacy `-oi` preserves lone-dot lines; otherwise a line containing
  only `.` terminates input. SMTP dot-stuffing is handled automatically.
- `-F name` is accepted for caller compatibility, but does not change headers.
- `-v` prints status to stderr, never the message or authentication tokens.
- `--` ends flag processing, as in other Cobra commands.

Only the documented sendmail subset is implemented. Queue management,
daemon modes, aliases, local delivery, DSNs, arbitrary `-o` options, and a local
retry spool are not implemented. Unknown options fail rather than being ignored.
The tool is not a setuid program or a complete drop-in MTA replacement.

## Transport and failure behavior

The relay must advertise **AUTH GSSAPI** after TLS. Mutual Kerberos
authentication and the signed SASL security-layer negotiation are mandatory.
The client selects the SASL **no security layer** option; TLS protects the
subsequent SMTP envelope and message. Relays requiring a SASL
integrity/confidentiality layer rather than TLS are not supported.

- Default: `--tls required` (STARTTLS); no downgrade if unavailable.
- Port 465: `--tls implicit --port 465`.
- Explicit opt-out: `--tls off`. This authenticates with Kerberos but exposes
  the message and envelope in plaintext; only use on a suitably protected network.
- Uses system-trusted CA certificates; there is no certificate-verification bypass.
- `--timeout 60s` bounds AD discovery, principal probing, mail lookup, and SMTP
  submission after stdin has been read. Individual SDK operations also have
  their own bounded timeouts. Opt-in password fallback uses the per-stage
  timeouts described above. Cleanup has a separate five-second bound.

Exit status is zero only after the relay confirms DATA acceptance; it is nonzero
for validation, credential, authentication, recipient, or submission failures.
All recipients must be accepted before DATA is sent. A failed QUIT or credential
cleanup after confirmed acceptance produces a warning, not a retry-inducing
failure. A lost connection during DATA/final acknowledgement can leave delivery
uncertain; the error says so. There are no automatic retries.

Tests cover argument validation, message privacy, Resent handling, domain
parsing, ordered principal probing, source configuration, canonical mail lookup,
sender rewriting and overrides, SDK GSSAPI delegation, and a local SMTP protocol
exchange. Cryptographic and native credential operations belong to the SDK.
Tests do not replace an end-to-end check against your AD KDC, protected LDAP
service, and GSSAPI-enabled SMTP gateway.
Windows SSPI must also be exercised on a domain-joined Windows machine.
