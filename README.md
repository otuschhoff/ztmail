# ztmail

## Objective

Submit email to an Active Directory mail gateway using **Kerberos SASL GSSAPI**
with a sendmail-style command-line interface.

ztmail discovers the host's AD domain, authenticates with a keytab, an existing
FILE credential cache, or Windows SSPI, and normally rewrites the sender to the
authenticated principal's canonical AD mailbox. No `krb5.conf`, external `kinit`,
or credential-cache writes are required. Password prompting is opt-in.

The application builds for Linux, Windows and macOS without CGO. On Linux,
eligible pre-submission failures can use the host's own sendmail. It is not a
complete MTA and has no queue of its own; it does not use NTLM or anonymous
SMTP fallback.

[Get a release binary](https://github.com/otuschhoff/ztmail/releases) or follow
the [build guide](docs/build.md).

## Use cases

- **Scripts and scheduled jobs:** submit an existing RFC 5322 message from
  stdin using the familiar `-oi`, `-t`, `-f` and recipient arguments.
- **AD service accounts:** authenticate with a keytab, automatically select a
  usable principal, and use its canonical mailbox or an explicit sender.
- **Windows domain users:** use the logged-in user's Kerberos credentials
  through SSPI without configuring a keytab or cache.
- **Interactive users:** use an existing credential cache, optionally prompt
  for a password, and save a preferred sender for later submissions.
- **Troubleshooting:** test AD/TLS/GSSAPI authentication without sending email,
  or send a diagnostic email with human-readable tables and a JSON attachment.
- **Go applications:** submit mail through an application-owned AD client
  using the [library API](docs/library.md), without CLI prompting or native
  sendmail fallback.

## Typical usage

Examples below assume the downloaded executable is available as `ztmail`.
On Linux/macOS, mark the binary executable with `chmod +x` before using it.
Windows examples use the executable under `dist`.

### Prerequisites and defaults

The normal AD submission path needs working AD DNS and clock synchronization,
usable Kerberos credentials, and a gateway advertising AUTH GSSAPI. The gateway
must have a registered SMTP SPN and a system-trusted TLS certificate.

For a host named `worker.corp.example.com`:

| Setting | Default |
| --- | --- |
| AD domain / realm | `corp.example.com` / `CORP.EXAMPLE.COM` |
| Relay / port | `mailgw.corp.example.com` / `25` |
| SMTP SPN | `smtp/mailgw.corp.example.com` |
| Transport | Verified STARTTLS; TLS 1.2 or newer |
| Sender | Explicit `-f`, then saved default, then canonical AD mailbox |

Use `--domain corp.example.com` when the host's DNS suffix does not identify
its AD domain, particularly in containers or on multihomed machines.

### Submit a message on Linux or macOS

Input is a complete RFC 5322 message. Include a blank line between headers and
body; supply Date, Message-ID and MIME headers yourself when needed.

```sh
ztmail -oi -t < message.eml

# Authenticate with a service-account keytab:
ztmail --keytab /etc/ztmail/mailer.keytab -oi -t < message.eml

# Use an existing, read-only FILE credential cache:
ztmail --ccache /path/to/existing.ccache -oi -t < message.eml

# Supply envelope recipients explicitly:
ztmail --keytab /etc/ztmail/mailer.keytab -oi recipient@example.com < message.eml
```

Without an explicit keytab/cache, Linux and macOS use `KRB5CCNAME` or
`/tmp/krb5cc_<uid>`. Only FILE caches with an unexpired TGT are supported.
Protect keytabs and caches as credentials; on Linux use owner-private files.

`-t` reads recipients from To/Cc/Bcc or the latest Resent block. Without
recipient arguments, headers are read automatically. Bcc headers are removed
before submission. If neither arguments nor headers provide recipients,
the authenticated user's canonical AD mailbox is required.

`-oi` (or `-i`) preserves dot-only body lines. Without it, a line containing
only `.` terminates input. Ctrl+C cancels incomplete message input without
submitting it.

### Submit using Windows SSPI

Windows defaults to the logged-in user's SSPI credentials. Use Command Prompt
redirection for byte-preserving input:

```bat
dist\ztmail-windows-amd64.exe -oi -t < message.eml
```

PowerShell can also supply text input:

```powershell
Get-Content -Raw .\message.eml | .\dist\ztmail-windows-amd64.exe -oi -t
```

The Windows logon must be suitable for Kerberos authentication to the AD
domain. SSPI does not fall back to NTLM.

### Test authentication or send a diagnostic report

```sh
# Authenticate and check TLS without reading stdin or sending email:
ztmail --test
ztmail --test --keytab /etc/ztmail/mailer.keytab

# Add observed DC activity, runtime, crypto and validity tables:
ztmail --test --debug

# Send a generated report to your canonical AD mailbox or an explicit recipient:
ztmail --testmail --debug
ztmail --testmail --debug recipient@example.com
```

`--test` accepts no recipients and never sends MAIL FROM, RCPT TO or DATA.
`--testmail` reads no stdin and always attaches `ztmail-report.json`, alongside
text and HTML report bodies. `--test` and `--testmail` are mutually exclusive.
Neither mode uses Linux native-sendmail fallback.

Reports contain account names, credential paths, queried DNS names and internal
topology. Review them before sharing. See the
[diagnostics guide](docs/diagnostics.md) for table meanings, timing limitations,
crypto estimates and the JSON schema.

### Select or save a sender

```sh
# Override the sender for one submission:
ztmail -f automation@example.com -oi -t < message.eml

# Set a default manually or fetch your canonical address once from AD:
ztmail --set-default-from alice@example.com
ztmail --set-default-from-ad

ztmail --show-default-from
ztmail --unset-default-from
```

`-f` wins over the saved default; either replaces the normal canonical sender
and rewrites From/Sender headers. `-f '<>'` uses a null envelope and preserves
the original sender headers.

The saved address is plaintext under Linux XDG configuration, Windows AppData,
or macOS Application Support; it contains no credentials. Manual management
does not read stdin or contact AD. AD-based setting permits password prompting
if existing credentials are unavailable, and does not need a reachable gateway.

Host/computer accounts without an AD mailbox may authenticate with a warning.
For testmail, specify a non-null sender with `-f` or a saved default; if no
recipient is supplied and the host has no mailbox, that configured sender is
also the report recipient. Normal submissions still need a sender and
explicit/header recipients when the host has no mailbox.

See [saved default sender](docs/advanced-usage.md#saved-default-sender) for exact
paths, management constraints and error handling.

### Allow an interactive credential prompt

```sh
ztmail --password-prompt -oi -t < message.eml
ztmail --password-prompt --principal alice@CORP.EXAMPLE.COM -oi -t < message.eml
```

Existing credentials are tried first; the password is read from the controlling
terminal, never message stdin. Normal sends do not prompt automatically.
`--password-prompt` requires `--cred-source auto`. See
[password fallback](docs/advanced-usage.md#opt-in-password-fallback) for source
order and timeout behavior.

### Understand acceptance and Linux fallback

On Linux, native-sendmail fallback is enabled for unavailable credentials,
undiscoverable host AD domain, or relay DNS/TCP failures. A warning identifies
fallback. Without credentials or a sender override, original sender headers
are preserved rather than using a guessed AD mailbox.

```sh
# Require the AD gateway path, with no native fallback:
ztmail --no-sendmail-fallback -oi -t < message.eml

# Select the host MTA executable explicitly:
ztmail --sendmail-path /usr/sbin/sendmail -oi -t < message.eml
```

Fallback never follows TLS/SMTP authentication rejection, uncertain submission,
caller cancellation, or fatal credential lifecycle errors. It is Linux
CLI-only, not a Windows/macOS or library feature. See
[native fallback details](docs/advanced-usage.md#linux-host-sendmail-fallback).

**Acceptance is not mailbox delivery.** Exit zero means the relay confirmed
DATA acceptance or native sendmail exited zero. If an error says delivery is
uncertain, check the relay/local MTA before retrying; ztmail never automatically
replays a submission.

## Advanced usage

### Override discovery, identity or transport

```sh
ztmail --domain corp.example.com --realm CORP.EXAMPLE.COM \
  --relay relay.corp.example.com --spn smtp/relay.corp.example.com \
  --keytab /etc/ztmail/mailer.keytab --principal mailer@CORP.EXAMPLE.COM \
  --ldap-ca /etc/ztmail/ad-ca.pem -oi -t < message.eml

# Use implicit TLS on the appropriate relay port:
ztmail --tls implicit --port 465 -oi -t < message.eml

ztmail --help
```

Use a DNS hostname for `--relay`, not a URL, IP literal or `host:port`.
`--hostname` overrides SMTP EHLO. Repeatable `--dns-server IP[:port]` selects
bootstrap resolvers; these are discovery hints, not automatically trusted AD
data servers. `--timeout` defaults to 60 seconds.

STARTTLS is required by default and never silently downgraded. `--tls off`
deliberately exposes the envelope and message in plaintext; use it only on a
suitably protected network. There is no TLS certificate-verification bypass.

### Control LDAP lookup fan-out

Canonical LDAP mail lookup races up to eight discovered DCs by default,
including connection, authentication, RootDSE and the user search. Limit fan-out
with `--ldap-race-candidates 3`, or use `--no-ldap-race` for ordinary SDK server
selection. The Go library preserves ordinary reads unless
`Options.LDAPRaceCandidates` is set. See
[LDAP read racing](docs/advanced-usage.md#ldap-read-racing) for result and
lifetime semantics.

### Detailed documentation

| Guide | Contents |
| --- | --- |
| [Advanced usage reference](docs/advanced-usage.md) | Discovery overrides, credential selection, sender configuration, native fallback, sendmail compatibility and failure semantics |
| [Diagnostics](docs/diagnostics.md) | No-email checks, testmail, JSON tables, DC observations, timings, crypto/validity and sharing precautions |
| [Implementation](docs/implementation.md) | Package layout, submission flow, AD ownership, LDAP canonical-mail lookup and transport safety |
| [mTLS design (proposed)](docs/mtls-design.md) | Certificate-authentication objective, key decisions, compatibility constraints and phased LLM implementation plan |
| [Go library](docs/library.md) | Application-owned AD client example, defaults, concurrency, message/result semantics and no-email testing |
| [Build, test and release](docs/build.md) | Toolchain, private dependencies, platform targets, version metadata, validation and GitHub Actions |

Release history is maintained in [CHANGELOG.md](CHANGELOG.md).
