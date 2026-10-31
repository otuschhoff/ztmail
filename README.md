# ztmail

A sendmail-style SMTP submission client written in Go, using Cobra and
Kerberos **SASL GSSAPI** (RFC 4752). Builds for Linux and Windows without CGO.
It does not use passwords, NTLM, HTTP Negotiate, or anonymous SMTP fallback.

## Build

Requires Go 1.26 or later; the module selects toolchain Go 1.26.9.
On Linux, `make build` produces:

- `dist/ztmail-linux-amd64`
- `dist/ztmail-windows-amd64.exe`

Alternatively, cross-compile directly (PowerShell users can set the environment
variables using `$env:GOOS`, `$env:GOARCH`, and `$env:CGO_ENABLED`):

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/ztmail-linux-amd64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o dist/ztmail-windows-amd64.exe .
# ARM64: substitute GOARCH=arm64 and use an appropriately named output file.
make test
```

All DNS, Kerberos, and LDAP queries use the combined
[`github.com/otuschhoff/adbind/ad/adclient`](https://github.com/otuschhoff/adbind)
SDK. The application owns one selected AD client and borrows its DNS and
credential lease; SMTP connections are made only to numeric IPs returned by
that client. GSSAPI setup, mutual authentication, signed SASL negotiation, and
Windows SSPI are delegated to the SDK. It uses
`github.com/otuschhoff/gokrb5/v8`, not the former v7 replacement.

The SDK is pinned to revision `cb6973368047`, which adds external credential
sources and OS DNS bootstrap. The repository is private: configure GitHub
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
Discovery uses the host FQDN. Linux additionally
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

## Credentials

### Linux or Windows: keytab

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

### Linux or Windows: existing FILE credential cache

```sh
./dist/ztmail-linux-amd64 --ccache /path/to/existing.ccache -oi -t < message.eml
```

`--ccache` is an alternative to `--keytab`, not an output file. Optional `FILE:`
prefixes are accepted; relative paths are resolved before passing them to the
SDK. Linux defaults to `KRB5CCNAME` or `/tmp/krb5cc_<uid>` when no keytab is
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
Windows SSPI or Linux's default FILE cache. Use `--auth keytab|ccache|sspi` to
require a backend. Explicit backends never silently fall back on failure.

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
  their own bounded timeouts. Cleanup has a separate five-second bound.

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
