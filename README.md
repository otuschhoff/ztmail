# ztmail

A sendmail-style SMTP submission client written in Go, using Cobra and
Kerberos **SASL GSSAPI** (RFC 4752). Builds for Linux and Windows without CGO.
It does not use passwords, NTLM, HTTP Negotiate, or anonymous SMTP fallback.

## Build

Requires Go 1.24 or later. On Linux, `make build` produces:

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

The requested [github.com/otuschhoff/gokrb5](https://github.com/otuschhoff/gokrb5)
fork retains the `gopkg.in/jcmturner/gokrb5.v7` module/import path.
`go.mod` pins that fork via `replace`; it is not using an unmodified upstream
Kerberos implementation. Windows integrated authentication uses
[alexbrainman/sspi](https://github.com/alexbrainman/sspi)'s **Kerberos** package,
not its NTLM-capable Negotiate package.

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
| Envelope sender | Current OS user at the host DNS domain |

Discovery uses the host FQDN, then its DNS canonical name. Linux additionally
uses the first suffix from the last `search`/`domain` directive in
`/etc/resolv.conf`; Windows reads the machine's primary DNS suffix using
`GetComputerNameExW`, not the logged-in user's domain. Search suffixes and DNS
aliases are heuristics: specify `--domain` on multihomed hosts, containers, or
machines whose resolver search domain differs from their AD domain.
Discovery fails explicitly if no domain is available.

Override with `--domain`, `--realm`, `--relay`, `--port`, `--hostname` (EHLO),
and/or `--spn`. The relay must be a DNS hostname, not a URL, IP literal, or
`host:port`. The SPN must be registered to the relay's AD service account;
an alias may require an explicit `--spn`.

## Credentials

### Linux: existing Kerberos ticket

```sh
kinit alice@CORP.EXAMPLE.COM
./dist/ztmail-linux-amd64 -oi -t < message.eml
```

By default, Linux reads `KRB5CCNAME`, falling back to `/tmp/krb5cc_<uid>`.
Only a **FILE** credential cache is supported; DIR, KCM, and KEYRING caches
must first be exported/replaced with a FILE cache:

```sh
KRB5CCNAME=FILE:/tmp/ztmail.ccache kinit alice@CORP.EXAMPLE.COM
./dist/ztmail-linux-amd64 --ccache /tmp/ztmail.ccache -t < message.eml
```

The cache must contain a valid TGT. Its principal is used as-is, including for
cross-realm clients; `--realm` does not change the cached identity.
Expired caches are not renewed automatically.

### Linux or Windows: keytab

```sh
./dist/ztmail-linux-amd64 \
  --keytab /etc/ztmail/mailer.keytab \
  --principal mailer@CORP.EXAMPLE.COM \
  -f automation@corp.example.com recipient@corp.example.com < message.eml
```

`--principal` is optional if the keytab contains exactly one distinct principal
in the selected realm (multiple encryption keys for that identity are fine).
Otherwise specify it explicitly. Its realm must match `--realm` or the inferred
realm. Protect keytabs and caches as credentials. Use AES-enabled AD accounts:
the pure-Go SASL wrap implementation supports RFC 4121 integrity tokens, not
legacy RC4/DES GSSAPI tokens. Kerberos FAST is disabled for AD interoperability.

Config precedence is `--krb5-config`, `KRB5_CONFIG` (a single file), then
`/etc/krb5.conf`. If the default file is absent, an in-memory configuration
uses the inferred realm and DNS SRV KDC discovery (`_kerberos._udp`/`_tcp`).
Explicitly selected missing or malformed files cause errors. Existing config
KDC entries and DNS settings are preserved; the selected AD realm and domain
mapping are applied. Realm/KDC DNS and clock synchronization must work.

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

SSPI obtains the Kerberos service ticket from the Windows logon session and
Windows manages KDC/realm routing. `--realm` does not switch Windows identities
or override SSPI's ticket routing. `--krb5-config` is rejected with SSPI.
No NTLM fallback occurs. Windows SSPI requires an appropriate domain logon,
reachable domain controllers, and the registered SMTP SPN.

`--auth auto` chooses an explicit keytab first, then an explicit cache, then
Windows SSPI or Linux's default FILE cache. Use `--auth keytab|ccache|sspi` to
require a backend. Explicit backends never silently fall back on failure.

## Sendmail compatibility

Input is a complete RFC 5322 message on stdin, with a blank line separating
headers and body. Headers such as `From`, `Date`, `Message-ID`, and MIME content
must be supplied by the caller; this tool does not generate or rewrite them.

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
  and body content are preserved, apart from SMTP line-ending normalization.
- CLI and header recipients are combined and exact duplicates are removed.
- `-f address` selects the envelope sender. `-f '<>'` sends a null sender.
  The message's `From` header remains unchanged.
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
- `--timeout 60s` bounds the entire SMTP connection/exchange. Host DNS discovery
  has a separate five-second lookup timeout; KDC operations use library timeouts.

Exit status is zero only after the relay confirms DATA acceptance; it is nonzero
for validation, credential, authentication, recipient, or submission failures.
All recipients must be accepted before DATA is sent. A failed QUIT or credential
cleanup after confirmed acceptance produces a warning, not a retry-inducing
failure. A lost connection during DATA/final acknowledgement can leave delivery
uncertain; the error says so. There are no automatic retries.

Tests cover argument validation, message privacy, Resent handling, discovery
parsing, keytab selection, AES wrap checksums/rotation/sequences, AP-REP timestamp
validation, SASL negotiation, and a local SMTP protocol exchange. Tests do not
replace an end-to-end check against your AD KDC and GSSAPI-enabled SMTP gateway.
Windows SSPI must also be exercised on a domain-joined Windows machine.
