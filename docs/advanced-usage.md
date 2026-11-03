# Advanced usage reference

[README](../README.md) | [Advanced usage](advanced-usage.md) | [Diagnostics](diagnostics.md) | [Implementation](implementation.md) | [Go library](library.md) | [Build and release](build.md)

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
| Envelope sender and From | Explicit `-f`, saved default, then canonical AD mail |
| DNS bootstrap | OS DNS servers, discovered by adclient |
| DNS diagnostic probe zone | `example.com` (outside the AD domain; used only for eligible `--test` failures) |
| Canonical LDAP read | Immediate racing across up to 8 discovered DCs |

Domain inference uses local host configuration, without ambient DNS queries.
Discovery uses the host FQDN. Linux and macOS additionally
use the first suffix from the last `search`/`domain` directive in
`/etc/resolv.conf`; Windows reads the machine's primary DNS suffix using
`GetComputerNameExW`, not the logged-in user's domain. Search suffixes
are heuristics: specify `--domain` on multihomed hosts, containers, or
machines whose resolver search domain differs from their AD domain.
Discovery fails explicitly if no domain is available.

Override with `--domain`, `--realm`, `--relay`, `--port`, `--hostname` (EHLO),
and/or `--spn`. The relay must be a DNS hostname, not a URL, IP literal, or
`host:port`. The SPN must be registered to the relay's AD service account;
an alias may require an explicit `--spn`.

The SDK discovers AD DNS servers from OS resolver configuration and qualifies
their AD namespace service, then uses that DNS path for DC/KDC and relay
resolution. CLI-owned clients select `QualificationOptimistic`: resolve actual
required internal/external names and alias targets without advance proof of
external recursion. Successful lookups do not trigger synthetic recursion
probes, including during topology refresh. Namespace and response validation
remain enforced. There is no application
`net.DefaultResolver`, alternate LDAP client, or direct Kerberos network client.
Override bootstrap with repeatable `--dns-server IP[:port]` (IPv6 ports require
brackets); this disables OS bootstrap fallback. Configure an external
`--dns-probe-zone` if `example.com` is in your AD domain or unsuitable for your
DNS policy. This zone is used only for optional failure diagnostics in `--test`,
not for normal sends or server admission. Such probes can generate upstream
external DNS traffic. Bootstrap servers are discovery hints, not automatically
trusted AD data servers. Library clients retain the qualification policy and
diagnostic configuration of their application-owned AD client.

## LDAP read racing

The CLI uses the SDK's complete, single-use read racing for canonical mail
lookup by default. Up to eight eligible LDAP DCs are started immediately,
including numeric-address connection, verified TLS, GSSAPI bind, RootDSE and
user search. Each candidate obtains its own verified `defaultNamingContext`;
its scoped user lookup stays on that same DC. Fewer candidates are used when
discovery/admission supplies fewer servers.

```sh
# Reduce the maximum concurrent DC candidates (accepted range: 1-8):
ztmail --ldap-race-candidates 3 -oi -t < message.eml

# Keep ordinary SDK LDAP selection and session reuse instead:
ztmail --no-ldap-race -oi -t < message.eml
```

The first complete lookup wins, including a complete "not found" or ambiguous
result. ztmail does not hunt for a favorable replica, merge entries, chase
referrals, or accept partial pages. Unsupported critical naming-context controls
remain errors; protection is never silently removed. Losers are canceled and
drained, and the racing view is closed before lookup returns. Cleanup failures
are returned explicitly. Racing increases cold connection/authentication
fan-out, not the number of SMTP submissions or the existing Kerberos race limit.

This applies to normal sends, `--test`, `--testmail`, and
`--set-default-from-ad` whenever canonical mail is needed. An explicit/saved
sender skips LDAP only when the authenticated user's own recipient address is
not needed. There is no race or LDAP network I/O for a skipped lookup.
The Go library is opt-in: `Options.LDAPRaceCandidates: 0` preserves ordinary
reads; values 1-8 enable the same helper. See [library ownership](library.md#ownership-defaults-and-concurrency).

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
  --cred-source sspi --domain corp.example.com --relay relay.corp.example.com -t
```

For byte-preserving file redirection on Windows, use Command Prompt:

```bat
dist\ztmail-windows-amd64.exe --cred-source sspi -oi -t < message.eml
```

The SDK obtains the current Windows logon principal through SSPI and uses it
for both LDAP and SMTP Kerberos authentication. `--principal`, if supplied,
must match that identity. `--realm` constrains the identity/domain rather than
switching Windows identities or overriding Windows ticket routing.
Verified SMTP TLS state is passed to the SDK for SSPI channel binding.
No NTLM fallback occurs. Windows SSPI requires an appropriate domain logon,
reachable domain controllers, and the registered SMTP SPN.

`--cred-source auto` chooses an explicit keytab first, then an explicit cache, then
Windows SSPI or the non-Windows default FILE cache. Use `--cred-source keytab|ccache|sspi` to
require a backend. Explicit backends never try other credential backends on
failure; eligible Linux CLI failures may instead use the documented native
sendmail path with a warning.

### Opt-in password fallback

```sh
./dist/ztmail-linux-amd64 --password-prompt -oi -t < message.eml
# Pin the password identity instead of accepting an editable guess:
./dist/ztmail-linux-amd64 --password-prompt \
  --principal alice@CORP.EXAMPLE.COM -oi -t < message.eml
```

`--password-prompt` requires `--cred-source auto`. It first tries the configured keytab
(including its principal candidates), then a configured/default FILE cache,
then Windows SSPI. Only if those methods fail does it prompt for a password.
Successful earlier methods never prompt. With this flag, both `--keytab` and
`--ccache` may be provided to try them in that order; without it, the original
mutually exclusive, no-fallback source policy remains unchanged.

When password fallback succeeds, its introductory notice is sufficient:
earlier credential-source failures are not repeated as failures/warnings in
the concise report or normal send output. Use `--verbose` for those details.
If password fallback fails, the original source errors remain part of the final
error. Unrelated warnings and later SMTP/cleanup failures are still reported.

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

## Sender configuration

Sender precedence is explicit `-f` > saved default > canonical AD mail. The
selected mailbox becomes the envelope sender and From/Sender headers.
`-f '<>'` preserves the original sender headers and uses a null envelope.
An override skips canonical lookup only when recipients are already known;
self-recipient fallback always requires the authenticated canonical mailbox.
For LDAP lookup, primary-address selection and rewriting details, see
[the implementation guide](implementation.md#canonical-sender-lookup-and-rewriting).

### Saved default sender

```sh
ztmail --set-default-from alice@example.com
ztmail --set-default-from-ad
ztmail --show-default-from
ztmail --unset-default-from
```

The address is stored as one plaintext mailbox plus a newline in
`$XDG_CONFIG_HOME/ztmail/default-from.txt` on Linux, defaulting to
`~/.config/ztmail/default-from.txt`. Windows uses
`%APPDATA%\ztmail\default-from.txt`; macOS uses
`~/Library/Application Support/ztmail/default-from.txt`.
The file contains no credentials. New directories/files use user-only Unix
permissions, and writes use a temporary file in the same directory before
replacement. Setting again replaces the old default; unsetting a missing file
is harmless. Malformed or unreadable files are errors rather than silently
ignored. Explicit `-f` bypasses reading the saved file.

Manual set, show and unset do not read message stdin or contact AD/the relay.
`--set-default-from-ad` looks up the canonical mailbox once and stores it only
after successful lookup and credential cleanup. It uses `--cred-source auto`
and automatically permits password prompting if existing keytab/cache/SSPI
credentials are unavailable; `--keytab`, `--ccache`, `--principal`, `--domain`,
`--realm`, `--dns-server` and `--ldap-ca` apply as usual. This action obtains
only the tickets needed by LDAP, not an SMTP ticket, and does not contact the
mail gateway. Normal submissions still never prompt unless
`--password-prompt` is explicitly supplied.

The saved address is a sender override, not an authenticated identity or a
self-recipient substitute. It skips canonical LDAP lookup only when recipients
are already known; the user's canonical AD mailbox is still required for
self-recipient fallback. Management actions are mutually exclusive and cannot
be combined with recipients, `-f`, `-t`, `--test`, `--testmail` or `--debug`.

### Linux host-sendmail fallback

For normal Linux submissions, fallback is enabled by default when no usable
credentials can be acquired, the host AD domain cannot be discovered, or relay
DNS lookup/TCP connection fails. Disable it with `--no-sendmail-fallback`.
`--sendmail-path /absolute/path/to/sendmail` explicitly selects the native
executable; otherwise ztmail tries `/usr/sbin/sendmail`, `/usr/lib/sendmail`,
`/sbin/sendmail`, then `/usr/libexec/sendmail`. It never searches `PATH`, and
rejects its own executable, including symlink/hardlink aliases, to prevent
recursion when installed under the name sendmail. A child-process environment
guard also prevents recursive fallback through separately installed copies.

Fallback never follows SMTP/TLS/authentication rejection, uncertain DATA,
credential-owner cleanup/capacity errors, caller cancellation, or AD
configuration/post-acquisition errors. A failed explicitly requested password
prompt/authentication also remains an error. If any credential attempt has
already failed after acquisition, earlier missing-credential errors do not
make fallback eligible. `--test`, `--testmail`, AD-default management, Windows,
macOS and the Go library never use this fallback.

The same message validation, dot-input handling, recipient extraction and
Bcc stripping run before native submission. Without credentials, no canonical
AD sender is guessed: original From/Sender are preserved unless `-f` or a
saved default explicitly selects a rewrite. A known canonical sender is
retained when only the relay is unreachable. `-f '<>'` always preserves headers
and is forwarded as a null envelope sender.

Native sendmail receives `-i`, an optional `-f`, `--` and the validated
recipients, not `-t`; the already-prepared message goes directly to its stdin
without a shell. If the host domain is unknown, simple local aliases such as
`root` are permitted in recipient arguments; otherwise unqualified arguments
retain their normal AD-domain qualification. Headers require full mailbox
addresses. File, pipe and include recipients are rejected. With neither
explicit/header recipients nor an authenticated canonical mailbox, fallback
fails rather than inventing a self-recipient. Use a fully qualified sender
override if the host domain cannot be discovered.

A warning identifies native fallback. The process gets a fresh `--timeout`
budget, but caller cancellation/deadlines still apply. Exit zero means the
host MTA accepted the message, possibly into its queue, not that a mailbox
received it. Failure after native process startup is conservatively reported
as uncertain: check local MTA logs/queue before retrying. Native failure retains
the original AD/relay error. ztmail never submits again automatically.

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

Press Ctrl+C to cancel while waiting for message input, including when started
without arguments or when a pipe remains open. The CLI exits with an error
without acquiring credentials or submitting a partially entered message.

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
- Without positional recipients, headers are read automatically as with `-t`.
  If neither supplies recipients, the authenticated user's canonical AD mail
  becomes the recipient, independently of any sender override. A missing or
  invalid canonical address fails explicitly. Test mode still sends no mail.
- With `-t`, CLI and header recipients are combined; exact duplicates are removed.
- `-f address` overrides both the envelope sender and message From/Sender.
  `-f '<>'` sends a null envelope sender without rewriting sender headers.
- `-i` or legacy `-oi` preserves lone-dot lines; otherwise a line containing
  only `.` terminates input. SMTP dot-stuffing is handled automatically.
- `-F name` is accepted for caller compatibility, but does not change headers.
- `-v` prints status to stderr, never the message or authentication tokens.
- `--` ends flag processing, as in other Cobra commands.

Only the documented sendmail subset is implemented. Native Linux fallback
delegates to a separately installed MTA; ztmail itself implements no queue management,
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

Exit status is zero only after the relay confirms DATA acceptance or, on eligible
Linux fallback, host sendmail exits zero. It is nonzero for unrecovered
validation, credential, authentication, recipient, or submission failures.
All recipients must be accepted before DATA is sent. A failed QUIT or credential
cleanup after confirmed acceptance produces a warning, not a retry-inducing
failure. A lost connection during DATA/final acknowledgement can leave delivery
uncertain; the error says so. There are no automatic retries.
