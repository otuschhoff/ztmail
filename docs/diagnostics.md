# Authentication and diagnostic reports

[README](../README.md) | [Advanced usage](advanced-usage.md) | [Diagnostics](diagnostics.md) | [Implementation](implementation.md) | [Go library](library.md) | [Build and release](build.md)

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

SMTP authentication is successful only after GSSAPI mutual authentication,
signed SASL negotiation, and the relay's final `235` response. A GSSAPI step
that produces no output token still requires an empty SMTP continuation; it
must not terminate AUTH early. A final `535` is reported as an authentication
failure, not as a QUIT failure.

The report is written to stderr as a rounded go-pretty key/value table:
Hostname, Target relay (including port), AD domain, User, Mail (from),
Cred source, Authentication method, SPN, Transport security,
Authentication, and Total runtime. The method is currently `GSSAPI`; User,
Cred source and SPN are shown only for GSSAPI. This does not enable mTLS
authentication.
For keytab and FILE-cache credentials, the CLI includes the resolved file path
in Cred source, for example `ccache (/tmp/krb5cc_1000)`. This includes the default
or environment-selected cache path. Borrowed library owners do not expose their
credential file paths through the identity API, so library reports omit them.
The table has no redundant column-header row. Successful authentication displays
`OK`; healthy transport displays
`OK (CN=smtp.corp.example; +69 days; TLS1.3 ~112bit)`.
The trailing rating is a conservative classical key-strength estimate based on
the weakest observable cipher, key exchange, certificate-chain key or certificate
signature. For example, RSA-2048 limits the estimate to 112 bits even with
AES-256. Missing or unsupported required metadata produces `strength unavailable`.
RSA/ECC tiers follow [NIST SP 800-57 Part 1 Rev. 5, Tables 2-3](https://doi.org/10.6028/NIST.SP.800-57pt1r5);
intermediate RSA sizes round down to a published tier.
This is not NIST certification, a post-quantum rating, or a full protocol-security
assessment. Hybrid key exchange is rated on its classical component only.
TLS handshake signature schemes are not exposed by Go and are not assessed;
the estimate is not a bound on per-record authentication or message-volume risks.
The remaining leaf-certificate lifetime uses whole days, hours or minutes,
with a leading `+`, or `+<1 minute`. Certificate validation
still uses the relay hostname/SANs, not the displayed CN. Certificates without a
CN display `CN unavailable`. On colour-enabled terminals only `OK` is bold green;
the CN retains normal text colour. AD-domain suffixes (including the leading
`.` or `@`, case-insensitive) in hostnames, UPNs, and mail addresses are grey.
Unreached values are marked unavailable rather than guessed. Total runtime is
elapsed wall-clock time through test/credential cleanup, before report rendering.
If the CLI actually prompted for a password, **Execution runtime** appears
immediately after **Total runtime**. It is elapsed wall-clock time minus the
principal/password prompt interval, not CPU time. Credential acquisition,
local user lookup and AD setup still count as execution. Prompt duration is
captured even without `--debug`; testmail text, HTML and JSON use the same
prompt-excluded snapshot value.
Failed checks, skipped protection, supplementary diagnostics, and warnings are
shown separately. Authentication acceptance does not hide a later cleanup/test
failure. No email is sent.

Use `--test --debug` for additional tables containing observed DC service
activity matched against discovered advertisements, observed LDAP/Kerberos
reachability and average completed-exchange response times, and SDK/application
runtime breakdown for DNS, Kerberos credentials/tickets, LDAP, SMTP handshake,
SMTP auth, SMTP QUIT, cleanup, host/domain discovery, local user lookup,
credential prompting, report preparation/output, AD setup/orchestration, and
other/untracked. Runtime breakdown rows below 0.1 ms are omitted.
When visible, **Credential prompting** is the first runtime category, followed
by **AD setup / orchestration**.
Cleanup measures security-context,
connection, and CLI AD credential-owner teardown (the library releases only its
borrowed lease). Security diagnostics are split into three tables:

- **Server TLS certificate / connection:** TLS version, subject, issuer and SANs.
- **Cryptography (TLS / Kerberos):** cipher suite, key exchange, certificate
  key/signature and verified-chain estimate; the SMTP ticket's encryption and
  session-key enctypes, names and nominal encoded key sizes; and separate
  SSPI context-protection attributes where available.
- **Validity (TLS certificates / Kerberos):** UTC start/end, relative age,
  remaining validity and start provenance for each unique presented/verified
  TLS certificate and the actual SMTP service ticket. Future starts and expired
  intervals are explicit.

The cryptography table's third column lists estimated NIST-equivalent classical
key strengths. TLS and Kerberos encryption-key estimates are shown separately,
with an overall weakest-component estimate only when both can be assessed;
strengths are never added. Kerberos AES enctypes are rated by encryption-key
strength, not by MAC strength, password entropy or overall protocol security.
Legacy DES/3DES/RC4 and unknown/unassessed enctypes are not rated. Non-applicable
cells show `-`; unavailable applicable estimates are explicitly marked.
Certificate signature strength is included in the verified-chain estimate
rather than rated separately. Plain-text mail keeps estimates beside the
corresponding details. No second TLS handshake or extra ticket acquisition
is performed.

Ticket validity uses the SDK's effective `ValidFrom`, not acquisition time.
`auth_time_fallback` means omitted StartTime used AuthTime;
`start_time_or_auth_time` means the dependency normalized StartTime and the
original optional field was not retained. Windows SSPI ticket enctypes and
validity remain explicitly OS-managed/unavailable. Available SSPI context
crypto/lifetime is listed separately and is never substituted for ticket
metadata or used to invent an overall ticket strength.
The runtime breakdown estimates elapsed time from observed intervals:
overlapping work is counted once, with DNS then Kerberos then LDAP taking
precedence. Specific operations take precedence over the enclosing AD
setup/orchestration interval, which includes local setup and coordination not
covered by more specific measurements. Credential-file acquisition, preliminary
keytab inspection, and principal selection are included in Kerberos. Credential
prompting includes time spent entering the principal and password, separately
from local user lookup. Report preparation/output covers testmail generation
and report event recording/streaming; final report rendering/output is outside
its own snapshot. Missing observations remain in other/untracked. OS-internal SSPI DNS
and KDC times cannot be separated from their enclosing call. Detailed step
durations require `--debug --verbose`. This collects existing observations only: no extra discovery,
refresh, connections, or reachability probes are initiated for the report.
Untested and canceled-only service rows are omitted; canceled race losers do
not prove unreachability. Completed connections and failed attempts remain visible.
Only observed protocol/port combinations appear; no LDAP/Kerberos cross-product
is displayed for each advertised port. `Responded` means a complete protocol
reply was received (possibly an error), not successful authentication; the main
Authentication row reports the authentication result.
Missing response times and zero reply counts display a grey `-`
(unstyled when colours are disabled). With SSPI credentials, per-DC Kerberos rows
are omitted because Windows manages ticket routing. Observed DNS exchange latency
is included only where resolver endpoints match discovered DC names or addresses,
deduplicated across advertised services; no DNS probes are added. DNS replies do
not prove LDAP/Kerberos reachability, and unmatched resolvers are not attributed
to a DC. Native SSPI KDC endpoints
and wire timing are OS-managed/unavailable. Response latency is not authentication
proof. Nested/concurrent step durations overlap and must not be summed.
DC rows are sorted case-insensitively by hostname, then protocol, then port.
Mainly numerical columns (including bit strengths and relative durations,
ignoring missing-value dashes) are right-aligned in terminal and HTML tables.
NIST strength, Age and Remaining columns stay right-aligned even when their
values are unavailable or contain status text. Plain-text email remains `Key: Value`.
Displayed response times and runtimes use one decimal place: milliseconds below
one second (for example `12.3ms`), otherwise seconds (for example `1.2s`).
`--debug` requires `--test` or `--testmail` and does not imply verbose event streaming.

Colours highlight successful checks in green, failures in red, and
warnings/skips in yellow only when the report writer is an interactive terminal.
`NO_COLOR` (nonempty) and `TERM=dumb` disable colours. Files, pipes, and
library report buffers receive uncoloured tables. The library's `Test` method
uses the same final-table format without changing its borrowed AD owner's hooks.

Add `--verbose` (or `-v`) for live step-by-step output before the final table,
including SDK operations, LDAP/Kerberos endpoint exchanges, and one DNS summary
per question/race. For example:

```text
[OK] DNS: name="mailgw.corp.example." type=A duration=42ms winner=192.0.2.10:53 transport=udp servers_queried=3 outcome=answered purpose=application
```

Verbose summaries also include correlation IDs, attempt counts, and response
peer/status details. Counts exclude unscheduled candidates and deduplicate
endpoints across retries/UDP-to-TCP fallback. Duration includes budget waits,
attempts, fallback, and started losing-worker cleanup; it is not the whole
AD discovery or multi-question lookup duration. A/AAAA and alias questions
have separate summaries. When there is no unique winner, the summary says
`winner=none`; consensus negatives list contributing responders instead.

After a DNS lookup failure carrying SDK failure evidence, test mode explicitly
requests supplementary diagnostics before credential cleanup. The SDK probes
only eligible failed external resolution, at one endpoint, within the original
remaining deadline and its bounded timeout/cooldown. Valid negatives, internal-only
failures, cancellation, and expired operations do not cause external probes;
successful A resolution with no AAAA records is not a failure. Skipped
diagnostics have an explicit reason. Probe work is labeled
`diagnostic_recursion`. Probe results never replace the original error, replay
the lookup, or change server selection. Success proves only that the probe
worked; failure does not establish the original failure's cause. Normal sends
do not enable or invoke these additional diagnostics.

Only real SDK exchanges identify used AD servers; discovered candidates are not
presented as contacted servers. Cached DNS results/TGTs/service tickets emit no
new network exchange. Windows SSPI manages its own KDC traffic, so the SDK
cannot report its used KDC endpoint. An exchange marked `SUCCESS` means a
response was received, not necessarily successful authentication: a KDC
preauthentication challenge or error reply is still a completed exchange.
The separate credential and SMTP authentication steps establish success.
Passwords, security tokens, LDAP filters, and payloads are not included.
DNS query names are included in verbose summaries and in failed-question
rows even without `--verbose`.
The report contains account names, queried internal DNS names, and network
topology; review it before sharing. Normal submissions do not enable DNS
summary hooks, even with `--verbose`.

Authentication failures stop the test with a nonzero exit status and retain
step diagnostics; configured credential/principal fallback may first try other
identities. QUIT, security/credential cleanup, and diagnostic-output failures
also fail test mode rather than claiming that a message was accepted.
Normal submission semantics, TLS requirements, authentication flags, and
password-prompt timeout behavior remain unchanged. `--test` does not check
sender/recipient acceptance or permission to submit message data.

## Send a diagnostic test email

Use `--testmail` to run the same AD, DNS, TLS and SMTP authentication checks
and then submit a generated diagnostic email on that authenticated connection:

```sh
ztmail --testmail
ztmail --testmail --debug
ztmail --testmail --debug recipient@example.com
```

No message input is read from stdin. Without recipient arguments, the recipient
is the authenticated user's canonical AD mail address, not the overridden
sender. Arguments override that recipient; unqualified names use the AD domain.
The canonical AD address is looked up even with `-f`. Sender overrides still
apply; with `-f '<>'`, the envelope is null but the generated From header uses
the canonical address.

The UTF-8 `multipart/mixed` email contains a `multipart/alternative` body with
styled HTML tables and a plain-text fallback using `Key: Value` lines without
table borders. Every testmail also attaches `ztmail-report.json` as
`application/json`. All three representations use the same snapshot as observed
immediately after SMTP authentication. `--debug` adds the DC inventory and
runtime breakdown; `--verbose` streams local events, and with `--debug` also
includes detailed timing rows in the email. Passwords, security tokens and
message payloads from other submissions are never included. The report does
contain account names, credential paths and internal topology: choose recipients
accordingly.

The JSON attachment uses `schema_version: 1`, a UTC `snapshot_at`, the
`snapshot_phase` value `after_smtp_authentication_before_data`, explanatory
`notes`, and an ordered `tables` array. Each table has a stable `id`, `title`,
`columns`, and `rows`; each row is an array of unstyled strings corresponding
to the columns. Values preserve the displayed units, unavailable markers and
unrounded-threshold row filtering; terminal colours and HTML styling are not
included. The `summary` table is always present; `issues` appears when needed.
With `--debug`, tables also include `runtime`, `dc_observations` when nonempty,
and `tls`, `crypto`, and `validity`; `--debug --verbose` additionally includes
`step_timings`.
Attachment contents follow the same table selection as the email body.

HTML uses the same bold green `OK`, grey AD-domain suffixes and status colours
as the CLI, regardless of terminal colour settings. Tables have grey borders
and rounded corners where supported by the email client; other clients may
show square corners. Colour-enabled CLI tables also use grey borders.

The email cannot include its own DATA acceptance, subsequent QUIT or final
cleanup outcomes. These are reported locally after submission. Relay acceptance
does not prove mailbox delivery. Failures before DATA prevent sending; an
uncertain DATA outcome must not be blindly retried. Post-acceptance QUIT or
cleanup warnings do not undo delivery and must not trigger automatic resends.
Report-output failures remain errors, even when delivery has already succeeded.

`--test` and `--testmail` are mutually exclusive. `--test` remains strictly
no-email. `--debug` works with either mode. This is a CLI convenience; library
`Test` remains no-email and normal library `Send` behavior is unchanged.
