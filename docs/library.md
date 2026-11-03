# Go library

[README](../README.md) | [Advanced usage](advanced-usage.md) | [Diagnostics](diagnostics.md) | [Implementation](implementation.md) | [Go library](library.md) | [Build and release](build.md)

GSSAPI remains the default. `AuthMTLS` performs TLS client-certificate
presentation only; `AuthMTLSExternal` additionally requires SMTP AUTH EXTERNAL
confirmation. Both work with `Send` and `Test`, without acquiring credentials,
requesting tickets or looking up LDAP mail. Diagnostics are method-aware;
testmail attachments use JSON schema v2 with independent transport, certificate
presentation and SMTP authentication evidence.
See the [design and approved platform limits](mtls-design.md).

For certificate authentication, supply `Auth: ztmail.AuthMTLSExternal`,
`ClientCertificate: certificate` (a `*tls.Certificate`) and, if needed,
`ServerTrust: ztmail.ServerTrust{Mode: ztmail.RootsReplace, Certificates: caDER}`.
The borrowed owner's DNS is still used; its credentials and configuration are
not touched. Create a DNS-only SDK owner with explicitly empty
`kerberos.Options.SourceMethods` and `PrincipalMethods` if no other application
component needs credentials. `Realm`, `SPN` and nonzero `LDAPRaceCandidates`
conflict with mTLS. Every `Send` needs `Message.From` and explicit/header
recipients; no AD or certificate identity is converted to a mail address.
Null-envelope `From: "<>"` preserves sender headers. `Test` needs neither.
`Result.Authentication` distinguishes certificate presentation from confirmed
SMTP authentication; `Accepted` remains separate DATA-acceptance evidence.
Mutable certificate/CA DER and selector slices are copied at `New`.
The private signer is borrowed and must remain immutable and concurrency-safe.

Import `github.com/otuschhoff/ztmail`. The application supplies an existing
`*adclient.Client` created with `adclient.NewAD`; ztmail does not create another
AD owner or duplicate its DNS, discovery, or credential state. Ordinary LDAP
sessions remain owner-managed; opt-in racing uses temporary child sessions.

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

## Ownership, defaults, and concurrency

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
- Each GSSAPI `Send` borrows a separate credential lease, uses AD DNS for relay
  resolution, and creates a fresh SMTP connection and TLS-bound GSSAPI context.
  The lease is released on every outcome and the security context is closed.
  Shared tickets and LDAP sessions remain managed by the application's SDK.
- `LDAPRaceCandidates` defaults to zero, preserving ordinary SDK LDAP reads.
  Values 1-8 opt into immediate complete canonical-mail racing across up to
  that many discovered/admitted DCs; other values are rejected by `New`.
  For example, add `LDAPRaceCandidates: 8` to `Options` above to match the CLI
  default. Each candidate keeps RootDSE and its scoped principal search on the
  same DC. A complete absent or ambiguous result can win, without trying to
  find a favorable replica. Every lookup closes its own single-use racing
  view, including on cancellation, without closing the application-owned AD
  client or changing its policy/hooks. Cleanup errors are surfaced. No view
  is created when a sender override makes LDAP unnecessary.
- A mailer supports concurrent calls, subject to SDK credential/LDAP capacity
  limits. Do not modify message slices until the call returns. There is no
  mailer `Close`: the application closes the shared AD client only after all
  in-flight operations complete. No credentials fallback or interactive
  password prompting is initiated by the library. It neither reads the CLI's
  saved sender nor executes host sendmail.
- The CLI and library share message validation, sender rewriting, canonical
  LDAP lookup, AD DNS/GSSAPI adapters, TLS and SMTP transport code. Cobra,
  sendmail stdin handling, source probing and password prompts belong to the
  CLI, not the public library API.

## Message and result semantics

`Message.Data` is a complete RFC 5322 message, not a dot-terminated SMTP stream.
Dot-only body lines are preserved. `Recipients` supplies envelope recipients;
when empty, recipients are read from headers automatically. In GSSAPI, if headers provide
none, delivery uses the authenticated user's canonical AD mail address. This
fallback requires canonical lookup even when `From` is overridden or null.
`ReadRecipients: true` also reads To/Cc/Bcc (or the latest Resent block).
Bcc/Resent-Bcc headers are always stripped, and duplicate recipients are
deduplicated. Message structure and envelope addresses are validated before
credential acquisition.

By default, the canonical AD mail address becomes the envelope sender and
From/Sender headers. `Message.From` explicitly overrides them and skips the
mail lookup. `Message.From: "<>"` uses the null envelope and preserves sender
headers. Input byte/slice contents are not mutated.

An LDAP-confirmed computer account can have no canonical mailbox. `Test`
attempts the lookup, emits a warning for that condition, and continues SMTP
authentication. User mailbox absence, malformed/ambiguous/incomplete data,
directory failures and cleanup errors remain fatal. Normal host submissions
without a mailbox require an explicit `Message.From` and explicit/header
recipients; the library never uses the sender as a recipient. A null envelope
with existing sender headers and known recipients retains its existing behavior.

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
its hooks. For per-question DNS summaries, set `adclient.ADOptions.DNSSummary`
when constructing that owner. The callback remains application-owned; `Test`
does not install or replace it. Normal `Send` does not write to stdout/stderr.
