# Changelog

Notable changes are maintained here and published as GitHub release notes.
Versions use Semantic Versioning; dates are in UTC.

## [Unreleased]

### Changed

- Upgrade the official GitHub Actions to Node.js 24.
- Pin all CI jobs to Ubuntu 26.04 instead of the moving `ubuntu-latest` label.
- Require a curated changelog entry for each new version tag and publish that
  entry on the GitHub release page, including on release reruns.

## [0.1.3] - 2026-11-01

### Added

- Add `--test` to check AD discovery, credentials, canonical mail lookup, relay
  DNS resolution, TLS, and SMTP GSSAPI authentication without reading a message
  or sending `MAIL FROM`, `RCPT TO`, or `DATA`.
- Report the selected principal, credential source, domain/realm, relay/SPN,
  and SDK-observed DNS, LDAP, and Kerberos servers and connected peers.
- Cover no-email authentication, STARTTLS, implicit TLS, certificate rejection,
  cleanup failures, and concurrent diagnostics with regression tests.

### Changed

- Upgrade the AD SDK to support server-attributed protocol exchange diagnostics.
- Treat QUIT, credential/security cleanup, and diagnostic-output failures as
  test failures while preserving normal sendmail-style submission behavior.

### Limitations

- Cached results and tickets produce no new network exchange. Windows SSPI's
  OS-managed KDC traffic cannot be observed by the SDK.
- `--test` verifies authentication, not sender/recipient acceptance or DATA
  submission permissions.

## [0.1.2] - 2026-11-01

### Added

- Add opt-in `--password-prompt` fallback after configured keytabs, FILE
  credential caches, and Windows SSPI fail.
- Show an editable current-user principal guess; honor a pinned `--principal`.
- Read passwords without echo from the controlling terminal, never message
  stdin, and use the AD SDK to acquire TGTs and service tickets in memory.

### Changed

- Allow both keytab and cache options when password fallback is enabled.
- Apply per-stage network timeouts without counting interactive credential
  input. Preserve strict source selection when fallback is not enabled.
- Upgrade the AD SDK for password-based Kerberos credentials.

### Limitations

- The SDK retains the password in memory until its credential owner closes.
  Go does not guarantee zeroization of immutable strings or runtime copies.
- Cancellation of an already-blocked terminal read may require input or EOF.

## [0.1.1] - 2026-11-01

### Added

- Automatically publish tagged GitHub releases containing six binaries and
  `SHA256SUMS`, with a manual workflow option to rebuild existing tags.

### Fixed

- Explain malformed RFC 5322 headers and the required blank line separating
  headers from the body, explicitly stating that the gateway received nothing.
- Validate header/separator structure before general message parsing, with
  LF/CRLF regression coverage.
- Read the semantic version from the checked-out source in CI instead of
  hard-coding the initial version.

## [0.1.0] - 2026-11-01

### Added

- Initial sendmail-style command-line client with Cobra flags and SMTP Kerberos
  SASL GSSAPI authentication, required STARTTLS by default.
- AD domain/realm discovery and the default `mailgw.<host-domain>` relay,
  with explicit overrides.
- AD SDK-managed DNS, Kerberos, LDAP, keytab principal selection, read-only
  FILE caches, and Windows SSPI, without external `kinit` or `krb5.conf`.
- Canonical AD sender lookup and rewriting, explicit sender overrides,
  header-derived recipients, and removal of Bcc headers.
- CGO-free Linux, Windows, and macOS binaries for amd64 and arm64, with UTC
  build time and seven-character commit SHA version metadata.

### Fixed

- Correct GitHub Actions credential-helper argument handling for private
  dependency downloads.
