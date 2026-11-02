// Package ztmail submits RFC 5322 messages using SMTP GSSAPI and a borrowed
// AD client. It never prompts for credentials or closes the supplied AD owner.
package ztmail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/ztmail/internal/mail"
)

// ErrDeliveryUncertain means DATA was started but message acceptance could not
// be confirmed. Retrying automatically can produce duplicate messages.
var ErrDeliveryUncertain = mail.ErrDeliveryUncertain

type TLSMode string

const (
	TLSRequired TLSMode = "required"
	TLSImplicit TLSMode = "implicit"
	TLSOff      TLSMode = "off"
)

// Options is copied by New. AD must have been created with adclient.NewAD.
// The application retains ownership and must keep AD alive until all calls end.
type Options struct {
	AD *adclient.Client
	// Domain is explicit; the library does not discover local host configuration.
	// It must describe the supplied AD client's domain.
	Domain string
	// Realm defaults to the uppercase Domain and must match the acquired identity.
	Realm string
	// Relay defaults to mailgw.<Domain>; Hostname (EHLO) defaults to localhost.
	Relay, Hostname string
	// SPN defaults to smtp/<Relay>.
	SPN string
	// Port defaults to 25; set 465 explicitly for implicit TLS if appropriate.
	Port int
	// TLS defaults to TLSRequired with system certificate/hostname verification.
	TLS TLSMode
	// Timeout defaults to 60 seconds and bounds the complete Send or Test call.
	Timeout time.Duration
}

// Message contains a complete RFC 5322 message, not an SMTP DATA stream.
// The caller must not modify Data or Recipients while Send is running.
type Message struct {
	Recipients []string
	Data       []byte
	// From overrides both envelope sender and From/Sender headers and skips
	// canonical-mail lookup. Empty uses canonical AD mail. "<>" preserves
	// original headers and uses the null envelope sender.
	From string
	// ReadRecipients adds To/Cc/Bcc recipients, using the latest Resent block.
	// Blind-recipient headers are removed whether or not this option is enabled.
	ReadRecipients bool
}

// Result describes the selected identity and the confirmed submission outcome.
// Accepted means the relay accepted DATA, not that recipients received mail.
type Result struct {
	Accepted   bool
	Identity   kerberos.Identity
	From       string
	Recipients []string
	// Warnings are post-acceptance QUIT/security cleanup errors. When Accepted
	// is true and error is nil, do not resend merely because warnings exist.
	Warnings []error
}

// Client is immutable after construction and supports concurrent calls. Each
// call acquires its own lease, SMTP connection and GSSAPI security context.
// SDK credential/LDAP capacity limits still apply. Client needs no Close:
// only the application closes the shared AD owner.
type Client struct {
	options Options
	acquire func(context.Context) (session, error)
}

type session interface {
	mail.Backend
	identity() (kerberos.Identity, error)
	ticket(context.Context, string) error
	canonical(context.Context, kerberos.Identity) (string, error)
	release()
}

type borrowedSession struct {
	mail.ADBackend
}

func (s *borrowedSession) identity() (kerberos.Identity, error) { return s.Lease.Identity() }
func (s *borrowedSession) ticket(ctx context.Context, spn string) error {
	_, err := s.Lease.ServiceTicket(ctx, spn)
	return err
}
func (s *borrowedSession) canonical(ctx context.Context, identity kerberos.Identity) (string, error) {
	return mail.CanonicalMail(ctx, s.Client, identity)
}
func (s *borrowedSession) release() { s.Lease.Release() }

// New validates configuration without network I/O. It borrows AD, never creates
// another AD owner, and never selects different credentials on failure.
func New(o Options) (*Client, error) {
	if o.AD == nil {
		return nil, errors.New("AD client is required")
	}
	if _, err := o.AD.DNS(); err != nil {
		return nil, fmt.Errorf("AD client must support AD-aware DNS (use adclient.NewAD): %w", err)
	}
	var err error
	o.Domain, err = mail.DNSName(o.Domain)
	if err != nil {
		return nil, fmt.Errorf("AD domain: %w", err)
	}
	if o.Realm == "" {
		o.Realm = strings.ToUpper(o.Domain)
	}
	if strings.ContainsAny(o.Realm, "\r\n\x00 /@") {
		return nil, errors.New("invalid Kerberos realm")
	}
	if o.Relay == "" {
		o.Relay = "mailgw." + o.Domain
	}
	o.Relay, err = mail.DNSName(o.Relay)
	if err != nil {
		return nil, fmt.Errorf("relay: %w", err)
	}
	if o.Hostname == "" {
		o.Hostname = "localhost"
	}
	o.Hostname, err = mail.DNSName(o.Hostname)
	if err != nil {
		return nil, fmt.Errorf("EHLO hostname: %w", err)
	}
	if o.SPN == "" {
		o.SPN = "smtp/" + o.Relay
	}
	if strings.ContainsAny(o.SPN, "\r\n\x00") {
		return nil, errors.New("invalid SMTP service principal")
	}
	if o.Port == 0 {
		o.Port = 25
	}
	if o.Port < 1 || o.Port > 65535 {
		return nil, errors.New("SMTP port must be between 1 and 65535")
	}
	if o.TLS == "" {
		o.TLS = TLSRequired
	}
	switch o.TLS {
	case TLSRequired, TLSImplicit, TLSOff:
	default:
		return nil, errors.New("TLS mode must be required, implicit, or off")
	}
	if o.Timeout == 0 {
		o.Timeout = 60 * time.Second
	}
	if o.Timeout < 0 {
		return nil, errors.New("timeout must be positive")
	}
	client := &Client{options: o}
	client.acquire = func(ctx context.Context) (session, error) {
		lease, err := o.AD.Credentials().Acquire(ctx)
		if err != nil {
			return nil, err
		}
		return &borrowedSession{ADBackend: mail.ADBackend{Client: o.AD, Lease: lease}}, nil
	}
	return client, nil
}

// Send validates the message before authentication. It does not retry SMTP
// submissions. Check ErrDeliveryUncertain before considering any retry.
func (c *Client) Send(ctx context.Context, message Message) (Result, error) {
	return c.send(ctx, message, nil, false)
}

// Test verifies the same AD/SMTP authentication path without reading a message
// or sending MAIL FROM, RCPT TO or DATA. Accepted remains false. Report must be
// non-nil; the library never writes to stdout/stderr. Configure AD observation
// hooks on the application's owner for detailed DNS/LDAP/KDC exchange events;
// this borrowed-client API does not replace the owner's hooks.
func (c *Client) Test(ctx context.Context, report io.Writer) (Result, error) {
	if report == nil {
		return Result{}, errors.New("test report writer is required")
	}
	return c.send(ctx, Message{}, report, true)
}

func (c *Client) send(ctx context.Context, message Message, output io.Writer, test bool) (result Result, err error) {
	if c == nil || c.acquire == nil {
		return result, errors.New("ztmail client must be constructed with New")
	}
	if ctx == nil {
		return result, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.options.Timeout)
	defer cancel()
	var report *mail.TestReport
	if test {
		report = mail.NewTestReport(output, false)
		report.Value("Hostname", c.options.Hostname)
		report.Value("AD domain", c.options.Domain)
		report.Value("Target relay", fmt.Sprintf("%s:%d", c.options.Relay, c.options.Port))
		report.Value("SPN", c.options.SPN)
		if c.options.TLS == TLSOff {
			report.Value("Transport security", "Disabled; no confidentiality")
		}
		defer report.Finish(&err)
		report.Line("INFO", "Target configuration", fmt.Sprintf("AD domain=%q realm=%q relay=%q port=%d EHLO=%q SPN=%q TLS=%q",
			c.options.Domain, c.options.Realm, c.options.Relay, c.options.Port, c.options.Hostname, c.options.SPN, c.options.TLS))
		report.Line("INFO", "Borrowed AD owner", "owner and observation hooks remain application-owned; no credential prompting or owner closure")
	}
	var data []byte
	from := message.From
	if from != "" && from != "<>" {
		from, err = mail.EnvelopeAddress(from, c.options.Domain, false)
		if err != nil {
			return result, fmt.Errorf("sender: %w", err)
		}
	}
	if !test {
		data, result.Recipients, err = mail.PrepareMessage(bytes.NewReader(message.Data),
			message.Recipients, c.options.Domain, message.ReadRecipients, true)
		if err != nil {
			return result, err
		}
	}
	credentials, err := c.acquire(ctx)
	report.Step("Acquire credential lease", err, "borrowed credential lease acquired")
	if err != nil {
		return result, fmt.Errorf("acquire AD credentials: %w", err)
	}
	defer credentials.release()
	result.Identity, err = credentials.identity()
	if err == nil && !strings.EqualFold(result.Identity.Realm, c.options.Realm) {
		err = fmt.Errorf("AD identity realm %q does not match configured realm %q", result.Identity.Realm, c.options.Realm)
	}
	report.Step("Credential identity", err, fmt.Sprintf("principal=%q realm=%q krb/gssapi source=%q",
		result.Identity.Principal, result.Identity.Realm, result.Identity.Source))
	report.Value("User", result.Identity.Principal)
	report.Value("Cred source", string(result.Identity.Source))
	if err != nil {
		return result, err
	}
	err = credentials.ticket(ctx, c.options.SPN)
	report.Step("SMTP service ticket", err, fmt.Sprintf("SPN=%q", c.options.SPN))
	if err != nil {
		return result, fmt.Errorf("SMTP service ticket: %w", err)
	}
	canonical := ""
	if from == "" || (!test && len(result.Recipients) == 0) {
		canonical, err = credentials.canonical(ctx, result.Identity)
		report.Step("Canonical AD mail lookup", err, fmt.Sprintf("mail=%q", canonical))
		if err != nil {
			return result, fmt.Errorf("canonical AD mail: %w", err)
		}
	}
	if !test {
		result.Recipients, err = mail.RecipientFallback(result.Recipients, canonical, c.options.Domain)
		if err != nil {
			return result, err
		}
		data, result.From, err = mail.ApplySender(data, from, canonical, c.options.Domain)
		if err != nil {
			return result, err
		}
	}
	if test {
		report.Value("Mail (from)", canonical)
	}
	err = mail.Deliver(ctx, mail.Config{Relay: c.options.Relay, Hello: c.options.Hostname, SPN: c.options.SPN,
		Port: c.options.Port, TLSMode: string(c.options.TLS), Timeout: c.options.Timeout,
		From: result.From, Test: test, Report: report,
		Warning: func(warning error) { result.Warnings = append(result.Warnings, warning) }},
		result.Recipients, data, credentials, io.Discard)
	if err != nil {
		return result, err
	}
	result.Accepted = !test
	return result, nil
}
