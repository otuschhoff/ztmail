package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

var ErrDeliveryUncertain = errors.New("SMTP delivery status uncertain")

func warn(o options, log io.Writer, err error) {
	if o.warning != nil {
		o.warning(err)
	} else {
		fmt.Fprintf(log, "Warning: %v\n", err)
	}
}

type SecurityContext interface {
	Start() ([]byte, error)
	Step([]byte) ([]byte, bool, error)
	Negotiate([]byte) ([]byte, error)
	Close() error
}

type Backend interface {
	Resolve(context.Context, string) ([]netip.Addr, error)
	NewSecurityContext(context.Context, string, *tls.ConnectionState) (SecurityContext, error)
}

type gssAuth struct {
	security  SecurityContext
	stage     int
	confirmed bool
	report    *TestReport
}

func (a *gssAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	found := false
	for _, mechanism := range server.Auth {
		if strings.EqualFold(mechanism, "GSSAPI") {
			found = true
		}
	}
	if !found {
		a.report.Step("SMTP AUTH mechanism", errors.New("relay does not advertise AUTH GSSAPI"), "")
		return "", nil, errors.New("relay does not advertise AUTH GSSAPI")
	}
	a.report.Step("SMTP AUTH mechanism", nil, "GSSAPI advertised")
	token, err := a.security.Start()
	a.report.Step("GSSAPI initial token", err, "initial security token created (not printed)")
	return "GSSAPI", token, err
}

func (a *gssAuth) Next(challenge []byte, more bool) ([]byte, error) {
	if !more {
		if a.stage != 2 {
			return nil, errors.New("relay completed AUTH before GSSAPI mutual authentication and SASL negotiation")
		}
		a.confirmed = true
		return nil, nil
	}
	switch a.stage {
	case 0:
		token, done, err := a.security.Step(challenge)
		if err != nil {
			a.report.Step("GSSAPI mutual authentication", err, "")
			return nil, fmt.Errorf("GSSAPI mutual authentication: %w", err)
		}
		if done {
			a.stage = 1
			a.report.Step("GSSAPI mutual authentication", nil, "server identity verified")
		}
		// net/smtp treats nil as end-of-AUTH, not as an empty GSSAPI token.
		if token == nil {
			token = []byte{}
		}
		return token, nil
	case 1:
		response, err := a.security.Negotiate(challenge)
		if err == nil && len(response) == 0 {
			err = errors.New("empty GSSAPI SASL negotiation response")
		}
		a.report.Step("GSSAPI SASL negotiation", err, "no-layer selection protected by GSSAPI")
		if err != nil {
			return nil, fmt.Errorf("AD GSSAPI SASL negotiation: %w", err)
		}
		a.stage = 2
		return response, nil
	default:
		return nil, errors.New("unexpected extra SMTP AUTH challenge")
	}
}

func deliver(ctx context.Context, o options, recipients []string, message []byte, backend Backend, log io.Writer) (err error) {
	o.report.Value("SPN", o.spn)
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	conn, err := dialRelay(ctx, o, backend)
	if err != nil {
		return fmt.Errorf("connect to relay: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("set SMTP deadline: %w", err)
		}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	tlsConfig := &tls.Config{ServerName: o.relay, MinVersion: tls.VersionTLS12}
	var transport net.Conn = conn
	if o.tlsMode == "implicit" {
		secure := tls.Client(conn, tlsConfig)
		tlsDone := o.report.Measure("SMTP implicit TLS")
		err := secure.HandshakeContext(ctx)
		tlsDone()
		if err != nil {
			o.report.Step("Implicit TLS", err, "")
			return fmt.Errorf("TLS handshake: %w", err)
		}
		o.report.Step("Implicit TLS", nil, "verified server certificate; TLS established")
		transport = secure
	}
	greetingDone := o.report.Measure("SMTP greeting")
	c, err := smtp.NewClient(transport, o.relay)
	greetingDone()
	o.report.Step("SMTP greeting", err, "relay greeting received")
	if err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}
	defer c.Close()
	helloDone := o.report.Measure("SMTP EHLO")
	err = c.Hello(o.hello)
	helloDone()
	o.report.Step("SMTP EHLO", err, fmt.Sprintf("hostname=%q", o.hello))
	if err != nil {
		return fmt.Errorf("SMTP EHLO: %w", err)
	}
	if o.tlsMode == "required" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			o.report.Step("SMTP STARTTLS", errors.New("relay does not offer STARTTLS"), "")
			return errors.New("relay does not offer STARTTLS; refusing an unencrypted submission")
		}
		tlsDone := o.report.Measure("SMTP STARTTLS")
		err = c.StartTLS(tlsConfig)
		tlsDone()
		o.report.Step("SMTP STARTTLS", err, "verified server certificate; TLS and post-TLS EHLO completed")
		if err != nil {
			return fmt.Errorf("SMTP STARTTLS: %w", err)
		}
	} else if o.tlsMode == "off" {
		o.report.Line("SKIP", "TLS", "explicitly disabled; no confidentiality")
	}
	var state *tls.ConnectionState
	if tlsState, ok := c.TLSConnectionState(); ok {
		state = &tlsState
		o.report.TLS(tlsState)
	}
	security, err := backend.NewSecurityContext(ctx, o.spn, state)
	o.report.Step("SMTP GSSAPI security context", err, fmt.Sprintf("SPN=%q TLS channel binding available=%t", o.spn, state != nil))
	if err != nil {
		return fmt.Errorf("AD SMTP security context: %w", err)
	}
	defer func() {
		if closeErr := security.Close(); closeErr != nil {
			if err != nil || o.testMode {
				err = errors.Join(err, closeErr)
			} else {
				warn(o, log, fmt.Errorf("message accepted, but security context cleanup failed: %w", closeErr))
			}
			o.report.Step("GSSAPI cleanup", closeErr, "")
		} else {
			o.report.Step("GSSAPI cleanup", nil, "security context closed")
		}
	}()
	auth := &gssAuth{security: security, report: o.report}
	authDone := o.report.Measure("SMTP GSSAPI authentication")
	err = c.Auth(auth)
	authDone()
	if err == nil && !auth.confirmed {
		err = errors.New("relay did not confirm SMTP authentication")
	}
	o.report.Step("SMTP AUTH GSSAPI", err, "relay accepted authentication")
	if err != nil {
		return fmt.Errorf("SMTP AUTH GSSAPI: %w", err)
	}
	if o.testMode {
		quitDone := o.report.Measure("SMTP QUIT")
		err = c.Quit()
		quitDone()
		o.report.Step("SMTP QUIT", err, "disconnected without MAIL FROM, RCPT TO or DATA")
		if err != nil {
			return fmt.Errorf("SMTP test QUIT: %w", err)
		}
		return nil
	}
	if o.testMail {
		message, err = o.report.TestMessage(o.from, recipients)
		if err != nil {
			return fmt.Errorf("build testmail: %w", err)
		}
	}
	if err := c.Mail(o.from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %w", err)
	}
	for _, recipient := range recipients {
		if err := c.Rcpt(recipient); err != nil {
			return fmt.Errorf("SMTP RCPT TO %s (message not sent to any recipient): %w", recipient, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %w", err)
	}
	if _, err := w.Write(message); err != nil {
		return fmt.Errorf("write message: %w: %w", ErrDeliveryUncertain, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("relay did not confirm message acceptance: %w: %w", ErrDeliveryUncertain, err)
	}
	if o.testMail {
		o.report.Value("Testmail delivery", "Accepted by relay (not mailbox delivery proof)")
		o.report.Step("SMTP DATA", nil, "testmail accepted by relay")
	}
	// A QUIT failure after a positive DATA reply must not cause the caller to resend.
	if err := c.Quit(); err != nil {
		warn(o, log, fmt.Errorf("message accepted, but SMTP QUIT failed: %w", err))
		if o.testMail {
			o.report.Line("WARN", "SMTP QUIT", "testmail accepted, but disconnect failed: "+err.Error())
		}
	} else if o.testMail {
		o.report.Step("SMTP QUIT", nil, "testmail accepted; disconnected")
	}
	return nil
}

func tlsTransportSummary(state tls.ConnectionState, now time.Time) string {
	cn, expiry := "CN unavailable", "expiry unavailable"
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		if cert.Subject.CommonName != "" {
			cn = "CN=" + cert.Subject.CommonName
		}
		expiry = certificateLifetime(cert.NotAfter, now)
	}
	strength, _ := overallTLSStrength(state)
	rating := "strength unavailable"
	if strength > 0 {
		rating = fmt.Sprintf("~%dbit", strength)
	}
	version := strings.ReplaceAll(tls.VersionName(state.Version), "TLS ", "TLS")
	if state.Version == 0 {
		version = "TLS unavailable"
	}
	return "OK (" + cn + "; " + expiry + "; " + version + " " + rating + ")"
}

func certificateLifetime(notAfter, now time.Time) string {
	remaining := notAfter.Sub(now)
	if remaining <= 0 {
		return "expired"
	}
	for _, unit := range []struct {
		duration time.Duration
		name     string
	}{{24 * time.Hour, "day"}, {time.Hour, "hour"}, {time.Minute, "minute"}} {
		if remaining >= unit.duration {
			count := int64(remaining / unit.duration)
			name := unit.name
			if count != 1 {
				name += "s"
			}
			return fmt.Sprintf("+%d %s", count, name)
		}
	}
	return "+<1 minute"
}

func dialRelay(ctx context.Context, o options, backend Backend) (net.Conn, error) {
	dnsDone := o.report.Measure("DNS relay lookup")
	addresses, err := backend.Resolve(ctx, o.relay)
	dnsDone()
	if err != nil {
		o.report.Step("Relay DNS lookup", err, "")
		return nil, fmt.Errorf("AD DNS relay lookup: %w", err)
	}
	if len(addresses) == 0 {
		err := errors.New("AD DNS relay lookup returned no addresses")
		o.report.Step("Relay DNS lookup", err, "")
		return nil, err
	}
	o.report.Step("Relay DNS lookup", nil, fmt.Sprintf("host=%q addresses=%v", o.relay, addresses))
	var failures []error
	tcpDone := o.report.Measure("SMTP TCP connection")
	defer tcpDone()
	for i, address := range addresses {
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
			err := errors.New("AD DNS relay lookup returned an invalid unicast IP")
			o.report.Step("Relay address validation", err, "")
			return nil, err
		}
		work := ctx
		cancel := func() {}
		if deadline, ok := ctx.Deadline(); ok {
			work, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(addresses)-i))
		}
		conn, err := (&net.Dialer{}).DialContext(work, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(o.port)))
		cancel()
		if err == nil {
			o.report.Step("SMTP TCP connection", nil, fmt.Sprintf("target=%q peer=%q", o.relay, conn.RemoteAddr().String()))
		} else {
			o.report.Step("SMTP TCP connection", err, "")
		}
		if err == nil {
			return conn, nil
		}
		failures = append(failures, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(failures...)
}

var _ smtp.Auth = (*gssAuth)(nil)
