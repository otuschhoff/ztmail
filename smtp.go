package main

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

type securityContext interface {
	Start() ([]byte, error)
	Step([]byte) ([]byte, bool, error)
	Negotiate([]byte) ([]byte, error)
	Close() error
}

type submissionBackend interface {
	Resolve(context.Context, string) ([]netip.Addr, error)
	NewSecurityContext(context.Context, string, *tls.ConnectionState) (securityContext, error)
}

type gssAuth struct {
	security securityContext
	stage    int
	report   *testReport
}

func (a *gssAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	found := false
	for _, mechanism := range server.Auth {
		if strings.EqualFold(mechanism, "GSSAPI") {
			found = true
		}
	}
	if !found {
		a.report.step("SMTP AUTH mechanism", errors.New("relay does not advertise AUTH GSSAPI"), "")
		return "", nil, errors.New("relay does not advertise AUTH GSSAPI")
	}
	a.report.step("SMTP AUTH mechanism", nil, "GSSAPI advertised")
	token, err := a.security.Start()
	a.report.step("GSSAPI initial token", err, "initial security token created (not printed)")
	return "GSSAPI", token, err
}

func (a *gssAuth) Next(challenge []byte, more bool) ([]byte, error) {
	if !more {
		if a.stage != 2 {
			return nil, errors.New("relay completed AUTH before GSSAPI mutual authentication and SASL negotiation")
		}
		return nil, nil
	}
	switch a.stage {
	case 0:
		token, done, err := a.security.Step(challenge)
		if err != nil {
			a.report.step("GSSAPI mutual authentication", err, "")
			return nil, fmt.Errorf("GSSAPI mutual authentication: %w", err)
		}
		if done {
			a.stage = 1
			a.report.step("GSSAPI mutual authentication", nil, "server identity verified")
		}
		return token, nil
	case 1:
		response, err := a.security.Negotiate(challenge)
		a.report.step("GSSAPI SASL negotiation", err, "no-layer selection protected by GSSAPI")
		if err != nil {
			return nil, fmt.Errorf("AD GSSAPI SASL negotiation: %w", err)
		}
		a.stage = 2
		return response, nil
	default:
		return nil, errors.New("unexpected extra SMTP AUTH challenge")
	}
}

func deliver(ctx context.Context, o options, recipients []string, message []byte, backend submissionBackend, log io.Writer) (err error) {
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
		if err := secure.HandshakeContext(ctx); err != nil {
			o.report.step("Implicit TLS", err, "")
			return fmt.Errorf("TLS handshake: %w", err)
		}
		o.report.step("Implicit TLS", nil, "verified server certificate; TLS established")
		transport = secure
	}
	c, err := smtp.NewClient(transport, o.relay)
	o.report.step("SMTP greeting", err, "relay greeting received")
	if err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}
	defer c.Close()
	err = c.Hello(o.hello)
	o.report.step("SMTP EHLO", err, fmt.Sprintf("hostname=%q", o.hello))
	if err != nil {
		return fmt.Errorf("SMTP EHLO: %w", err)
	}
	if o.tlsMode == "required" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			o.report.step("SMTP STARTTLS", errors.New("relay does not offer STARTTLS"), "")
			return errors.New("relay does not offer STARTTLS; refusing an unencrypted submission")
		}
		err = c.StartTLS(tlsConfig)
		o.report.step("SMTP STARTTLS", err, "verified server certificate; TLS and post-TLS EHLO completed")
		if err != nil {
			return fmt.Errorf("SMTP STARTTLS: %w", err)
		}
	} else if o.tlsMode == "off" {
		o.report.line("SKIP", "TLS", "explicitly disabled; no confidentiality")
	}
	var state *tls.ConnectionState
	if tlsState, ok := c.TLSConnectionState(); ok {
		state = &tlsState
	}
	security, err := backend.NewSecurityContext(ctx, o.spn, state)
	o.report.step("SMTP GSSAPI security context", err, fmt.Sprintf("SPN=%q TLS channel binding available=%t", o.spn, state != nil))
	if err != nil {
		return fmt.Errorf("AD SMTP security context: %w", err)
	}
	defer func() {
		if closeErr := security.Close(); closeErr != nil {
			if err != nil || o.testMode {
				err = errors.Join(err, closeErr)
			} else {
				fmt.Fprintf(log, "Warning: message accepted, but security context cleanup failed: %v\n", closeErr)
			}
			o.report.step("GSSAPI cleanup", closeErr, "")
		} else {
			o.report.step("GSSAPI cleanup", nil, "security context closed")
		}
	}()
	err = c.Auth(&gssAuth{security: security, report: o.report})
	o.report.step("SMTP AUTH GSSAPI", err, "relay accepted authentication")
	if err != nil {
		return fmt.Errorf("SMTP AUTH GSSAPI: %w", err)
	}
	if o.testMode {
		err = c.Quit()
		o.report.step("SMTP QUIT", err, "disconnected without MAIL FROM, RCPT TO or DATA")
		if err != nil {
			return fmt.Errorf("SMTP test QUIT: %w", err)
		}
		return nil
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
		return fmt.Errorf("write message (delivery status uncertain): %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("relay did not confirm message acceptance (delivery status uncertain): %w", err)
	}
	// A QUIT failure after a positive DATA reply must not cause the caller to resend.
	if err := c.Quit(); err != nil {
		fmt.Fprintf(log, "Warning: message accepted, but SMTP QUIT failed: %v\n", err)
	}
	return nil
}

func dialRelay(ctx context.Context, o options, backend submissionBackend) (net.Conn, error) {
	addresses, err := backend.Resolve(ctx, o.relay)
	if err != nil {
		o.report.step("Relay DNS lookup", err, "")
		return nil, fmt.Errorf("AD DNS relay lookup: %w", err)
	}
	if len(addresses) == 0 {
		err := errors.New("AD DNS relay lookup returned no addresses")
		o.report.step("Relay DNS lookup", err, "")
		return nil, err
	}
	o.report.step("Relay DNS lookup", nil, fmt.Sprintf("host=%q addresses=%v", o.relay, addresses))
	var failures []error
	for i, address := range addresses {
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
			err := errors.New("AD DNS relay lookup returned an invalid unicast IP")
			o.report.step("Relay address validation", err, "")
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
			o.report.step("SMTP TCP connection", nil, fmt.Sprintf("target=%q peer=%q", o.relay, conn.RemoteAddr().String()))
		} else {
			o.report.step("SMTP TCP connection", err, "")
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
