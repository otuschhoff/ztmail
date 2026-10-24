package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strconv"
	"strings"
)

type securityContext interface {
	Start() ([]byte, error)
	Step([]byte) ([]byte, bool, error)
	Unwrap([]byte) ([]byte, error)
	Wrap([]byte) ([]byte, error)
	Close() error
}

type gssAuth struct {
	security securityContext
	stage    int
}

func (a *gssAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	found := false
	for _, mechanism := range server.Auth {
		if strings.EqualFold(mechanism, "GSSAPI") {
			found = true
		}
	}
	if !found {
		return "", nil, errors.New("relay does not advertise AUTH GSSAPI")
	}
	token, err := a.security.Start()
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
			return nil, fmt.Errorf("GSSAPI mutual authentication: %w", err)
		}
		if done {
			a.stage = 1
		}
		return token, nil
	case 1:
		offer, err := a.security.Unwrap(challenge)
		if err != nil {
			return nil, fmt.Errorf("verify SASL security-layer offer: %w", err)
		}
		if len(offer) != 4 || offer[0]&1 == 0 {
			return nil, errors.New("relay does not offer the SASL no-security-layer option; use TLS with a compatible relay")
		}
		// RFC 4752: select no SASL layer; TLS provides transport confidentiality and integrity.
		response, err := a.security.Wrap([]byte{1, 0, 0, 0})
		if err != nil {
			return nil, fmt.Errorf("sign SASL security-layer selection: %w", err)
		}
		a.stage = 2
		return response, nil
	default:
		return nil, errors.New("unexpected extra SMTP AUTH challenge")
	}
}

func deliver(ctx context.Context, o options, recipients []string, message []byte, security securityContext, log io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	addr := net.JoinHostPort(o.relay, strconv.Itoa(o.port))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
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
			return fmt.Errorf("TLS handshake: %w", err)
		}
		transport = secure
	}
	c, err := smtp.NewClient(transport, o.relay)
	if err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}
	defer c.Close()
	if err := c.Hello(o.hello); err != nil {
		return fmt.Errorf("SMTP EHLO: %w", err)
	}
	if o.tlsMode == "required" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("relay does not offer STARTTLS; refusing an unencrypted submission")
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("SMTP STARTTLS: %w", err)
		}
	}
	if err := c.Auth(&gssAuth{security: security}); err != nil {
		return fmt.Errorf("SMTP AUTH GSSAPI: %w", err)
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

var _ smtp.Auth = (*gssAuth)(nil)
