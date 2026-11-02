package mail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fakeSecurity struct {
	offer    []byte
	wrapped  []byte
	fail     bool
	closed   int
	closeErr error
}

func (f *fakeSecurity) Start() ([]byte, error) { return []byte("request"), nil }
func (f *fakeSecurity) Step(input []byte) ([]byte, bool, error) {
	if !bytes.Equal(input, []byte("reply")) {
		return nil, false, errors.New("bad mutual-auth reply")
	}
	return []byte{}, true, nil
}
func (f *fakeSecurity) Negotiate([]byte) ([]byte, error) {
	if f.fail {
		return nil, errors.New("bad signature")
	}
	if len(f.offer) != 4 || f.offer[0]&1 == 0 {
		return nil, errors.New("no supported SASL security layer")
	}
	f.wrapped = []byte{1, 0, 0, 0}
	return []byte("signed-selection"), nil
}
func (f *fakeSecurity) Close() error { f.closed++; return f.closeErr }

type fakeBackend struct {
	security   *fakeSecurity
	address    netip.Addr
	contexts   int
	state      *tls.ConnectionState
	resolveErr error
	addresses  []netip.Addr
}

func (f *fakeBackend) Resolve(context.Context, string) ([]netip.Addr, error) {
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	if f.addresses != nil {
		return f.addresses, nil
	}
	return []netip.Addr{f.address}, nil
}

func TestRelayDNSFailuresDoNotCreateContext(t *testing.T) {
	for _, backend := range []*fakeBackend{
		{resolveErr: errors.New("AD DNS unavailable")},
		{addresses: []netip.Addr{}},
		{addresses: []netip.Addr{netip.Addr{}}},
		{addresses: []netip.Addr{netip.MustParseAddr("0.0.0.0")}},
	} {
		o := options{relay: "relay.corp.example", port: 25, timeout: time.Second}
		err := deliver(context.Background(), o, []string{"user@example.com"}, nil, backend, io.Discard)
		if err == nil || backend.contexts != 0 {
			t.Fatalf("err=%v contexts=%d", err, backend.contexts)
		}
	}
}

func (f *fakeBackend) NewSecurityContext(_ context.Context, _ string, state *tls.ConnectionState) (SecurityContext, error) {
	f.contexts++
	f.state = state
	return f.security, nil
}

func TestGSSAPIAuth(t *testing.T) {
	f := &fakeSecurity{offer: []byte{7, 0, 16, 0}}
	a := &gssAuth{security: f}
	mech, first, err := a.Start(&smtp.ServerInfo{Auth: []string{"PLAIN", "GSSAPI"}})
	if err != nil || mech != "GSSAPI" || string(first) != "request" {
		t.Fatalf("Start: %s %q %v", mech, first, err)
	}
	if _, err := a.Next([]byte("reply"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Next([]byte("signed-offer"), true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.wrapped, []byte{1, 0, 0, 0}) {
		t.Fatalf("wrong selection: %x", f.wrapped)
	}
	if _, err := a.Next(nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Next(nil, true); err == nil {
		t.Fatal("extra challenge accepted")
	}
}

func TestGSSAPIAuthRejectsInvalidNegotiation(t *testing.T) {
	a := &gssAuth{security: &fakeSecurity{}}
	if _, _, err := a.Start(&smtp.ServerInfo{Auth: []string{"PLAIN"}}); err == nil {
		t.Fatal("missing GSSAPI accepted")
	}
	for stage := 0; stage < 2; stage++ {
		if _, err := (&gssAuth{security: &fakeSecurity{}, stage: stage}).Next(nil, false); err == nil {
			t.Fatal("premature success accepted")
		}
	}
	for _, offer := range [][]byte{nil, {1}, {2, 0, 0, 0}, {1, 0, 0, 0, 0}} {
		a := &gssAuth{security: &fakeSecurity{offer: offer}, stage: 1}
		if _, err := a.Next(nil, true); err == nil {
			t.Fatalf("offer %x accepted", offer)
		}
	}
	a = &gssAuth{security: &fakeSecurity{offer: []byte{1, 0, 0, 0}, fail: true}, stage: 1}
	if _, err := a.Next(nil, true); err == nil {
		t.Fatal("invalid signature accepted")
	}
}

type smtpResult struct {
	message  string
	commands []string
	err      error
}

func serveSMTP(conn net.Conn, rejectRecipient, quitFailure bool) (result smtpResult) {
	return serveSMTPWithTLS(conn, rejectRecipient, quitFailure, nil)
}

func serveSMTPWithTLS(conn net.Conn, rejectRecipient, quitFailure bool, tlsConfig *tls.Config) (result smtpResult) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		result.err = err
		return
	}
	r := textproto.NewReader(bufio.NewReader(conn))
	w := bufio.NewWriter(conn)
	reply := func(s string) error {
		if _, err := fmt.Fprint(w, s+"\r\n"); err != nil {
			return err
		}
		return w.Flush()
	}
	if err := reply("220 test ESMTP"); err != nil {
		result.err = err
		return
	}
	authStep := 0
	secure := false
	for {
		line, err := r.ReadLine()
		if err != nil {
			result.err = err
			return
		}
		result.commands = append(result.commands, line)
		var response string
		switch {
		case strings.HasPrefix(line, "EHLO "):
			response = "250-test\r\n250 AUTH GSSAPI"
			if tlsConfig != nil && !secure {
				response = "250-test\r\n250-STARTTLS\r\n250 AUTH GSSAPI"
			}
		case line == "STARTTLS" && tlsConfig != nil && !secure:
			if err := reply("220 start TLS"); err != nil {
				result.err = err
				return
			}
			tlsConn := tls.Server(conn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				result.err = err
				return
			}
			conn = tlsConn
			r = textproto.NewReader(bufio.NewReader(conn))
			w = bufio.NewWriter(conn)
			secure = true
			continue
		case strings.HasPrefix(line, "AUTH GSSAPI "):
			if line != "AUTH GSSAPI "+base64.StdEncoding.EncodeToString([]byte("request")) {
				result.err = fmt.Errorf("bad initial response: %q", line)
				return
			}
			authStep = 1
			response = "334 " + base64.StdEncoding.EncodeToString([]byte("reply"))
		case authStep == 1:
			if line != "" {
				result.err = fmt.Errorf("expected empty AP-REP response, got %q", line)
				return
			}
			authStep = 2
			response = "334 " + base64.StdEncoding.EncodeToString([]byte("signed-offer"))
		case authStep == 2:
			if line != base64.StdEncoding.EncodeToString([]byte("signed-selection")) {
				result.err = fmt.Errorf("bad SASL selection: %q", line)
				return
			}
			authStep = 3
			response = "235 authenticated"
		case strings.HasPrefix(line, "MAIL FROM:"):
			response = "250 sender accepted"
		case strings.HasPrefix(line, "RCPT TO:"):
			response = "250 recipient accepted"
			if rejectRecipient {
				response = "550 recipient rejected"
			}
		case line == "DATA":
			if err := reply("354 send message"); err != nil {
				result.err = err
				return
			}
			message, err := io.ReadAll(r.DotReader())
			if err != nil {
				result.err = err
				return
			}
			result.message = string(message)
			response = "250 queued"
		case line == "QUIT":
			if !quitFailure {
				result.err = reply("221 bye")
			}
			return
		default:
			result.err = fmt.Errorf("unexpected SMTP command %q", line)
			return
		}
		if err := reply(response); err != nil {
			result.err = err
			return
		}
	}
}

func TestSMTPSubmission(t *testing.T) {
	for _, mode := range []string{"success", "recipient-rejected", "quit-failure", "starttls-required"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			results := make(chan smtpResult, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					results <- smtpResult{err: err}
					return
				}
				results <- serveSMTP(conn, mode == "recipient-rejected", mode == "quit-failure")
			}()
			host, port, err := net.SplitHostPort(listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			n, err := strconv.Atoi(port)
			if err != nil {
				t.Fatal(err)
			}
			o := options{relay: host, port: n, hello: "host.example.com", from: "sender@example.com", tlsMode: "off", timeout: 3 * time.Second}
			if mode == "starttls-required" {
				o.tlsMode = "required"
			}
			f := &fakeSecurity{offer: []byte{1, 0, 0, 0}}
			backend := &fakeBackend{security: f, address: netip.MustParseAddr(host)}
			var log bytes.Buffer
			err = deliver(context.Background(), o, []string{"one@example.com", "two@example.com"}, []byte("Subject: test\n\nline\n.dot\n"), backend, &log)
			result := <-results
			if mode == "starttls-required" {
				if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
					t.Fatalf("expected STARTTLS failure, got %v", err)
				}
				if backend.contexts != 0 {
					t.Fatal("security context created before required TLS")
				}
				for _, command := range result.commands {
					if strings.HasPrefix(command, "AUTH ") {
						t.Fatal("credentials sent without required TLS")
					}
				}
				return
			}
			if mode == "recipient-rejected" {
				if err == nil || !strings.Contains(err.Error(), "RCPT TO") {
					t.Fatalf("expected recipient error, got %v", err)
				}
				if result.message != "" {
					t.Fatal("message sent after recipient rejection")
				}
				return
			}
			if err != nil || result.err != nil {
				t.Fatalf("client=%v server=%v", err, result.err)
			}
			if f.closed != 1 || backend.contexts != 1 || backend.state != nil {
				t.Fatalf("context lifecycle: closed=%d contexts=%d TLS=%v", f.closed, backend.contexts, backend.state)
			}
			if result.message != "Subject: test\n\nline\n.dot\n" {
				t.Fatalf("message corrupted: %q", result.message)
			}
			var recipients []string
			for _, command := range result.commands {
				if strings.HasPrefix(command, "RCPT TO:") {
					recipients = append(recipients, command)
				}
			}
			if !reflect.DeepEqual(recipients, []string{"RCPT TO:<one@example.com>", "RCPT TO:<two@example.com>"}) {
				t.Fatalf("recipients: %v", recipients)
			}
			if mode == "quit-failure" && !strings.Contains(log.String(), "message accepted") {
				t.Fatal("missing QUIT failure warning")
			}
		})
	}
}
