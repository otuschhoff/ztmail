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
	"net/textproto"
	"strings"
	"testing"
	"time"
)

// The peer stops at a named I/O boundary, and remains owned until release.
func cancellationSMTPPeer(conn net.Conn, fixture certificateSMTPFixture, mode, boundary string, reached chan<- struct{}, release <-chan struct{}) error {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	pause := func(at string) bool {
		if at != boundary {
			return false
		}
		close(reached)
		select {
		case <-release:
		case <-time.After(4 * time.Second):
		}
		return true
	}
	if mode == "implicit" {
		if pause("implicitTLS") {
			return nil
		}
		secure := tls.Server(conn, fixture.server)
		if err := secure.Handshake(); err != nil {
			return err
		}
		conn = secure
	}
	if pause("greeting") {
		return nil
	}
	reply := func(s string) error {
		_, err := fmt.Fprintf(conn, "%s\r\n", s)
		return err
	}
	if err := reply("220 test"); err != nil {
		return err
	}
	reader := textproto.NewReader(bufio.NewReader(conn))
	tlsActive := mode == "implicit"
	authStep := 0
	for {
		line, err := reader.ReadLine()
		if err != nil {
			return err
		}
		var response string
		switch {
		case strings.HasPrefix(line, "EHLO "):
			at := "EHLO"
			if mode == "required" && tlsActive {
				at = "postTLS-EHLO"
			}
			if pause(at) {
				return nil
			}
			response = "250-test\r\n250-AUTH GSSAPI EXTERNAL\r\n250 STARTTLS"
		case line == "STARTTLS":
			if pause("STARTTLS-command") {
				return nil
			}
			if err := reply("220 begin TLS"); err != nil {
				return err
			}
			if pause("STARTTLS-handshake") {
				return nil
			}
			secure := tls.Server(conn, fixture.server)
			if err := secure.Handshake(); err != nil {
				return err
			}
			conn, reader, tlsActive = secure, textproto.NewReader(bufio.NewReader(secure)), true
			continue
		case strings.HasPrefix(line, "AUTH EXTERNAL"):
			if pause("AUTH-EXTERNAL") {
				return nil
			}
			response = "235 authenticated"
		case strings.HasPrefix(line, "AUTH GSSAPI"):
			if pause("AUTH-GSSAPI") {
				return nil
			}
			authStep = 1
			response = "334 " + base64.StdEncoding.EncodeToString([]byte("reply"))
		case authStep == 1:
			if pause("GSSAPI-mutual") {
				return nil
			}
			authStep = 2
			response = "334 " + base64.StdEncoding.EncodeToString([]byte("signed-offer"))
		case authStep == 2:
			if pause("GSSAPI-confirmation") {
				return nil
			}
			authStep = 3
			response = "235 authenticated"
			if boundary == "AUTH-reject" {
				response = "535 authentication rejected"
			}
		case line == "*":
			response = "501 authentication aborted"
		case strings.HasPrefix(line, "MAIL FROM:"):
			if pause("MAIL") {
				return nil
			}
			response = "250 OK"
		case strings.HasPrefix(line, "RCPT TO:"):
			if pause("RCPT") {
				return nil
			}
			response = "250 OK"
			if boundary == "RCPT-reject" {
				response = "550 recipient rejected"
			}
		case line == "DATA":
			if pause("DATA-command") {
				return nil
			}
			if err := reply("354 send content"); err != nil {
				return err
			}
			if boundary == "DATA-write" {
				if _, err := reader.ReadLine(); err != nil {
					return err
				}
				if pause("DATA-write") {
					return nil
				}
			}
			if _, err := io.Copy(io.Discard, reader.DotReader()); err != nil {
				return err
			}
			if pause("DATA-response") {
				return nil
			}
			response = "250 accepted"
		case line == "QUIT":
			if pause("AUTH-reject") {
				return nil
			}
			if pause("QUIT") {
				return nil
			}
			return reply("221 bye")
		default:
			return fmt.Errorf("unexpected command %q", line)
		}
		if err := reply(response); err != nil {
			return err
		}
	}
}

func TestSMTPIOCancellation(t *testing.T) {
	fixture := newCertificateSMTPFixture(t)
	for _, boundary := range []string{
		"greeting", "EHLO", "implicitTLS", "STARTTLS-command", "STARTTLS-handshake", "postTLS-EHLO",
		"AUTH-EXTERNAL", "AUTH-GSSAPI", "GSSAPI-mutual", "GSSAPI-confirmation",
		"MAIL", "RCPT", "DATA-command", "DATA-write", "DATA-response", "QUIT", "acceptedQUIT",
	} {
		for _, cause := range []string{"canceled", "expired"} {
			t.Run(boundary+"/"+cause, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				reached, release, peerDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
				mode := "off"
				if boundary == "implicitTLS" || boundary == "AUTH-EXTERNAL" {
					mode = "implicit"
				} else if strings.HasPrefix(boundary, "STARTTLS") || boundary == "postTLS-EHLO" {
					mode = "required"
				}
				peerFixture := fixture
				if boundary != "AUTH-EXTERNAL" {
					peerFixture.server = fixture.server.Clone()
					peerFixture.server.ClientAuth = tls.NoClientCert
				}
				peerBoundary := boundary
				if boundary == "acceptedQUIT" {
					peerBoundary = "QUIT"
				}
				go func() {
					conn, err := listener.Accept()
					if err == nil {
						err = cancellationSMTPPeer(conn, peerFixture, mode, peerBoundary, reached, release)
					}
					peerDone <- err
				}()
				ctx, cancel := context.WithCancel(context.Background())
				want := context.Canceled
				if cause == "expired" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
					want = context.DeadlineExceeded
				}
				defer cancel()
				o := options{relay: "relay.example.test", hello: "host.example.test", from: "sender@example.test",
					port: listener.Addr().(*net.TCPAddr).Port, timeout: 3 * time.Second, tlsMode: mode,
					clientCertificate: fixture.client, serverTrust: ServerTrust{Mode: RootsReplace, Certificates: [][]byte{fixture.ca.Raw}},
					testMode: boundary == "QUIT"}
				if boundary == "AUTH-EXTERNAL" {
					o.auth = AuthMTLSExternal
				}
				security := &fakeSecurity{offer: []byte{1, 0, 0, 0}}
				backend := &fakeBackend{address: netip.MustParseAddr("127.0.0.1"), security: security}
				message := []byte("Subject: test\r\n\r\nbody\r\n")
				if boundary == "DATA-write" {
					message = bytes.Repeat([]byte("long body line\r\n"), 1<<20)
				}
				finished := make(chan error, 1)
				var warning error
				o.warning = func(err error) { warning = err }
				go func() { finished <- deliver(ctx, o, []string{"recipient@example.test"}, message, backend, io.Discard) }()
				defer func() {
					cancel()
					close(release)
					listener.Close()
					select {
					case <-peerDone:
					case <-time.After(5 * time.Second):
						t.Error("peer did not terminate")
					}
				}()
				select {
				case <-reached:
				case err := <-finished:
					t.Fatalf("boundary not reached: %v", err)
				case <-time.After(2 * time.Second):
					cancel()
					<-finished
					t.Fatal("boundary watchdog")
				}
				if cause == "canceled" {
					cancel()
				}
				select {
				case err = <-finished:
				case <-time.After(4 * time.Second):
					cancel()
					<-finished
					t.Fatal("delivery did not terminate")
				}
				causeErr := err
				if boundary == "acceptedQUIT" {
					if err != nil || warning == nil {
						t.Errorf("accepted delivery must succeed with QUIT warning: err=%v warning=%v", err, warning)
					}
					causeErr = warning
				}
				if !errors.Is(causeErr, want) {
					t.Errorf("context identity missing: got %v, want %v", err, want)
				}
				var socketErr *net.OpError
				if !errors.As(causeErr, &socketErr) {
					t.Errorf("network cause missing: %v", causeErr)
				}
				uncertain := boundary == "DATA-write" || boundary == "DATA-response"
				if errors.Is(err, ErrDeliveryUncertain) != uncertain {
					t.Errorf("uncertainty mismatch: %v", err)
				}
				if security.closed != backend.contexts || backend.contexts > 1 {
					t.Errorf("context cleanup closed=%d created=%d", security.closed, backend.contexts)
				}
			})
		}
	}
}

type smtpDeadlineWithoutTimer struct {
	context.Context
	deadline time.Time
}

func (c smtpDeadlineWithoutTimer) Deadline() (time.Time, bool) { return c.deadline, true }

func TestSMTPDeadlineTimerLag(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reached, release, peerDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			err = cancellationSMTPPeer(conn, certificateSMTPFixture{}, "off", "greeting", reached, release)
		}
		peerDone <- err
	}()
	defer func() { close(release); listener.Close(); <-peerDone }()
	ctx := smtpDeadlineWithoutTimer{Context: context.Background(), deadline: time.Now().Add(100 * time.Millisecond)}
	o := options{relay: "relay.example.test", port: listener.Addr().(*net.TCPAddr).Port, timeout: time.Second, tlsMode: "off"}
	err = deliver(ctx, o, nil, nil, certificateResolver{netip.MustParseAddr("127.0.0.1")}, io.Discard)
	var socketErr *net.OpError
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &socketErr) || !socketErr.Timeout() {
		t.Fatalf("socket deadline before context timer lost causes: %v", err)
	}
}

type smtpCleanupSecurity struct {
	*fakeSecurity
	cancel context.CancelFunc
}

func (s smtpCleanupSecurity) Close() error {
	s.cancel()
	return s.fakeSecurity.Close()
}

type smtpCreationBackend struct {
	*fakeBackend
	security SecurityContext
	err      error
	cancel   context.CancelFunc
}

type smtpFailingTokenSecurity struct {
	*fakeSecurity
	stage  string
	cancel context.CancelFunc
	err    error
}

func (s smtpFailingTokenSecurity) Start() ([]byte, error) {
	if s.stage == "token-start" {
		s.cancel()
		return nil, s.err
	}
	return s.fakeSecurity.Start()
}

func (s smtpFailingTokenSecurity) Step(input []byte) ([]byte, bool, error) {
	if s.stage == "token-step" {
		s.cancel()
		return nil, false, s.err
	}
	return s.fakeSecurity.Step(input)
}

func (s smtpFailingTokenSecurity) Negotiate(input []byte) ([]byte, error) {
	if s.stage == "token-negotiate" {
		s.cancel()
		return nil, s.err
	}
	return s.fakeSecurity.Negotiate(input)
}

func (b smtpCreationBackend) NewSecurityContext(context.Context, string, *tls.ConnectionState) (SecurityContext, error) {
	if b.cancel != nil {
		b.cancel()
	}
	return b.security, b.err
}

func TestSMTPProtocolAndCreationErrorsSurviveLateCancel(t *testing.T) {
	for _, boundary := range []string{"RCPT-reject", "AUTH-reject", "creation", "token-start", "token-step", "token-negotiate"} {
		t.Run(boundary, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			reached, release, peerDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					err = cancellationSMTPPeer(conn, certificateSMTPFixture{}, "off", boundary, reached, release)
				}
				peerDone <- err
			}()
			defer func() { close(release); listener.Close(); <-peerDone }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			security := &fakeSecurity{offer: []byte{1, 0, 0, 0}}
			backend := smtpCreationBackend{fakeBackend: &fakeBackend{address: netip.MustParseAddr("127.0.0.1")},
				security: smtpCleanupSecurity{fakeSecurity: security, cancel: cancel}}
			original := errors.New("security context creation failed")
			if boundary == "creation" {
				backend.err = original
				backend.cancel = cancel
			}
			if strings.HasPrefix(boundary, "token-") {
				switch boundary {
				case "token-start":
					original = io.EOF
				case "token-step":
					original = io.ErrUnexpectedEOF
				case "token-negotiate":
					original = &net.DNSError{Err: "security-provider timeout", IsTimeout: true}
				}
				backend.security = smtpFailingTokenSecurity{fakeSecurity: security, stage: boundary, cancel: cancel, err: original}
			}
			o := options{relay: "relay.example.test", hello: "host.example.test", from: "sender@example.test",
				port: listener.Addr().(*net.TCPAddr).Port, timeout: time.Second, tlsMode: "off"}
			finished := make(chan error, 1)
			go func() { finished <- deliver(ctx, o, []string{"recipient@example.test"}, nil, backend, io.Discard) }()
			if boundary == "AUTH-reject" {
				select {
				case <-reached:
					cancel()
				case err := <-finished:
					t.Fatalf("AUTH rejection did not reach internal QUIT: %v", err)
				case <-time.After(2 * time.Second):
					cancel()
					<-finished
					t.Fatal("AUTH rejection watchdog")
				}
			}
			select {
			case err = <-finished:
			case <-time.After(3 * time.Second):
				cancel()
				<-finished
				t.Fatal("delivery watchdog")
			}
			cancel()
			if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrDeliveryUncertain) {
				t.Fatalf("meaningful failure misclassified: %v", err)
			}
			if boundary == "creation" {
				if !errors.Is(err, original) || security.closed != 0 {
					t.Fatalf("creation error/cleanup changed: %v closed=%d", err, security.closed)
				}
			} else if strings.HasPrefix(boundary, "token-") {
				if !errors.Is(err, original) || security.closed != 1 {
					t.Fatalf("token error/cleanup changed: %v closed=%d", err, security.closed)
				}
			} else {
				var rejection *textproto.Error
				code := 550
				if boundary == "AUTH-reject" {
					code = 535
				}
				if !errors.As(err, &rejection) || rejection.Code != code || security.closed != 1 {
					t.Fatalf("rejection/cleanup changed: %v closed=%d", err, security.closed)
				}
			}
		})
	}
}

func TestSMTPIOCause(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
		want error
	}{
		{"canceled-socket", canceled, &net.OpError{Op: "read", Net: "tcp", Err: net.ErrClosed}, context.Canceled},
		{"canceled-eof", canceled, io.EOF, context.Canceled},
		{"late-cancel-protocol", canceled, &textproto.Error{Code: 550, Msg: "rejected"}, nil},
		{"late-cancel-local", canceled, errors.New("GSSAPI signature invalid"), nil},
		{"late-cancel-success", canceled, nil, nil},
		{"deadline-timer-lag", smtpDeadlineWithoutTimer{context.Background(), time.Now().Add(-time.Second)}, &net.DNSError{Err: "timeout", IsTimeout: true}, context.DeadlineExceeded},
		{"earlier-socket-timeout", smtpDeadlineWithoutTimer{context.Background(), time.Now().Add(time.Hour)}, &net.DNSError{Err: "timeout", IsTimeout: true}, nil},
		{"expired-nontimeout-socket", smtpDeadlineWithoutTimer{context.Background(), time.Now().Add(-time.Second)}, &net.OpError{Op: "read", Net: "tcp", Err: net.ErrClosed}, nil},
		{"expired-protocol", smtpDeadlineWithoutTimer{context.Background(), time.Now().Add(-time.Second)}, &textproto.Error{Code: 550, Msg: "rejected"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := smtpIOCause(tc.ctx, tc.err)
			if tc.err != nil && !errors.Is(got, tc.err) {
				t.Errorf("original I/O cause lost: %v", got)
			}
			if tc.want != nil {
				if !errors.Is(got, tc.want) {
					t.Errorf("missing context cause %v: %v", tc.want, got)
				}
			} else if errors.Is(got, context.Canceled) || errors.Is(got, context.DeadlineExceeded) || (tc.err == nil && got != nil) {
				t.Errorf("spurious context failure: %v", got)
			}
		})
	}
}
