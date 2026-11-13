package mail

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type outputFailureWriter struct {
	match string
	cause error
	short bool
}

func (w outputFailureWriter) Write(p []byte) (int, error) {
	if w.match == "" || strings.Contains(string(p), w.match) {
		if w.short {
			return len(p) - 1, nil
		}
		return 0, w.cause
	}
	return len(p), nil
}

func TestSMTPRequiredOutputFailure(t *testing.T) {
	cause := errors.New("required output broken")
	for _, stage := range []string{"Relay DNS lookup", "SMTP EHLO", "SMTP AUTH GSSAPI", "SMTP DATA", "SMTP QUIT", "GSSAPI cleanup"} {
		t.Run(stage, func(t *testing.T) {
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
				results <- serveSMTP(conn, false, false)
			}()
			security := &fakeSecurity{offer: []byte{1, 0, 0, 0}}
			backend := &fakeBackend{security: security, address: netip.MustParseAddr("127.0.0.1")}
			writer := outputFailureWriter{match: stage, cause: cause}
			o := options{relay: "relay.example.test", hello: "host.example.test", port: listener.Addr().(*net.TCPAddr).Port,
				from: "from@example.test", timeout: time.Second, tlsMode: "off", testMail: true, report: NewTestReport(writer, true)}
			err = deliver(context.Background(), o, []string{"to@example.test"}, nil, backend, writer)
			listener.Close()
			result := <-results
			if !errors.Is(err, cause) || errors.Is(err, ErrDeliveryUncertain) {
				t.Fatalf("output cause lost or made uncertain: %v", err)
			}
			accepted := stage == "SMTP DATA" || stage == "SMTP QUIT" || stage == "GSSAPI cleanup"
			if errors.Is(err, ErrAcceptedOutput) != accepted {
				t.Fatalf("accepted output classification=%v: %v", accepted, err)
			}
			if (stage == "Relay DNS lookup" || stage == "SMTP EHLO") && backend.contexts != 0 {
				t.Fatalf("credentials acquired after failed notification: %d", backend.contexts)
			}
			count := 0
			for _, command := range result.commands {
				if command == "DATA" {
					count++
				}
				if !accepted && (strings.HasPrefix(command, "MAIL FROM:") || strings.HasPrefix(command, "RCPT TO:") || command == "DATA") {
					t.Fatalf("email after failed notification: %v", result.commands)
				}
			}
			if accepted && count != 1 {
				t.Fatalf("DATA count=%d, want one", count)
			}
		})
	}
}

func TestSMTPWarningOutputFailure(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "writer error", true: "short write"}[short], func(t *testing.T) {
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
				results <- serveSMTP(conn, false, true)
			}()
			cause := errors.New("warning broken")
			writer := outputFailureWriter{cause: cause, short: short}
			if short {
				cause = io.ErrShortWrite
			}
			o := options{relay: "relay.example.test", hello: "host.example.test", port: listener.Addr().(*net.TCPAddr).Port,
				from: "from@example.test", timeout: time.Second, tlsMode: "off"}
			backend := &fakeBackend{security: &fakeSecurity{offer: []byte{1, 0, 0, 0}}, address: netip.MustParseAddr("127.0.0.1")}
			err = deliver(context.Background(), o, []string{"to@example.test"}, []byte("Subject: test\r\n\r\nbody\r\n"), backend, writer)
			result := <-results
			if !errors.Is(err, ErrAcceptedOutput) || !errors.Is(err, cause) || errors.Is(err, ErrDeliveryUncertain) || result.message == "" {
				t.Fatalf("accepted output failure: err=%v message=%q", err, result.message)
			}
			if !errors.Is(err, io.EOF) {
				t.Fatalf("independent QUIT failure lost: %v", err)
			}
		})
	}
}
