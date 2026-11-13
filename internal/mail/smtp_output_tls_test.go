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

type outputCountingResolver struct{ calls int }

func (r *outputCountingResolver) Resolve(context.Context, string) ([]netip.Addr, error) {
	r.calls++
	return nil, errors.New("resolver must not be called")
}

func TestConfiguredTLSWarningFailureBeforeResolver(t *testing.T) {
	for _, method := range []AuthMode{AuthGSSAPI, AuthMTLS, AuthMTLSExternal} {
		for _, short := range []bool{false, true} {
			t.Run(string(method)+map[bool]string{false: "/error", true: "/short"}[short], func(t *testing.T) {
				cause := errors.New("TLS configured warning broken")
				writer := outputFailureWriter{cause: cause, short: short}
				if short {
					cause = io.ErrShortWrite
				}
				fixture := newCertificateSMTPFixture(t)
				resolver := &outputCountingResolver{}
				config := Config{Auth: method, Relay: "relay.example.test", TLSMode: "implicit", Timeout: time.Second,
					ServerTrust: ServerTrust{InsecureAllowUnverifiableIssuer: true}}
				if method != AuthGSSAPI {
					config.ClientCertificate = fixture.client
				}
				err := Deliver(context.Background(), config, nil, nil, resolver, writer)
				if !errors.Is(err, cause) || !errors.Is(err, ErrOutputFailed) || resolver.calls != 0 ||
					errors.Is(err, ErrAcceptedOutput) || errors.Is(err, ErrDeliveryUncertain) {
					t.Fatalf("failed TLS warning allowed DNS/uncertainty: calls=%d err=%v", resolver.calls, err)
				}
			})
		}
	}
}

func TestCertificateRequiredOutputFailure(t *testing.T) {
	for _, stage := range []string{"Server TLS verification exception", "Certificate-only TLS authentication", "TLS client certificate presentation", "SMTP AUTH EXTERNAL"} {
		for _, test := range []bool{false, true} {
			t.Run(stage+map[bool]string{false: "/send", true: "/test"}[test], func(t *testing.T) {
				fixture := newCertificateSMTPFixture(t)
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
					results <- serveCertificateSMTP(conn, fixture, true, true, false)
				}()
				cause := errors.New("required certificate notification broken")
				writer := outputFailureWriter{match: stage, cause: cause}
				config := Config{Auth: AuthMTLSExternal, Relay: "relay.example.test", Hello: "host.example.test", TLSMode: "implicit",
					Port: listener.Addr().(*net.TCPAddr).Port, Timeout: time.Second, ClientCertificate: fixture.client,
					ServerTrust: ServerTrust{Mode: RootsReplace, Certificates: [][]byte{fixture.ca.Raw}},
					From:        "from@example.test", Test: test}
				if stage == "Certificate-only TLS authentication" {
					config.Auth = AuthMTLS
				}
				if stage == "Server TLS verification exception" {
					config.ServerTrust = ServerTrust{InsecureAllowUnverifiableIssuer: true}
				}
				if stage == "TLS client certificate presentation" || stage == "SMTP AUTH EXTERNAL" {
					config.Report = NewTestReport(writer, true)
				}
				err = Deliver(context.Background(), config, []string{"to@example.test"}, []byte("Subject: test\r\n\r\nbody\r\n"),
					certificateResolver{netip.MustParseAddr("127.0.0.1")}, writer)
				result := <-results
				assertNoEmailCommands(t, result)
				if !errors.Is(err, cause) || !errors.Is(err, ErrOutputFailed) ||
					errors.Is(err, ErrAcceptedOutput) || errors.Is(err, ErrDeliveryUncertain) {
					t.Fatalf("required certificate output lost: %v", err)
				}
				if stage == "TLS client certificate presentation" || stage == "Server TLS verification exception" {
					for _, command := range result.commands {
						if strings.HasPrefix(command, "AUTH ") {
							t.Fatalf("credentials after failed notification: %v", result.commands)
						}
					}
				}
			})
		}
	}
}
