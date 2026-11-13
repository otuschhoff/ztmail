package mail

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestCertificateAcceptedReportOutput(t *testing.T) {
	for _, method := range []AuthMode{AuthMTLS, AuthMTLSExternal} {
		for _, short := range []bool{false, true} {
			t.Run(string(method)+map[bool]string{false: "/error", true: "/short"}[short], func(t *testing.T) {
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
				cause := errors.New("accepted certificate status broken")
				writer := outputFailureWriter{match: "SMTP DATA", cause: cause, short: short}
				if short {
					cause = io.ErrShortWrite
				}
				config := Config{Auth: method, Relay: "relay.example.test", Hello: "host.example.test", TLSMode: "implicit",
					Port: listener.Addr().(*net.TCPAddr).Port, Timeout: time.Second, ClientCertificate: fixture.client,
					ServerTrust: ServerTrust{Mode: RootsReplace, Certificates: [][]byte{fixture.ca.Raw}},
					From:        "from@example.test", TestMail: true, Report: NewTestReport(writer, true)}
				err = Deliver(context.Background(), config, []string{"to@example.test"}, nil,
					certificateResolver{netip.MustParseAddr("127.0.0.1")}, writer)
				result := <-results
				count := 0
				for _, command := range result.commands {
					if command == "DATA" {
						count++
					}
				}
				if !errors.Is(err, ErrAcceptedOutput) || !errors.Is(err, cause) || errors.Is(err, ErrDeliveryUncertain) ||
					count != 1 || result.message == "" {
					t.Fatalf("known certificate acceptance not retained: err=%v DATA=%d message=%q", err, count, result.message)
				}
			})
		}
	}
}
