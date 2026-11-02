package mail

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/quotedprintable"
	"net"
	netmail "net/mail"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestGeneratedTestmailDelivery(t *testing.T) {
	for _, mode := range []string{"normal", "debug", "auth-failure", "recipient-failure", "quit-failure"} {
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
				results <- serveSMTP(conn, mode == "recipient-failure", mode == "quit-failure")
			}()
			var output bytes.Buffer
			report := NewTestReport(&output, false)
			report.EnableTestMail()
			report.color = true
			report.Value("AD domain", "corp.example")
			report.Value("Hostname", "worker.corp.example")
			report.Value("Canonical mail", "self@corp.example")
			if mode == "debug" {
				report.EnableDebug()
			}
			security := &fakeSecurity{offer: []byte{1, 0, 0, 0}, fail: mode == "auth-failure"}
			backend := &fakeBackend{security: security, address: netip.MustParseAddr("127.0.0.1")}
			err = Deliver(context.Background(), Config{Relay: "relay.corp.example", Hello: "worker.corp.example",
				Port: listener.Addr().(*net.TCPAddr).Port, Timeout: 3 * time.Second, TLSMode: "off",
				From: "self@corp.example", TestMail: true, Report: report},
				[]string{"recipient@corp.example"}, nil, backend, &output)
			wire := <-results
			report.Finish(&err)
			if mode == "auth-failure" || mode == "recipient-failure" {
				if err == nil || wire.message != "" || strings.Contains(output.String(), "Testmail delivery: Accepted") {
					t.Fatalf("failed testmail claimed acceptance: err=%v wire=%+v output=%s", err, wire, &output)
				}
				return
			}
			if err != nil || wire.message == "" {
				t.Fatalf("testmail failed: %v wire=%+v", err, wire)
			}
			message, err := netmail.ReadMessage(strings.NewReader(wire.message))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(quotedprintable.NewReader(message.Body))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"worker.corp.example", "Authentication", "OK", "before sending this message",
				"DATA acceptance, QUIT and final cleanup are not included"} {
				if !strings.Contains(string(body), want) {
					t.Errorf("missing %q:\n%s", want, body)
				}
			}
			if strings.Contains(string(body), "\x1b[") || strings.Contains(string(body), "No email sent") ||
				strings.Contains(string(body), "RUNTIME BREAKDOWN") != (mode == "debug") {
				t.Fatalf("incorrect body/verbosity:\n%s", body)
			}
			if message.Header.Get("From") != "<self@corp.example>" ||
				message.Header.Get("To") != "<recipient@corp.example>" ||
				message.Header.Get("Message-ID") == "" || message.Header.Get("Date") == "" {
				t.Fatalf("bad headers: %v", message.Header)
			}
			if !strings.Contains(output.String(), "Testmail delivery: Accepted by relay") {
				t.Fatalf("missing actual delivery outcome: %s", &output)
			}
		})
	}
}

func TestTestmailNullSenderAndOutputFailure(t *testing.T) {
	report := NewTestReport(io.Discard, false)
	report.Value("Canonical mail", "self@corp.example")
	message, err := report.TestMessage("", []string{"recipient@corp.example"})
	if err != nil || !bytes.Contains(message, []byte("From: <self@corp.example>")) {
		t.Fatalf("null envelope needs canonical header: %v %s", err, message)
	}
	if _, err := report.TestMessage("bad\r\nsender", []string{"recipient@corp.example"}); err == nil {
		t.Fatal("invalid header sender accepted")
	}
	writeErr := errors.New("report output failed")
	report = NewTestReport(dnsReportFailureWriter{writeErr}, true)
	report.Line("INFO", "Synthetic", "write failure")
	if _, err := report.TestMessage("self@corp.example", []string{"recipient@corp.example"}); !errors.Is(err, writeErr) {
		t.Fatalf("failed diagnostic output must prevent testmail generation: %v", err)
	}
}
