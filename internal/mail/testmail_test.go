package mail

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	netmail "net/mail"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/observe"
)

func TestGeneratedTestmailDelivery(t *testing.T) {
	for _, mode := range []string{"normal", "debug", "debug-verbose", "auth-failure", "recipient-failure", "quit-failure"} {
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
			report := NewTestReport(&output, mode == "debug-verbose")
			report.EnableTestMail()
			report.color = true
			report.Value("AD domain", "corp.example")
			report.Value("Hostname", "worker.corp.example")
			report.Value("Canonical mail", "self@corp.example")
			debug := strings.HasPrefix(mode, "debug")
			if debug {
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
			bodies := testmailBodies(t, message)
			for contentType, body := range bodies {
				for _, want := range []string{"worker.corp.example", "Authentication", "OK", "before sending this message",
					"DATA acceptance, QUIT and final cleanup are not included"} {
					if !strings.Contains(body, want) {
						t.Errorf("%s missing %q:\n%s", contentType, want, body)
					}
				}
				if strings.ContainsAny(body, "\x1b╭╮╰╯│─┌┐└┘") || strings.Contains(body, "No email sent") ||
					strings.Contains(body, "Runtime breakdown") != debug ||
					strings.Contains(body, "Step timings (nested/concurrent") != (mode == "debug-verbose") {
					t.Fatalf("incorrect %s body/verbosity:\n%s", contentType, body)
				}
			}
			if !strings.Contains(bodies["text/plain"], "Hostname: worker.corp.example") ||
				!strings.Contains(bodies["text/plain"], "Authentication: OK") ||
				!strings.Contains(bodies["text/html"], `<th scope="row"`) ||
				!strings.Contains(bodies["text/html"], "<table ") {
				t.Fatalf("missing key/value fallback or HTML table: %v", bodies)
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

func testmailBodies(t *testing.T, message *netmail.Message) map[string]string {
	t.Helper()
	contentType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || contentType != "multipart/alternative" || params["boundary"] == "" {
		t.Fatalf("bad multipart header: %v, %v", message.Header, err)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	bodies := make(map[string]string)
	for _, want := range []string{"text/plain", "text/html"} {
		part, err := reader.NextRawPart()
		if err != nil {
			t.Fatal(err)
		}
		contentType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil || contentType != want || params["charset"] != "UTF-8" ||
			part.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
			t.Fatalf("bad %s part headers: %v, %v", want, part.Header, err)
		}
		body, err := io.ReadAll(quotedprintable.NewReader(part))
		if err != nil {
			t.Fatal(err)
		}
		bodies[want] = string(body)
	}
	if _, err := reader.NextRawPart(); err != io.EOF {
		t.Fatalf("expected multipart end, got %v", err)
	}
	return bodies
}

func TestTestmailEscapesHTMLAndPreservesPlainValues(t *testing.T) {
	report := NewTestReport(io.Discard, true)
	report.EnableDebug()
	value := `Jörg <script>alert("x")</script> & friends`
	report.Value("User", value)
	report.Line("WARN", "Certificate", value)
	report.Trace(context.Background(), observe.TraceEvent{Phase: observe.TraceCompleted, Operation: value})
	data, err := report.TestMessage("self@corp.example", []string{"recipient@corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	message, err := netmail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	bodies := testmailBodies(t, message)
	for _, want := range []string{"User: " + value, "[WARN] Certificate: " + value, "Step: " + value} {
		if !strings.Contains(bodies["text/plain"], want) {
			t.Errorf("plain fallback missing %q:\n%s", want, bodies["text/plain"])
		}
	}
	htmlBody := bodies["text/html"]
	if strings.Contains(htmlBody, "<script>") ||
		strings.Count(htmlBody, "Jörg &lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; &amp; friends") != 3 {
		t.Fatalf("HTML values must be escaped in summary, issues and timings:\n%s", htmlBody)
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
