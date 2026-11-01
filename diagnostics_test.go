package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/observe"
)

func TestTestFlagDoesNotReadStdin(t *testing.T) {
	cmd := newCommand()
	cmd.SetArgs([]string{"--test", "--domain", "corp.example", "--keytab", filepath.Join(t.TempDir(), "missing"), "-t", "-v"})
	cmd.SetIn(failingReader{})
	var output bytes.Buffer
	cmd.SetErr(&output)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "inspect keytab") {
		t.Fatalf("expected credential failure without consuming stdin: %v", err)
	}
	for _, expected := range []string{
		"[OK] Host/domain discovery", `AD domain="corp.example"`, `realm="CORP.EXAMPLE"`,
		`relay="mailgw.corp.example"`, `SPN="smtp/mailgw.corp.example"`, `source="keytab"`,
		"[FAIL] Keytab inspection", "[FAIL] Test", "stdin is not read",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q in %s", expected, &output)
		}
	}
	if strings.Contains(output.String(), "Message accepted") {
		t.Fatal("test mode claimed to send a message")
	}
}

func TestTestFlagRejectsRecipients(t *testing.T) {
	cmd := newCommand()
	cmd.SetArgs([]string{"--test", "recipient@corp.example"})
	cmd.SetIn(failingReader{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "does not accept recipients") {
		t.Fatalf("expected recipient validation error: %v", err)
	}
}

func TestEndpointReportIsConcurrentAndServerAttributed(t *testing.T) {
	var output bytes.Buffer
	report := newTestReport(&output)
	var wg sync.WaitGroup
	for _, protocol := range []string{"dns", "kerberos", "ldap"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				report.exchange(context.Background(), observe.ExchangeEvent{Protocol: protocol, Request: "synthetic-request",
					Server: "dc.corp.example:88", Address: "192.0.2.10:88", Transport: "tcp",
					Outcome: observe.Success, Duration: time.Millisecond})
			}
		}()
	}
	wg.Wait()
	var err error
	report.finish(&err)
	if err != nil || report.exchanges != 30 {
		t.Fatalf("exchanges=%d err=%v", report.exchanges, err)
	}
	for _, expected := range []string{`protocol="dns"`, `protocol="kerberos"`, `protocol="ldap"`,
		`server="dc.corp.example:88"`, `peer="192.0.2.10:88"`, `transport="tcp"`,
		"not authentication proof", "Windows SSPI", "Cache hits", "30 AD exchanges"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q", expected)
		}
	}
}

func TestDiagnosticHooksAreOptInAndPreserveSDKRouting(t *testing.T) {
	o := options{auth: "auto", domain: "corp.example", realm: "CORP.EXAMPLE", dnsProbeZone: "example.com",
		ccache: filepath.Join(t.TempDir(), "cache")}
	settings, err := adOptions(o)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Hooks.Exchange != nil || settings.Credentials.Hooks.Exchange != nil {
		t.Fatal("diagnostics were enabled without --test")
	}
	var output bytes.Buffer
	o.report = newTestReport(&output)
	settings, err = adOptions(o)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Credentials.KDCProvider != nil || settings.Credentials.DialContext != nil ||
		settings.DialContext != nil || settings.Discovery.DialContext != nil {
		t.Fatal("diagnostics replaced SDK-managed network routing")
	}
	if settings.Hooks.Exchange == nil || settings.Credentials.Hooks.Observe == nil || settings.Discovery.Hooks.Observe == nil {
		t.Fatal("shared/credential/discovery hooks were not wired")
	}
	if settings.Credentials.Hooks.Exchange != nil || settings.Discovery.Hooks.Exchange != nil {
		t.Fatal("leaf exchange hooks would duplicate SDK-forwarded observations")
	}
	settings.Hooks.Exchange(context.Background(), observe.ExchangeEvent{Protocol: "ldap", Outcome: observe.Success})
	if !strings.Contains(output.String(), `protocol="ldap"`) {
		t.Fatal("hook was not connected to the report")
	}
}

type failedReportWriter struct{ err error }

func (w failedReportWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDiagnosticOutputFailureIsReturned(t *testing.T) {
	writeErr := errors.New("diagnostic output failed")
	report := newTestReport(failedReportWriter{writeErr})
	report.step("Synthetic step", nil, "completed")
	original := errors.New("authentication failed")
	err := original
	report.finish(&err)
	if !errors.Is(err, writeErr) || !errors.Is(err, original) {
		t.Fatalf("lost test or output error: %v", err)
	}
}
